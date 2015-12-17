#include "udpv4server.hpp"
#include "tcpv4server.hpp"
#include "dns.hpp"
#include <string>
#include <stdexcept>
#include <iostream>
#include <time.h>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>
#include <boost/regex.hpp>

const char *MY_ADDRESS      = "192.168.33.1";
const char *MY_DOMAIN       = "example.com";
const char *BIND_ADDRESS    = "192.168.33.1";
const int   TTL             = 600;
const int   NS_RECORD_COUNT = 2;
const int   SUBDOMAIN_SIZE  = 30;
const int   BUF_SIZE        = 256 * 256;


std::string generate_subdomain( const std::string &qname, bool &is_update )
{
    std::ostringstream os;
    uint32_t begin_time = 0;
    uint32_t now = time( NULL );

    static boost::basic_regex<char> reg( "ns([0-9]+).([0-9]+).example.com" );
    boost::match_results<std::string::const_iterator> results;

    if ( boost::regex_match(qname.begin(), qname.end(), results, reg) ) {
    std::string str( results[2].first, results[2].second );
    begin_time = boost::lexical_cast<uint32_t>( str );

    if ( now - begin_time > 3 ) {
        begin_time = now;
        is_update  = true;
        std::cerr << "updated" << std::endl;
    }
    else {
        is_update = false;
    }
    }
    else {
    begin_time = now;
    is_update  = true;
    std::cerr << "unmatched:" << qname << std::endl;
    }

    os << begin_time;

    return os.str();
}


PacketData generate_response( uint16_t id, const dns::QuestionSectionEntry query )
{
    dns::PacketInfo packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = query.q_domainname;
    question.q_type       = query.q_type;
    question.q_class      = query.q_class;
    packet_info.question_section.push_back( question );

    dns::ResponseSectionEntry answer;
    answer.r_domainname    = query.q_domainname;
    answer.r_type          = dns::TYPE_A;
    answer.r_class         = dns::CLASS_IN;
    answer.r_ttl           = 30;
    answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
    packet_info.answer_section.push_back( answer );

    /*
    bool is_update = false;
    std::string subdomain = generate_subdomain( query.q_domainname, is_update );
    for ( int i = 0 ; i < 8 ; i++ ) {
    std::ostringstream os;
    os << "ns" << i << "." << subdomain << "." << MY_DOMAIN;
    std::string nameserver_name = os.str();

    dns::ResponseSectionEntry authority;
    authority.r_domainname = query.q_domainname;
    authority.r_type       = dns::TYPE_NS;
    authority.r_class      = dns::CLASS_IN;
    authority.r_ttl        = 6;
    authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( nameserver_name ) );
    packet_info.authority_section.push_back( authority );

    dns::ResponseSectionEntry additional;
    additional.r_domainname = "ns1.example.com";
    additional.r_type       = dns::TYPE_A;
    additional.r_class      = dns::CLASS_IN;
    additional.r_ttl        = 6;
    packet_info.additional.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "127.0.2.1" ) );
    //    packet_info.additional_infomation_section.push_back( additional );
    }
    */

    //    if ( ! is_update ) {
    std::vector<dns::OptPseudoRROptPtr> edns_options_1, edns_options_2;
    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "aaaaaaaaaaaaa" ) ) );
    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "bbbbbbbbb" ) ) );

    dns::OptPseudoRecord opt_rr_1, opt_rr_2;
    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
    opt_rr_1.payload_size = 1024;
    opt_rr_1.rcode        = 1;
    opt_rr_2.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_2 ) ); 
    opt_rr_2.payload_size = 1024;
    opt_rr_2.rcode        = 0;
    packet_info.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
    //    packet_info.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_2 ) );
    //    }

    packet_info.id                   = id;
    packet_info.opcode               = 0;
    packet_info.query_response       = 1;
    packet_info.authoritative_answer = 1;
    packet_info.truncation           = 0;
    packet_info.recursion_desired    = 0;
    packet_info.recursion_available  = 0;
    packet_info.zero_field           = 0;
    packet_info.authentic_data       = 1;
    packet_info.checking_disabled    = 1;
    packet_info.response_code        = dns::NO_ERROR;

    return dns::generate_dns_packet( packet_info );
}

void udp_server()
{
   try {
    udpv4::ServerParameters params;
    params.bind_address = BIND_ADDRESS;
    params.bind_port    = 53;
    udpv4::Server dns_receiver( params );

    while( true ) {

        try {
        udpv4::PacketInfo recv_data;
        PacketData response_packet;
        dns::QueryPacketInfo query;

        recv_data = dns_receiver.receivePacket();
        query = dns::parse_dns_query_packet( recv_data.begin(), recv_data.end() );
        response_packet = generate_response( query.id, query.question[0] );

        udpv4::ClientParameters client;
        client.destination_address = recv_data.source_address;
        client.destination_port    = recv_data.source_port;

        dns_receiver.sendPacket( client, response_packet );
        }
        catch( std::runtime_error &e ) {
        std::cerr << "send response failed," << std::endl;
        std::exit(1 );
        }
    }
    }
    catch ( std::runtime_error &e ) {
    std::cerr << "caught " << e.what() << std::endl;
    }
}


void tcp_server()
{
   try {
    tcpv4::ServerParameters params;
    params.bind_address = BIND_ADDRESS;
    params.bind_port    = 53;

    tcpv4::Server dns_receiver( params );

    while( true ) {

        try {
        tcpv4::ConnectionPtr connection = dns_receiver.acceptConnection();
        PacketData size_data = connection->receive( 2 );
        uint16_t size = ntohs( *( reinterpret_cast<const uint16_t *>( &size_data[0] ) ) );

        PacketData recv_data = connection->receive( size );
        dns::QueryPacketInfo query = dns::parse_dns_query_packet( &recv_data[0], &recv_data[0] + recv_data.size() );
        std::cerr << "tcp recv" << std::endl;

        PacketData response_packet = generate_response( query.id, query.question[0] );
        
        uint16_t send_size = htons( response_packet.size() );
        connection->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof(send_size) );
        connection->send( response_packet );
        }
        catch( std::runtime_error &e ) {
        std::cerr << "send response failed(" << e.what() << ")." << std::endl;
        std::exit(1 );
        }
    }
    }
    catch ( std::runtime_error &e ) {
    std::cerr << "caught " << e.what() << std::endl;
    }
}


int main( int arc, char **argv )
{
    boost::thread udp_server_thread( udp_server );
    boost::thread tcp_server_thread( tcp_server );

    udp_server_thread.join();
    tcp_server_thread.join();

    return 0;
}
