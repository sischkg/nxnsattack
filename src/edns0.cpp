#include "udpv4client.hpp"
#include "dns.hpp"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

//const char *DNS_SERVER_ADDRESS = "192.168.33.10";
const char *DNS_SERVER_ADDRESS = "192.168.33.11";
// const char *DNS_SERVER_ADDRESS = "172.16.253.81";
//const char *DNS_SERVER_ADDRESS = "49.212.193.254";

int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.com";
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;

    std::vector<dns::OptPseudoRROptPtr> edns_options;
    std::string nsid = "test";
    nsid.push_back( 0 );
    nsid += "post";

    edns_options.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( nsid ) ) );

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = true;
    query.question.push_back( question );
    query.edns0     = true;
    query.opt_pseudo_rr = dns::RecordOpt( 1280, 0, edns_options );

    /*
    dns::PacketHeaderField header;
    header.id                   = htons( query.id );
    header.opcode               = 0;
    header.query_response       = 0;
    header.authoritative_answer = 0;
    header.truncation           = 0;
    header.recursion_desired    = query.recursion;
    header.recursion_available  = 0;
    header.zero_field           = 0;
    header.authentic_data       = 0;
    header.checking_disabled    = 0;
    header.response_code        = 0;

    header.question_count              = htons( 1 );
    header.answer_count                = htons( 0 );
    header.authority_count             = htons( 0 );
    header.additional_infomation_count = htons( 1 );

    std::vector<boost::uint8_t> packet;
    std::vector<boost::uint8_t> question_packet   = dns::generate_question_section( query.question[0] );
    std::vector<boost::uint8_t> additional_packet_1 = dns::generate_edns0_section( edns0_1 );
    std::vector<boost::uint8_t> additional_packet_2 = dns::generate_edns0_section( edns0_2 );
    
    int packet_size = sizeof(header) + question_packet.size();
    int opt_count = 1;
    for ( int i = 0 ; i < opt_count ; i++ ) {
	packet_size += additional_packet_1.size();
    }
    packet.resize( packet_size );

    uint8_t *pos = &packet[0];
    std::memcpy( pos, &header, sizeof(header) ); pos += sizeof(header);
    pos = std::copy( question_packet.begin(),   question_packet.end(),   pos );

    for ( int i = 0 ; i < opt_count ; i++ ) {
	pos = std::copy( additional_packet_1.begin(), additional_packet_1.end(), pos );
    }
    */

    std::vector<boost::uint8_t> packet = dns::generate_dns_query_packet( query );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = DNS_SERVER_ADDRESS;
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( packet.data(), packet.size() );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );

    std::cout << res;


    return 0;
}
