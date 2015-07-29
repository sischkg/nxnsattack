#include "udpv4client.hpp"
#include "dns.hpp"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
// const char *DNS_SERVER_ADDRESS = "192.168.33.11";
// const char *DNS_SERVER_ADDRESS = "172.16.253.81";
//const char *DNS_SERVER_ADDRESS = "49.212.193.254";

int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "mail.example.com";
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;

    std::vector<dns::OptPseudoRROptPtr> edns_options_1, edns_options_2;
    std::string nsid = "";

    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( nsid ) ) );

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = false;
    query.question.push_back( question );
    query.edns0     = true;
    query.opt_pseudo_rr = dns::RecordOpt( 1280, 0, edns_options_1 );

    dns::RecordOpt opt2( 560, 0, edns_options_2 );

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
    header.additional_infomation_count = htons( 2 );

    std::vector<uint8_t> packet;
    std::vector<uint8_t> question_packet   = dns::generate_question_section( query.question[0] );
    std::vector<uint8_t> opt_pseudo_packet_1 = query.opt_pseudo_rr.getPacket();
    std::vector<uint8_t> opt_pseudo_packet_2 = opt2.getPacket();
    
    int packet_size = sizeof(header) + question_packet.size() + opt_pseudo_packet_1.size() + opt_pseudo_packet_2.size();
    packet.resize( packet_size );

    uint8_t *pos = &packet[0];
    pos = std::copy( reinterpret_cast<uint8_t *>( &header ),
		     reinterpret_cast<uint8_t *>( &header ) + sizeof(header),
		     pos );
    pos = std::copy( question_packet.begin(),
		     question_packet.end(),
		     pos );
    pos = std::copy( opt_pseudo_packet_1.begin(),
		     opt_pseudo_packet_1.end(),
		     pos );
    pos = std::copy( opt_pseudo_packet_2.begin(),
		     opt_pseudo_packet_2.end(),
		     pos );

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
