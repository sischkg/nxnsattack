#include "udpv4client.hpp"
#include "dns.hpp"
#include "tcpv4client.hpp"
#include <iostream>
#include <time.h>

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

    dns::ResponseSectionEntry additonal;
    additonal.r_domainname = "www.example.com";
    additonal.r_type       = dns::TYPE_A;
    additonal.r_class      = dns::CLASS_IN;
    additonal.r_ttl        = 30;
    additonal.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
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

    WireFormat message;
    dns::generate_dns_packet( packet_info, message );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = "49.212.193.254";
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( message );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );
    std::cout << res;

    return 0;
}
