#include "udpv4client.hpp"
#include "dns.hpp"
#include "tcpv4client.hpp"
#include <iostream>
#include <time.h>

int main()
{
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.com";
    question.q_type       = dns::TYPE_TKEY;
    question.q_class      = dns::CLASS_IN;
    question_section.push_back( question );

    dns::ResponseSectionEntry additonal;
    additonal.r_domainname = "www.example.com";
    additonal.r_type       = dns::TYPE_A;
    additonal.r_class      = dns::CLASS_IN;
    additonal.r_ttl        = 30;
    additonal.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
    additional_infomation_section.push_back( additonal );

    dns::PacketHeaderField header;
    header.id                   = htons( 1234 );
    header.opcode               = 0;
    header.query_response       = 0;
    header.authoritative_answer = 0;
    header.truncation           = 0;
    header.recursion_desired    = false;
    header.recursion_available  = 0;
    header.zero_field           = 0;
    header.authentic_data       = 0;
    header.checking_disabled    = 0;
    header.response_code        = 0;

    std::vector<uint8_t> packet = dns::generate_dns_packet( header,
							    question_section,
							    answer_section,
							    authority_section,
							    additional_infomation_section );

     udpv4::ClientParameters udp_param;
    udp_param.destination_address = "49.212.193.254";
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( packet.data(), packet.size() );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );
    std::cout << res;

    return 0;
}
