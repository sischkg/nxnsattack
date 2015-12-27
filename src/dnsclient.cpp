#include "dns.hpp"
#include "udpv4client.hpp"
#include <iostream>

int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "www.siskrn.co";
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = false;
    query.question.push_back( question );

    WireFormat dns_query_packet;
    dns::generate_dns_query_packet( query, dns_query_packet );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = "49.212.193.254";
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( dns_query_packet );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(), received_packet.end() );
    std::cout << res;

    return 0;
}
