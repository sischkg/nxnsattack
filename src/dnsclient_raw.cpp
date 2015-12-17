#include "udpv4client.hpp"
#include "dns.hpp"
#include <iostream>


int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.ne.jp";
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = false;
    query.question.push_back( question );

    udpv4::Sender sender( udpv4::Sender::ChecksumPtr( new udpv4::BadChecksumCalculator ) );
    udpv4::Receiver receiver( 10000 );

    udpv4::PacketInfo udp_param;
    udp_param.source_address      = "192.168.33.1";
    udp_param.source_port         = 10000;
    udp_param.destination_address = "192.168.33.10";
    udp_param.destination_port    = 53;
    udp_param.payload             = dns::generate_dns_query_packet( query );

    while (true) {
    sender.sendPacket( udp_param );

        udpv4::PacketInfo received_packet = receiver.receivePacket();
        dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                      received_packet.end() );
        std::cout << res;

    usleep( 1000000 );
    }

    return 0;
}
