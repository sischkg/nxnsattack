#include "udpv4client.hpp"
#include "dns.hpp"
#include "tcpv4client.hpp"
#include <iostream>
#include <time.h>

int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "www.siskrn.co";
    question.q_type       = dns::TYPE_TKEY;
    question.q_class      = dns::CLASS_IN;
 
    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = false;
    query.question.push_back( question );
    query.tkey      = true;
    query.edns0     = false;

    query.tkey_rr.domain     = "www.siskrn.co";
    query.tkey_rr.inception  = time( NULL ) - 1000;
    query.tkey_rr.expiration = time( NULL ) + 1000;
    query.tkey_rr.mode       = 2;

    std::vector<uint8_t> dns_query_packet = dns::generate_dns_query_packet( query );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = "49.212.193.254";
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( dns_query_packet.data(), dns_query_packet.size() );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );
    std::cout << res;

    tcpv4::ClientParameters params;
    params.destination_address = "49.212.193.254";
    params.destination_port    = 53;
    tcpv4::Client tcp( params );
    uint16_t length = htons( (uint16_t)dns_query_packet.size() );
    tcp.send( reinterpret_cast<uint8_t *>( &length ), 2 );
    tcp.send( dns_query_packet );
    tcp.receive();

    return 0;
}
