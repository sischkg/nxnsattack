#include "ipv4.hpp"
#include "udpv4.hpp"
#include "udpv4client.hpp"
#include <iostream>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>

int main()
{
    const char *src_address   = "127.0.0.1";
    const char *dst_address   = "127.0.0.1";
    const uint16_t src_port   = 10007;
    const uint16_t dst_port   = 7;
    const std::string payload = "test12\r\n";

    udpv4::ClientParameters params;
    params.destination_address = "127.0.0.1";
    params.destination_port    = 7;
    udpv4::Client udp( params );

    udp.sendPacket( reinterpret_cast<const boost::uint8_t *>( payload.c_str() ),
                    payload.size() );
    udpv4::PacketInfo recv_packet = udp.receivePacket();
    std::cout << "udp response: " << reinterpret_cast<const char *>( recv_packet.getData() ) << std::endl;

    udpv4::PacketInfo raw_udp_packet_info;
    raw_udp_packet_info.source_address      = src_address;
    raw_udp_packet_info.destination_address = dst_address;
    raw_udp_packet_info.source_port         = src_port;
    raw_udp_packet_info.destination_port    = dst_port;
    raw_udp_packet_info.payload.insert( raw_udp_packet_info.payload.end(),
                                        payload.begin(),
                                        payload.end() );

    udpv4::Sender   udp_sender;
    udpv4::Receiver udp_receiver( src_port );
    udp_sender.sendPacket( raw_udp_packet_info );
    udpv4::PacketInfo udp_packet_info = udp_receiver.receivePacket();
    std::string responsed_data( udp_packet_info.begin(), udp_packet_info.end() );

    std::cout << "raw socket response size: " << udp_packet_info.getPayloadLength() << std::endl;
    std::cout << "raw socket response: "      << responsed_data                     << std::endl;
    std::cout << "source address:"            << udp_packet_info.source_address     << std::endl;
    std::cout << "source port:"               << udp_packet_info.source_port        << std::endl;

    return 0;
}
