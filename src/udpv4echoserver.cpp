#include "udpv4server.hpp"
#include <iostream>

int main( int argc, char **argv )
{
    udpv4::ServerParameters echo_params;
    echo_params.bind_address = "0.0.0.0";
    echo_params.bind_port    = 10050;

    udpv4::Server echo( echo_params );
    while ( true ) {
        udpv4::PacketInfo received_packet = echo.receivePacket();
        std::cerr << "received " << received_packet.getLength() << " bytes "
                  << " from " << received_packet.source_address << ":" << received_packet.source_port << std::endl;
        udpv4::ClientParameters peer;
        peer.destination_address = received_packet.source_address;
        peer.destination_port    = received_packet.source_port;

        std::cerr << "send data size: " << received_packet.getPayloadLength() << std::endl;
        echo.sendPacket( peer, received_packet.getData(), received_packet.getPayloadLength() );
    }

    return 0;
}
