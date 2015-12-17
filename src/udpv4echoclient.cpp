#include "udpv4server.hpp"
#include <unistd.h>

int main( int argc, char **argv )
{
    //udpv4::Sender sender( udpv4::Sender::ChecksumPtr( new udpv4::StandardChecksumCalculator ) );
    udpv4::Sender sender( udpv4::Sender::ChecksumPtr( new udpv4::BadChecksumCalculator ) );

    udpv4::PacketInfo udp_param;
    udp_param.source_address      = "10.201.8.34";
    udp_param.source_port         = 500;
    udp_param.destination_address = "10.201.8.38";
    udp_param.destination_port    = 500;

    udp_param.payload.push_back( 'a' );
    udp_param.payload.push_back( 'b' );
    udp_param.payload.push_back( 'd' );

    while (true) {
        sender.sendPacket( udp_param );
        //       udpv4::PacketInfo received_packet = receiver.receivePacket();
        usleep( 10000 );
    }

    return 0;
}
