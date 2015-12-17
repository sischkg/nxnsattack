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
#include <boost/program_options.hpp>

int main( int argc, char **argv )
{
    namespace po = boost::program_options;
    std::string source_address;
    std::string destination_address;
    uint16_t    source_port;
    uint16_t    destination_port;
    std::string message;
    bool        wait_response = false;

    po::options_description desc("UDP Echo client.");
    desc.add_options()
        ("help,h",
         "print this message")

        ("source-address,s",
         po::value<std::string>(&source_address),
         "source address of echo packet")

        ("source-port,S",
         po::value<uint16_t>(&source_port)->default_value( 10007 ),
         "source port of echo packet")

        ("destination-address,d",
         po::value<std::string>(&destination_address),
         "destination address of echo packet")

        ("destination-port,D",
         po::value<uint16_t>(&destination_port)->default_value( 7 ),
         "destination port of echo packet")

        ("wait,w",
         "wait response")

        ("message,m",
         po::value<std::string>(&message)->default_value( "test" ),
         "message in echo packet")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    if ( vm.count( "source-address" )      != 1 ||
         vm.count( "source-port" )         != 1 ||
         vm.count( "destination-address" ) != 1 ||
         vm.count( "destination-port" )    != 1 ||
         vm.count( "message" )             != 1 ) {
        std::cerr << desc << "\n";
        return 1;
    }

    if ( vm.count( "wait" ) ) {
        wait_response = true;
    }

    udpv4::PacketInfo raw_udp_packet_info;
    raw_udp_packet_info.source_address      = source_address;
    raw_udp_packet_info.destination_address = destination_address;
    raw_udp_packet_info.source_port         = source_port;
    raw_udp_packet_info.destination_port    = destination_port;
    raw_udp_packet_info.payload.insert( raw_udp_packet_info.payload.end(),
                                        message.begin(),
                                        message.end() );

    udpv4::Sender   udp_sender;
    udpv4::Receiver udp_receiver( source_port );
    udp_sender.sendPacket( raw_udp_packet_info );

    if ( wait_response ) {
        udpv4::PacketInfo udp_packet_info = udp_receiver.receivePacket();
        std::string responsed_data( udp_packet_info.begin(), udp_packet_info.end() );

        std::cout << "raw socket response size: " << udp_packet_info.getPayloadLength() << std::endl;
        std::cout << "raw socket response: "      << responsed_data                     << std::endl;
        std::cout << "source address:"            << udp_packet_info.source_address     << std::endl;
        std::cout << "source port:"               << udp_packet_info.source_port        << std::endl;
    }
    return 0;
}
