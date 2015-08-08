#include "tcpv4.hpp"
#include "ipv4.hpp"

#include <iostream>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <string>
#include <cstring>
#include <cerrno>
#include <cstdio>

int main( int argc, char **argv )
{
    namespace po = boost::program_options;
    std::string source_address;
    std::string destination_address;
    uint16_t    source_port;
    uint16_t    destination_port;

    po::options_description desc("TCP Syn packet Generator.");
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
         vm.count( "destination-port" )    != 1 ) {
        std::cerr << desc << "\n";
        return 1;
    }

    tcpv4::PacketInfo raw_tcp_packet_info;
    raw_tcp_packet_info.source_address        = source_address;
    raw_tcp_packet_info.destination_address   = destination_address;
    raw_tcp_packet_info.source_port           = source_port;
    raw_tcp_packet_info.destination_port      = destination_port;
    raw_tcp_packet_info.sequence_number       = 1;
    raw_tcp_packet_info.acknowledgment_number = 0;
    raw_tcp_packet_info.window                = 512;
    raw_tcp_packet_info.urgent_pointer        = 0;

    raw_tcp_packet_info.urg = false;
    raw_tcp_packet_info.ack = false;
    raw_tcp_packet_info.psh = false;
    raw_tcp_packet_info.rst = false;
    raw_tcp_packet_info.syn = true;
    raw_tcp_packet_info.fin = false;

    tcpv4::Packet tcp_packet = tcpv4::generate_tcpv4_packet( raw_tcp_packet_info );

    int raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
    if ( raw_socket < 0 ) {
	perror( "cannot open socket" );
	exit( 1 );
    }

    int on = 1;
    int res = setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int) );
    if( res < 0 ) {
	perror( "cannot setsockopt" );
	close( raw_socket );
	exit( 1 );
    }

    ipv4::PacketInfo ip_packet_info;
    ip_packet_info.tos         = 0;
    ip_packet_info.id          = 1;
    ip_packet_info.flag        = 0;
    ip_packet_info.offset      = 0;
    ip_packet_info.ttl         = 255;
    ip_packet_info.protocol    = ipv4::IP_PROTOCOL_TCP;
    ip_packet_info.source      = raw_tcp_packet_info.source_address;
    ip_packet_info.destination = raw_tcp_packet_info.destination_address;
    ip_packet_info.payload.insert( ip_packet_info.payload.end(),
				   tcp_packet.begin(),
				   tcp_packet.end() );
    ipv4::Packet ip_packet = ipv4::generate_ipv4_packet( ip_packet_info );

    sockaddr_in dst_socket_address;
    std::memset( &dst_socket_address, 0, sizeof(dst_socket_address) );
    if ( inet_pton( AF_INET, raw_tcp_packet_info.destination_address.c_str(), &dst_socket_address.sin_addr ) < 0 ) {
	std::cerr << "cannot convert destination address" << std::endl;
	close( raw_socket );
	exit( 1 );
    }

    dst_socket_address.sin_family = AF_INET;
    dst_socket_address.sin_port   = htons( raw_tcp_packet_info.destination_port );

    uint16_t sent_size = sendto( raw_socket, ip_packet.getData(), ip_packet.getLength(), 0,
				 reinterpret_cast<const sockaddr *>( &dst_socket_address ),
				 sizeof(dst_socket_address) );
    if ( sent_size < 0 )
	perror( "cannot send packet" );

    close( raw_socket );

    return 0;
}
