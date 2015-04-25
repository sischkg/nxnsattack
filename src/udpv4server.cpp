#include "udpv4server.hpp"
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <boost/scoped_array.hpp>
#include "utils.hpp"


namespace udpv4
{

    const uint16_t UDP_RECEIVE_BUFFER_SIZE = 65535;

    Server::~Server()
    {
        closeSocket();
    }


    void Server::openSocket()
    {
        if ( udp_socket > 0 ) {
            closeSocket();
        }

        udp_socket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
        if ( udp_socket < 0 ) {
            std::string msg = get_error_message( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof(socket_address) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convert_address_string_to_binary( parameters.bind_address );
        socket_address.sin_port   = htons( parameters.bind_port );
        if ( bind( udp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof(socket_address) ) < 0 ) {
            closeSocket();
	    std::ostringstream str;
	    str << "cannot bind to " << parameters.bind_address << ":" << parameters.bind_port << ".";
            std::string msg = get_error_message( str.str(), errno );
            throw SocketError( msg );
        }
    }

    void Server::closeSocket()
    {
        if ( udp_socket > 0 ) {
            close( udp_socket );
            udp_socket = -1;
        }
    }


    boost::uint16_t Server::sendPacket( const ClientParameters &dest, const boost::uint8_t *data, boost::uint16_t size )
    {
        if ( udp_socket < 0 )
            openSocket();

        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof(socket_address) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convert_address_string_to_binary( dest.destination_address );
        socket_address.sin_port   = htons( dest.destination_port );
        int sent_size = sendto( udp_socket, data, size, 0,
				reinterpret_cast<const sockaddr *>( &socket_address ), sizeof(socket_address) );
        if ( sent_size < 0 ) {
	    std::ostringstream s;
	    s << "cannot to to " << dest.destination_address << ":" << dest.destination_port << ".";
            std::string msg = get_error_message( s.str(), errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    PacketInfo Server::receivePacket( bool is_nonblocking )
    {
        if ( udp_socket < 0 )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        sockaddr_in peer_address;
        socklen_t   peer_address_size = sizeof(peer_address);
        std::vector<boost::uint8_t> receive_buffer( UDP_RECEIVE_BUFFER_SIZE );
        int recv_size = recvfrom( udp_socket,
                                  receive_buffer.data(), UDP_RECEIVE_BUFFER_SIZE,
                                  flags,
                                  reinterpret_cast<sockaddr *>( &peer_address ), &peer_address_size );
        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                PacketInfo info;
                return info;
            }
            std::perror( "cannot recv" );
            throw SocketError( get_error_message( "cannot recv packet", error_num ) );
        }

        PacketInfo info;
        info.source_address = convert_address_binary_to_string( peer_address.sin_addr );
        info.source_port    = ntohs( peer_address.sin_port );
        info.payload        = receive_buffer;
        return info;
    }


    bool Server::isReadable()
    {
	return true;
    }

}
