#include "tcpv4client.hpp"
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <boost/scoped_array.hpp>
#include "utils.hpp"

namespace tcpv4
{
    const uint16_t TCP_RECEIVE_BUFFER_SIZE = 65535;

    Client::~Client()
    {
        closeSocket();
    }


    void Client::openSocket()
    {
        if ( tcp_socket > 0 ) {
            closeSocket();
        }

        tcp_socket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        if ( tcp_socket < 0 ) {
            std::string msg = get_error_message( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof(socket_address) );
	socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convert_address_string_to_binary( parameters.destination_address );
        socket_address.sin_port   = htons( parameters.destination_port );
        if ( connect( tcp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof(socket_address) ) < 0 ) {
            closeSocket();
            std::string msg = get_error_message( "cannot connect to " + parameters.destination_address, errno );
            throw SocketError( msg );
        }
    }

    void Client::closeSocket()
    {
        if ( tcp_socket > 0 ) {
            close( tcp_socket );
            tcp_socket = -1;
        }
    }

    void Client::shutdown( int how )
    {
        if ( tcp_socket > 0 ) {
            ::shutdown( tcp_socket, how );
        }
    }

    void Client::shutdown_read()
    {
	shutdown( SHUT_RD );
    }

    void Client::shutdown_write()
    {
	shutdown( SHUT_WR );
    }

    boost::uint16_t Client::send( const boost::uint8_t *data, boost::uint16_t size )
    {
        if ( tcp_socket < 0 )
            openSocket();
	
	int sent_size = write( tcp_socket, data, size );
	std::cerr << data[0] << "," << sent_size << std::endl;
	if ( sent_size < 0 ) {
            std::string msg = get_error_message( "cannot connect to " + parameters.destination_address, errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    PacketInfo Client::receive( bool is_nonblocking )
    {
	if ( tcp_socket < 0 )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        sockaddr_in peer_address;
        socklen_t   peer_address_size = sizeof(peer_address);
	std::vector<boost::uint8_t> receive_buffer( TCP_RECEIVE_BUFFER_SIZE );
	std::cerr << "recv" << std::endl;
	int recv_size = read( tcp_socket, receive_buffer.data(), TCP_RECEIVE_BUFFER_SIZE );
	std::cerr  << recv_size << std::endl;

        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                PacketInfo info;
                return info;
            }
            std::perror( "cannot recv" );
            throw SocketError( get_error_message( "cannot recv packet", error_num ) );
        }
	receive_buffer.resize( recv_size );

        PacketInfo info;
	//        info.source_address = convert_address_binary_to_string( peer_address.sin_addr );
        //info.source_port    = ntohs( peer_address.sin_port );
        info.payload        = receive_buffer;
        return info;
    }


    bool Client::isReadable()
    {

    }



}
