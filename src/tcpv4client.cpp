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
#include <iostream>
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

    uint16_t Client::send( const uint8_t *data, uint16_t size )
    {
        if ( tcp_socket < 0 )
            openSocket();
	
	int sent_size = write( tcp_socket, data, size );
	if ( sent_size < 0 ) {
            std::string msg = get_error_message( "cannot connect to " + parameters.destination_address, errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    ConnectionInfo Client::receive( bool is_nonblocking )
    {
	if ( tcp_socket < 0 )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        sockaddr_in peer_address;
        socklen_t   peer_address_size = sizeof(peer_address);
	std::vector<uint8_t> receive_buffer( TCP_RECEIVE_BUFFER_SIZE );
	int recv_size = read( tcp_socket, receive_buffer.data(), TCP_RECEIVE_BUFFER_SIZE );

        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                ConnectionInfo info;
                return info;
            }
            throw SocketError( get_error_message( "cannot recv packet", error_num ) );
        }
	receive_buffer.resize( recv_size );

        ConnectionInfo info;
	info.stream = receive_buffer;
        return info;
    }

    ConnectionInfo Client::receive_data( int size )
    {
	if ( tcp_socket < 0 )
            openSocket();

        int flags = 0;

        sockaddr_in peer_address;
        socklen_t   peer_address_size = sizeof(peer_address);
	std::vector<uint8_t> receive_buffer( size );
	int recv_size = read( tcp_socket, receive_buffer.data(), size );

        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                ConnectionInfo info;
                return info;
            }
            throw SocketError( get_error_message( "cannot recv packet", error_num ) );
        }
	receive_buffer.resize( recv_size );

        ConnectionInfo info;
	info.stream = receive_buffer;
        return info;
    }


    bool Client::isReadable()
    {

    }



}
