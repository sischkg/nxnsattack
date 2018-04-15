#include "tcpv4server.hpp"
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

namespace tcpv4
{

    Connection::~Connection()
    {
        if ( tcp_socket > 0 )
            close( tcp_socket );
    }

    void Connection::shutdownReceive()
    {
        if ( tcp_socket > 0 )
            shutdown( tcp_socket, SHUT_RD );
    }

    void Connection::shutdownSend()
    {
        if ( tcp_socket > 0 )
            shutdown( tcp_socket, SHUT_WR );
    }

    PacketData Connection::receive( int size )
    {
        PacketData recv_buffer;
        recv_buffer.resize( size );

    retry:
        int recv_size = read( tcp_socket, &recv_buffer[ 0 ], size );
        if ( recv_size < 0 ) {
            if ( errno == EINTR || errno == EAGAIN )
                goto retry;
            else {
                close( tcp_socket );
                tcp_socket = 0;
                throw SocketError( getErrorMessage( "cannot read data from peer", errno ) );
            }
        }

        recv_buffer.resize( recv_size );
        return recv_buffer;
    }

    ssize_t Connection::send( const PacketData &data )
    {
        return send( &data[ 0 ], data.size() );
    }

    ssize_t Connection::send( const uint8_t *begin, const uint8_t *end )
    {
        return send( begin, end - begin );
    }

    ssize_t Connection::send( const uint8_t *data, int size )
    {
    retry:
        int sent_size = write( tcp_socket, data, size );
        if ( sent_size < 0 ) {
            if ( errno == EINTR || errno == EAGAIN )
                goto retry;
            else {
                throw SocketError( getErrorMessage( "cannot write data to peer", errno ) );
            }
        }

        return sent_size;
    }

    ssize_t Connection::send( const WireFormat &message )
    {
        return message.send( tcp_socket, nullptr, 0 );
    }

    Server::Server( const ServerParameters &parameters )
    {
        tcp_socket = socket( AF_INET, SOCK_STREAM, 0 );
        if ( tcp_socket < 0 ) {
            SocketError( getErrorMessage( "cannot create socket", errno ) );
        }

        const int one = 1;
        setsockopt( tcp_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one) );

        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( parameters.mAddress );
        socket_address.sin_port   = htons( parameters.mPort );
        if ( bind( tcp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) ) < 0 ) {
            close( tcp_socket );
            tcp_socket = -1;
            throw SocketError( getErrorMessage( "cannot bind to " + parameters.mAddress, errno ) );
        }

        if ( listen( tcp_socket, 10 ) < 0 ) {
            close( tcp_socket );
            tcp_socket = -1;
            throw SocketError( getErrorMessage( "cannot listen", errno ) );
        }
    }

    Server::~Server()
    {
        close( tcp_socket );
    }

    ConnectionPtr Server::acceptConnection()
    {
        sockaddr_in socket_address;
        socklen_t   socket_address_size = sizeof( socket_address );

    retry:
        int new_connection =
            accept( tcp_socket, reinterpret_cast<sockaddr *>( &socket_address ), &socket_address_size );
        if ( new_connection < 0 ) {
            if ( errno == EAGAIN || errno == EINTR )
                goto retry;
            throw SocketError( getErrorMessage( "cannot accept", errno ) );
        }
        return ConnectionPtr( new Connection( new_connection ) );
    }
}
