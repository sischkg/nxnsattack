#include "tcpv4client.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <boost/scoped_array.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace tcpv4
{
    const uint16_t TCP_RECEIVE_BUFFER_SIZE = 65535;

    Client::~Client()
    {
        closeSocket();
    }

    bool Client::isEnableSocket() const
    {
	return mTCPSocket > 0;
    }

    void Client::openSocket()
    {
        if ( isEnableSocket() ) {
            closeSocket();
        }

        mTCPSocket = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
        if ( mTCPSocket < 0 ) {
            std::string msg = getErrorMessage( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( mParameters.mAddress );
        socket_address.sin_port   = htons( mParameters.mPort );
        if ( connect( mTCPSocket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) ) <
             0 ) {
            closeSocket();
            std::string msg = getErrorMessage( "cannot connect to " + mParameters.mAddress, errno );
            throw SocketError( msg );
        }
    }

    void Client::closeSocket()
    {
        if ( isEnableSocket() ) {
            close( mTCPSocket );
            mTCPSocket = -1;
        }
    }

    void Client::shutdown( int how )
    {
        if ( mTCPSocket > 0 ) {
            ::shutdown( mTCPSocket, how );
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
        int sent_size = write( mTCPSocket, data, size );
        if ( sent_size < 0 ) {
            std::string msg = getErrorMessage( "cannot connect to " + mParameters.mAddress, errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    uint16_t Client::send( const WireFormat &data )
    {
        return data.send( mTCPSocket, NULL, 0, 0 );
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    ConnectionInfo Client::receive( bool is_nonblocking )
    {
        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        std::vector<uint8_t> receive_buffer( TCP_RECEIVE_BUFFER_SIZE );
        int                  recv_size = read( mTCPSocket, receive_buffer.data(), TCP_RECEIVE_BUFFER_SIZE );

        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                ConnectionInfo info;
                return info;
            }
            throw SocketError( getErrorMessage( "cannot recv packet", error_num ) );
        }
        receive_buffer.resize( recv_size );

        ConnectionInfo info;
        info.mStream = receive_buffer;
        return info;
    }

    ConnectionInfo Client::receive_data( int size )
    {
        std::vector<uint8_t> receive_buffer( size );
        int                  recv_size = read( mTCPSocket, receive_buffer.data(), size );

        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                ConnectionInfo info;
                return info;
            }
            throw SocketError( getErrorMessage( "cannot recv packet", error_num ) );
        }
        receive_buffer.resize( recv_size );

        ConnectionInfo info;
        info.mStream = receive_buffer;
        return info;
    }

    bool Client::isReadable()
    {
        return true;
    }
}
