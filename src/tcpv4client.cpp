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
#include <unistd.h>
#include <fcntl.h>
#define _GNU_SOURCE
#include <poll.h>

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

        struct timeval tv;

        tv.tv_sec  = 1;
        tv.tv_usec = 0;
        setsockopt( mTCPSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv) );

        if ( ! mParameters.mBlock ) {
            fcntl( mTCPSocket, F_SETFL, O_NONBLOCK );
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
        if ( ! isEnableSocket() ) {
            throw SocketError( "not enabled socket" );
        }
        int sent_size = write( mTCPSocket, data, size );
        if ( sent_size < 0 ) {
            std::string msg = getErrorMessage( "cannot send data to " + mParameters.mAddress, errno );
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

        if ( ! isEnableSocket() ) {
            throw SocketError( "not enabled socket" );
        }

        PacketData receive_buffer( TCP_RECEIVE_BUFFER_SIZE );
        int        recv_size = read( mTCPSocket, receive_buffer.data(), TCP_RECEIVE_BUFFER_SIZE );

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
        if ( ! isEnableSocket() ) {
            throw SocketError( "not enabled socket" );
        }

        PacketData receive_buffer( size );
        int        recv_size = read( mTCPSocket, receive_buffer.data(), size );

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


    FD::Event Client::wait( unsigned int timeout_msec )
    {
        pollfd fds[1];
        std::memset( fds, 0, sizeof(fds)/sizeof(pollfd) );
        fds[0].fd = mTCPSocket;
        fds[0].events = POLLIN | POLLPRI | POLLOUT | POLLERR | POLLRDHUP | POLLNVAL;
        int fd_count = poll( fds, sizeof(fds)/sizeof(pollfd), timeout_msec );
        if ( fd_count < 0 ) {
            throw std::runtime_error( "poll error" );
        }
            
        if ( fd_count == 0 )
            return FD::NONE;

        FD::Event event_flag = FD::NONE;
        if ( fds[0].revents & POLLIN ) event_flag |= FD::READABLE;
        if ( fds[0].revents & POLLOUT ) event_flag |= FD::WRITABLE;
        if ( fds[0].revents & ( POLLERR | POLLRDHUP | POLLNVAL ) )
             event_flag |= FD::ERROR;
        return event_flag;
    }

}
