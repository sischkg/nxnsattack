#include "udpv4client.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <boost/scoped_array.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace udpv4
{

    const uint16_t UDP_RECEIVE_BUFFER_SIZE = 65535;

    Client::~Client()
    {
        closeSocket();
    }

    void Client::openSocket()
    {
        if ( udp_socket > 0 ) {
            closeSocket();
        }

        udp_socket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
        if ( udp_socket < 0 ) {
            std::string msg = getErrorMessage( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( parameters.mAddress );
        socket_address.sin_port   = htons( parameters.mPort );
        if ( connect( udp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) ) <
             0 ) {
            closeSocket();
            std::string msg = getErrorMessage( "cannot connect to " + parameters.mAddress, errno );
            throw SocketError( msg );
        }
    }

    void Client::closeSocket()
    {
        if ( udp_socket > 0 ) {
            close( udp_socket );
            udp_socket = -1;
        }
    }

    uint16_t Client::sendPacket( const uint8_t *data, uint16_t size )
    {
        if ( udp_socket < 0 )
            openSocket();

        int sent_size = send( udp_socket, data, size, 0 );
        if ( sent_size < 0 ) {
            std::string msg = getErrorMessage( "cannot connect to " + parameters.mAddress, errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    uint16_t Client::sendPacket( const WireFormat &data )
    {
        if ( udp_socket < 0 )
            openSocket();

        return data.send( udp_socket, NULL, 0 );
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    PacketInfo Client::receivePacket( bool is_nonblocking )
    {
        if ( udp_socket < 0 )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        sockaddr_in          peer_address;
        socklen_t            peer_address_size = sizeof( peer_address );
        std::vector<uint8_t> receive_buffer( UDP_RECEIVE_BUFFER_SIZE );
        int                  recv_size = recvfrom( udp_socket,
						   receive_buffer.data(),
						   UDP_RECEIVE_BUFFER_SIZE,
						   flags,
						   reinterpret_cast<sockaddr *>( &peer_address ),
						   &peer_address_size );
        if ( recv_size < 0 ) {
            int error_num = errno;
            if ( error_num == EAGAIN ) {
                PacketInfo info;
                return info;
            }
            std::perror( "cannot recv" );
            throw SocketError( getErrorMessage( "cannot recv packet", error_num ) );
        }

        PacketInfo info;
        info.mSourceAddress = convertAddressBinaryToString( peer_address.sin_addr );
        info.mSourcePort    = ntohs( peer_address.sin_port );
        info.mPayload       = receive_buffer;
        return info;
    }

    bool Client::isReadable()
    {
        return true;
    }

}

