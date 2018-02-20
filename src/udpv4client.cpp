#include "udpv4client.hpp"
#include "ipv4.hpp"
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
            std::string msg = get_error_message( "cannot create socket", errno );
            throw SocketError( msg );
        }
        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( parameters.destination_address );
        socket_address.sin_port   = htons( parameters.destination_port );
        if ( connect( udp_socket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) ) <
             0 ) {
            closeSocket();
            std::string msg = get_error_message( "cannot connect to " + parameters.destination_address, errno );
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
            std::string msg = get_error_message( "cannot connect to " + parameters.destination_address, errno );
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
            throw SocketError( get_error_message( "cannot recv packet", error_num ) );
        }

        PacketInfo info;
        info.source_address = convertAddressBinaryToString( peer_address.sin_addr );
        info.source_port    = ntohs( peer_address.sin_port );
        info.payload        = receive_buffer;
        return info;
    }

    bool Client::isReadable()
    {
        return true;
    }

    void Sender::openSocket()
    {
        if ( raw_socket > 0 )
            closeSocket();

        raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
        if ( raw_socket < 0 ) {
            throw SocketError( get_error_message( "cannot create raw socket", errno ) );
        }
        int on  = 1;
        int res = setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof( int ) );
        if ( res < 0 ) {
            closeSocket();
            throw SocketError( get_error_message( "cannot cannot set socket option", errno ) );
        }
    }

    void Sender::closeSocket()
    {
        if ( raw_socket > 0 ) {
            close( raw_socket );
            raw_socket = -1;
        }
    }

    uint16_t Sender::sendPacket( const PacketInfo &udp_packet_info )
    {
        if ( raw_socket < 0 )
            openSocket();

        Packet udp_packet = generate_udpv4_packet( udp_packet_info, *udp_checksum );

        ipv4::PacketInfo ip_packet_info;
        ip_packet_info.tos         = 0;
        ip_packet_info.id          = 1;
        ip_packet_info.flag        = 0;
        ip_packet_info.offset      = 0;
        ip_packet_info.ttl         = 255;
        ip_packet_info.protocol    = ipv4::IP_PROTOCOL_UDP;
        ip_packet_info.source      = udp_packet_info.source_address;
        ip_packet_info.destination = udp_packet_info.destination_address;
        ip_packet_info.payload.insert( ip_packet_info.payload.end(), udp_packet.begin(), udp_packet.end() );
        ipv4::Packet ip_packet = ipv4::generate_ipv4_packet( ip_packet_info );

        sockaddr_in dst_socket_address;
        std::memset( &dst_socket_address, 0, sizeof( dst_socket_address ) );
        if ( inet_pton( AF_INET, udp_packet_info.destination_address.c_str(), &dst_socket_address.sin_addr ) < 0 ) {
            throw InvalidAddressFormatError( "invalid destination address " + udp_packet_info.destination_address );
        }
        dst_socket_address.sin_family = AF_INET;
        dst_socket_address.sin_port   = htons( udp_packet_info.destination_port );

        uint16_t sent_size;
        sent_size = sendto( raw_socket,
                            ip_packet.getData(),
                            ip_packet.getLength(),
                            0,
                            reinterpret_cast<const sockaddr *>( &dst_socket_address ),
                            sizeof( dst_socket_address ) );
        if ( sent_size < 0 )
            throw SocketError( get_error_message( "cannot send packet", errno ) );

        return sent_size;
    }

    void Receiver::openSocket()
    {
        if ( udp_socket > 0 )
            closeSocket();

        udp_socket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
        if ( udp_socket < 0 ) {
            throw SocketError( get_error_message( "cannot create udp socket", errno ) );
        }

        sockaddr_in recv_socket_address;
        recv_socket_address.sin_family = AF_INET;
        recv_socket_address.sin_addr   = convertAddressStringToBinary( bind_address );
        recv_socket_address.sin_port   = htons( bind_port );
        if ( bind( udp_socket,
                   reinterpret_cast<const sockaddr *>( &recv_socket_address ),
                   sizeof( recv_socket_address ) ) < 0 ) {
            std::perror( "cannot bind" );
            throw SocketError( get_error_message( "cannot bind receive socket", errno ) );
        }
    }

    void Receiver::closeSocket()
    {
        if ( udp_socket > 0 ) {
            close( udp_socket );
            udp_socket = -1;
        }
    }

    PacketInfo Receiver::receivePacket()
    {
        if ( udp_socket < 0 )
            openSocket();

        sockaddr_in          peer_address;
        socklen_t            peer_address_size = sizeof( peer_address );
        std::vector<uint8_t> receive_buffer( UDP_RECEIVE_BUFFER_SIZE );
        int                  recv_size = recvfrom( udp_socket,
                                  receive_buffer.data(),
                                  UDP_RECEIVE_BUFFER_SIZE,
                                  0,
                                  reinterpret_cast<sockaddr *>( &peer_address ),
                                  &peer_address_size );
        if ( recv_size < 0 ) {
            throw SocketError( get_error_message( "cannot recv packet", errno ) );
        }
        receive_buffer.resize( recv_size );

        PacketInfo info;
        info.source_address = convertAddressBinaryToString( peer_address.sin_addr );
        info.source_port    = ntohs( peer_address.sin_port );
        info.payload        = receive_buffer;
        return info;
    }
}
