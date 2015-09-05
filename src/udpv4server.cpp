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
#include <iostream>
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

	int one = 1;
	int err = setsockopt( udp_socket, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one) );
	if ( err ) {
            std::string msg = get_error_message( "cannot setsocketopt", errno );
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


    uint16_t Server::sendPacket( const ClientParameters &dest, const uint8_t *data, uint16_t size )
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
	    s << "cannot send to " << dest.destination_address << ":" << dest.destination_port << ".";
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

        std::vector<uint8_t> receive_buffer;
	receive_buffer.resize( UDP_RECEIVE_BUFFER_SIZE );
	struct msghdr      msg;
	struct iovec       iov[1];
	struct cmsghdr     *cmsg;
	uint8_t            cbuf[512];
	struct in_pktinfo  *pktinfo;
	struct sockaddr_in sin;

	iov[0].iov_base = &receive_buffer[0];
	iov[0].iov_len  = receive_buffer.size();
	
	std::memset( &msg, 0, sizeof(msg) );
	msg.msg_name       = &sin;
	msg.msg_namelen    = sizeof(sin);
	msg.msg_iov        = iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	int recv_size = recvmsg( udp_socket, &msg, 0);
	if ( recv_size < 0 ){
            std::string msg = get_error_message( "cannot recvmsg", errno );
            throw SocketError( msg );
	}

	pktinfo = NULL;
	for( cmsg = CMSG_FIRSTHDR( &msg ); cmsg != NULL ; cmsg = CMSG_NXTHDR( &msg, cmsg ) ) {
	    if( cmsg->cmsg_level == IPPROTO_IP &&
	        cmsg->cmsg_type  == IP_PKTINFO ) {
		pktinfo = (struct in_pktinfo *)CMSG_DATA( cmsg );
		break;
	    }
	}

	if ( pktinfo == NULL ) {
            throw SocketError( "cannot found pkginfo" );
	}

        PacketInfo info;
        info.source_address = convert_address_binary_to_string( sin.sin_addr );
        info.source_port    = ntohs( sin.sin_port );
	info.destination_address = convert_address_binary_to_string( pktinfo->ipi_addr );
	info.payload.insert( info.payload.end(),
			     receive_buffer.begin(),
			     receive_buffer.begin() + recv_size );

        return info;
    }


    bool Server::isReadable()
    {
	return true;
    }

}
