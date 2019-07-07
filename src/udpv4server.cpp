#include "udpv4server.hpp"
#include "utils.hpp"
#include <arpa/inet.h>
#include <boost/scoped_array.hpp>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>

namespace udpv4
{

    const uint16_t UDP_RECEIVE_BUFFER_SIZE = 65535;

    Server::~Server()
    {
        closeSocket();
    }

    bool Server::isEnableSocket() const
    {
	return mUDPSocket > 0;
    }
    
    void Server::openSocket()
    {
        if ( isEnableSocket() ) {
            closeSocket();
        }

        mUDPSocket = socket( AF_INET, SOCK_DGRAM, IPPROTO_UDP );
        if ( mUDPSocket < 0 ) {
            std::string msg = getErrorMessage( "cannot create socket", errno );
            throw SocketError( msg );
        }

        int one = 1;
        int err = setsockopt( mUDPSocket, IPPROTO_IP, IP_PKTINFO, &one, sizeof( one ) );
        if ( err ) {
            std::string msg = getErrorMessage( "cannot setsocketopt", errno );
            throw SocketError( msg );
        }
        setsockopt( mUDPSocket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one) );
        if ( err ) {
            std::string msg = getErrorMessage( "cannot setsocketopt SO_REUSEADDR", errno );
            throw SocketError( msg );
        }

        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        if ( mParameters.mMulticast )
            socket_address.sin_addr   = convertAddressStringToBinary( "0.0.0.0" );
        else
            socket_address.sin_addr   = convertAddressStringToBinary( mParameters.mAddress );
        socket_address.sin_port   = htons( mParameters.mPort );
        if ( bind( mUDPSocket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) ) < 0 ) {
            closeSocket();
            std::ostringstream str;
            str << "cannot bind to " << mParameters.mAddress << ":" << mParameters.mPort << ".";
            std::string msg = getErrorMessage( str.str(), errno );
            throw SocketError( msg );
        }

        if ( mParameters.mMulticast ) {
            std::cerr << "using multicast" << std::endl;
            ip_mreqn mreqn;
            mreqn.imr_multiaddr = convertAddressStringToBinary( "224.0.0.251" );
            mreqn.imr_address   = socket_address.sin_addr;
            mreqn.imr_ifindex   = 0;
            err = setsockopt( mUDPSocket, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn) );
            if ( err ) {
                std::string msg = getErrorMessage( "cannot use multicast", errno );
                throw SocketError( msg );
            }
        }
    }

    void Server::closeSocket()
    {
        if ( isEnableSocket() ) {
            close( mUDPSocket );
            mUDPSocket = -1;
        }
    }

    uint16_t Server::sendPacket( const ClientParameters &dest, const uint8_t *data, uint16_t size )
    {
        if ( ! isEnableSocket() )
            openSocket();

        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( dest.mAddress );
        socket_address.sin_port   = htons( dest.mPort );
        int sent_size             = sendto( mUDPSocket,
                                            data,
                                            size,
                                            0,
                                            reinterpret_cast<const sockaddr *>( &socket_address ),
                                            sizeof( socket_address ) );
        if ( sent_size < 0 ) {
            std::ostringstream s;
            s << "cannot send to " << dest.mAddress << ":" << dest.mPort << ".";
            std::string msg = getErrorMessage( s.str(), errno );
            throw SocketError( msg );
        }
        return sent_size;
    }

    uint16_t Server::sendPacket( const ClientParameters &dest, const WireFormat &data )
    {
        if ( ! isEnableSocket() )
            openSocket();

        sockaddr_in socket_address;
        std::memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr   = convertAddressStringToBinary( dest.mAddress );
        socket_address.sin_port   = htons( dest.mPort );
        return data.send( mUDPSocket, reinterpret_cast<const sockaddr *>( &socket_address ), sizeof( socket_address ) );
    }

    const int RECEIVE_BUFFER_SIZE = 0xffff;

    PacketInfo Server::receivePacket( bool is_nonblocking )
    {
        if ( ! isEnableSocket() )
            openSocket();

        int flags = 0;
        if ( is_nonblocking )
            flags |= MSG_DONTWAIT;

        std::vector<uint8_t> receive_buffer;
        receive_buffer.resize( UDP_RECEIVE_BUFFER_SIZE );
        struct msghdr      msg;
        struct iovec       iov[ 1 ];
        struct cmsghdr *   cmsg;
        uint8_t            cbuf[ 512 ];
        struct in_pktinfo *pktinfo;
        struct sockaddr_in sin;

        iov[ 0 ].iov_base = &receive_buffer[ 0 ];
        iov[ 0 ].iov_len  = receive_buffer.size();

        std::memset( &msg, 0, sizeof( msg ) );
        msg.msg_name       = &sin;
        msg.msg_namelen    = sizeof( sin );
        msg.msg_iov        = iov;
        msg.msg_iovlen     = 1;
        msg.msg_control    = cbuf;
        msg.msg_controllen = sizeof( cbuf );

        int recv_size = recvmsg( mUDPSocket, &msg, 0 );
        if ( recv_size < 0 ) {
            std::string msg = getErrorMessage( "cannot recvmsg", errno );
            throw SocketError( msg );
        }

        pktinfo = NULL;
        for ( cmsg = CMSG_FIRSTHDR( &msg ); cmsg != NULL; cmsg = CMSG_NXTHDR( &msg, cmsg ) ) {
            if ( cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO ) {
                pktinfo = (struct in_pktinfo *)CMSG_DATA( cmsg );
                break;
            }
        }

        if ( pktinfo == NULL ) {
            throw SocketError( "cannot found pkginfo" );
        }

        PacketInfo info;
        info.mSourceAddress      = convertAddressBinaryToString( sin.sin_addr );
        info.mSourcePort         = ntohs( sin.sin_port );
        info.mDestinationAddress = convertAddressBinaryToString( pktinfo->ipi_addr );
        info.mPayload.insert( info.mPayload.end(), receive_buffer.begin(), receive_buffer.begin() + recv_size );

        return info;
    }

    bool Server::isReadable()
    {
        return true;
    }
}
