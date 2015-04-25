#ifndef UDPV4SERVER_HPP
#define UDPV4SERVER_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>
#include "udpv4.hpp"
#include "udpv4client.hpp"

namespace udpv4
{

    struct ServerParameters
    {
        std::string     bind_address;
        boost::uint16_t bind_port;
    };

    class Server
    {
    private:
        ServerParameters parameters;
        int udp_socket;

        void openSocket();
        void closeSocket();
    public:
        Server( const ServerParameters &param )
            : parameters( param ), udp_socket( -1 )
        {}

        ~Server();

	boost::uint16_t sendPacket( const ClientParameters &dest, const boost::uint8_t *data, boost::uint16_t size );
	boost::uint16_t sendPacket( const ClientParameters &dest, const boost::uint8_t *begin, const boost::uint8_t *end )
        {
            return sendPacket( dest, begin, end - begin );
        }
        boost::uint16_t sendPacket( const ClientParameters &dest , const std::vector<boost::uint8_t> &packet )
        {
            return sendPacket( dest, packet.data(), packet.size() );
        }

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };
}

#endif
