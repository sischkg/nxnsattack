#ifndef UDPV4SERVER_HPP
#define UDPV4SERVER_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>
#include "udpv4.hpp"
#include "udpv4client.hpp"
#include "wireformat.hpp"

namespace udpv4
{

    struct ServerParameters
    {
        std::string bind_address;
        uint16_t    bind_port;
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

        uint16_t sendPacket( const ClientParameters &dest, const uint8_t *data, uint16_t size );
        uint16_t sendPacket( const ClientParameters &dest, const uint8_t *begin, const uint8_t *end )
        {
            return sendPacket( dest, begin, end - begin );
        }
        uint16_t sendPacket( const ClientParameters &dest , const std::vector<uint8_t> &packet )
        {
            return sendPacket( dest, packet.data(), packet.size() );
        }
        uint16_t sendPacket( const ClientParameters &dest , const WireFormat & );

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };
}

#endif
