#ifndef UDPV4SERVER_HPP
#define UDPV4SERVER_HPP

#include "udpv4client.hpp"
#include "wireformat.hpp"
#include <boost/cstdint.hpp>
#include <string>
#include <vector>

namespace udpv4
{

    struct ServerParameters {
        std::string mAddress;
        uint16_t    mPort;
	bool        mMulticast;

	ServerParameters()
	    : mPort( 0 ), mMulticast( false )
	{}
    };

    class Server
    {
    private:
        ServerParameters mParameters;
        int              mUDPSocket;

        void openSocket();
        void closeSocket();
	bool isEnableSocket() const;

    public:
        Server( const ServerParameters &param )
	    : mParameters( param ), mUDPSocket( -1 )
        {
        }

        ~Server();

        uint16_t sendPacket( const ClientParameters &dest, const uint8_t *data, uint16_t size );
        uint16_t sendPacket( const ClientParameters &dest, const uint8_t *begin, const uint8_t *end )
        {
            return sendPacket( dest, begin, end - begin );
        }
        uint16_t sendPacket( const ClientParameters &dest, const std::vector<uint8_t> &packet )
        {
            return sendPacket( dest, packet.data(), packet.size() );
        }
        uint16_t sendPacket( const ClientParameters &dest, const WireFormat & );

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };
}

#endif
