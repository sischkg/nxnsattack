#ifndef UDPV4CLIENT_HPP
#define UDPV4CLIENT_HPP

#include "wireformat.hpp"
#include <boost/cstdint.hpp>
#include <string>
#include <vector>

namespace udpv4
{

    struct ClientParameters {
        std::string mAddress;
        uint16_t    mPort;
    };

    struct PacketInfo {
        std::string          source_address;
        std::string          destination_address;
        uint16_t             source_port;
        uint16_t             destination_port;
        std::vector<uint8_t> payload;

        /*!
         * @return payload length of UDP packet(bytes)
         */
        uint16_t getPayloadLength() const
        {
            return payload.size();
        }

        const uint8_t *getData() const
        {
            return payload.data();
        }

        const uint8_t *begin() const
        {
            return getData();
        }

        const uint8_t *end() const
        {
            return begin() + payload.size();
        }

	uint8_t operator[]( unsigned int index ) const
	{
	    return payload[index];
	}

    	uint8_t &operator[]( unsigned int index )
	{
	    return payload[index];
	}
    };

    class Client
    {
    private:
        ClientParameters parameters;
        int              udp_socket;

        void openSocket();
        void closeSocket();

    public:
        Client( const ClientParameters &param ) : parameters( param ), udp_socket( -1 )
        {
        }

        ~Client();

        uint16_t sendPacket( const uint8_t *data, uint16_t size );
        uint16_t sendPacket( const uint8_t *begin, const uint8_t *end )
        {
            return sendPacket( begin, end - begin );
        }
        uint16_t sendPacket( const std::vector<uint8_t> &packet )
        {
            return sendPacket( packet.data(), packet.size() );
        }
        uint16_t sendPacket( const WireFormat & );

        PacketInfo receivePacket( bool is_nonblocking = false );
        bool isReadable();
    };
}

#endif
