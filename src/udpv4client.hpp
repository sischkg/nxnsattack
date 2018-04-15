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
        std::string          mSourceAddress;
        std::string          mDestinationAddress;
        uint16_t             mSourcePort;
        uint16_t             mDestinationPort;
        std::vector<uint8_t> mPayload;

        /*!
         * @return payload length of UDP packet(bytes)
         */
        uint16_t getPayloadLength() const
        {
            return mPayload.size();
        }

        const uint8_t *getData() const
        {
            return mPayload.data();
        }

        const uint8_t *begin() const
        {
            return getData();
        }

        const uint8_t *end() const
        {
            return begin() + mPayload.size();
        }

	uint8_t operator[]( unsigned int index ) const
	{
	    return mPayload[index];
	}

    	uint8_t &operator[]( unsigned int index )
	{
	    return mPayload[index];
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
