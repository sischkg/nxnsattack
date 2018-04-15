#ifndef TCPV4CLIENT_HPP
#define TCPV4CLIENT_HPP

#include "wireformat.hpp"
#include <boost/cstdint.hpp>
#include <string>
#include <vector>

namespace tcpv4
{
    struct ConnectionInfo {
        std::string          mSourceAddress;
        std::string          mDestinationAddress;
        uint16_t             mSourcePort;
        uint16_t             mDestinationPort;
        std::vector<uint8_t> mStream;

        /*!
         * @return TCP Stream length(bytes)
         */
        uint16_t getLength() const
        {
            return mStream.size();
        }

        const uint8_t *getData() const
        {
            return mStream.data();
        }

        const uint8_t *begin() const
        {
            return mStream.data();
        }

        const uint8_t *end() const
        {
            return begin() + getLength();
        }
    };

    struct ClientParameters {
        std::string destination_address;
        uint16_t    destination_port;
    };

    class Client
    {
    private:
        ClientParameters mParameters;
        int              mTCPSocket;
        void             shutdown( int );

    public:
        Client( const ClientParameters &param )
	    : mParameters( param ), mTCPSocket( -1 )
        {
        }

        ~Client();

        void openSocket();
        void closeSocket();
        void shutdown_read();
        void shutdown_write();
	bool isEnableSocket() const;

        uint16_t send( const uint8_t *data, uint16_t size );
        uint16_t send( const uint8_t *begin, const uint8_t *end )
        {
            return send( begin, end - begin );
        }
        uint16_t send( const std::vector<uint8_t> &packet )
        {
            return send( packet.data(), packet.size() );
        }
        uint16_t send( const WireFormat & );

        ConnectionInfo receive( bool is_nonblocking = false );
        ConnectionInfo receive_data( int size );
        bool isReadable();
    };
}

#endif
