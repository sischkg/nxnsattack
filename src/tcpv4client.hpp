#ifndef TCPV4CLIENT_HPP
#define TCPV4CLIENT_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>
#include "wireformat.hpp"

namespace tcpv4
{
    struct ConnectionInfo
    {
        std::string          source_address;
        std::string          destination_address;
        uint16_t             source_port;
        uint16_t             destination_port;
        std::vector<uint8_t> stream;

        /*!
         * @return TCP Stream length(bytes)
         */
        uint16_t getLength() const
        {
            return stream.size();
        }

        const uint8_t *getData() const
        {
            return stream.data();
        }

        const uint8_t *begin() const
        {
            return stream.data();
        }

        const uint8_t *end() const
        {
            return begin() + getLength();
        }
    };

    struct ClientParameters
    {
        std::string     destination_address;
        uint16_t destination_port;
    };

    class Client
    {
    private:
        ClientParameters parameters;
        int tcp_socket;
        void shutdown( int );
    public:
        Client( const ClientParameters &param )
            : parameters( param ), tcp_socket( -1 )
        {}

        ~Client();

        void openSocket();
        void closeSocket();
        void shutdown_read();
        void shutdown_write();

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
