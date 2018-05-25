#ifndef TCPV4SERVER_HPP
#define TCPV4SERVER_HPP

#include "utils.hpp"
#include "wireformat.hpp"
#include <boost/noncopyable.hpp>

namespace tcpv4
{
    struct ServerParameters {
        std::string mAddress;
        uint16_t    mPort;
    };

    class Connection : boost::noncopyable
    {
    private:
        int mTCPSocket;

    public:
        Connection( int s )
	    : mTCPSocket( s )
        {
        }
        ~Connection();

        PacketData receive( int size );

        ssize_t send( const PacketData & );
        ssize_t send( const uint8_t *begin, const uint8_t *end );
        ssize_t send( const uint8_t *data, int size );
        ssize_t send( const WireFormat & );

        void shutdownSend();
        void shutdownReceive();
    };

    typedef std::shared_ptr<Connection> ConnectionPtr;

    class Server
    {
    private:
        int mTCPSocket;

    public:
        Server( const ServerParameters &p );
        ~Server();

        ConnectionPtr acceptConnection();
    };
}

#endif
