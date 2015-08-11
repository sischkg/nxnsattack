#ifndef TCPV4SERVER_HPP
#define TCPV4SERVER_HPP

#include <boost/noncopyable.hpp>
#include "utils.hpp"

namespace tcpv4
{
    struct ServerParameters
    {
	std::string bind_address;
	uint16_t    bind_port;
    };

    class Connection : boost::noncopyable
    {
    private:
	int tcp_socket;

    public:
	Connection( int s )
	    : tcp_socket( s )
	{}
	~Connection();

	PacketData receive( int size );

	ssize_t send( const PacketData & );	
	ssize_t send( const uint8_t *begin, const uint8_t *end );
	ssize_t send( const uint8_t *data, int size );

	void shutdownSend();
	void shutdownReceive();
    };

    typedef boost::shared_ptr<Connection> ConnectionPtr;

    class Server
    {
    private:
	int tcp_socket;

    public:
	Server( const ServerParameters &p );
	~Server();

	ConnectionPtr acceptConnection();

    };
}

#endif
