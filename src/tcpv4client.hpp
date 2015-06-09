#ifndef TCPV4CLIENT_HPP
#define TCPV4CLIENT_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>

namespace tcpv4
{
    struct ConnectionInfo
    {
        std::string     source_address;
        std::string     destination_address;
        boost::uint16_t source_port;
        boost::uint16_t destination_port;
        std::vector<boost::uint8_t> stream;

        /*!
         * @return TCP Stream length(bytes)
         */
        boost::uint16_t getLength() const
        {
            return stream.size();
        }

        const boost::uint8_t *getData() const
        {
            return stream.data();
        }

        const boost::uint8_t *begin() const
        {
            return stream.data();
        }

        const boost::uint8_t *end() const
        {
            return begin() + getLength();
        }
    };

    struct ClientParameters
    {
        std::string     destination_address;
        boost::uint16_t destination_port;
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

        boost::uint16_t send( const boost::uint8_t *data, boost::uint16_t size );
        boost::uint16_t send( const boost::uint8_t *begin, const boost::uint8_t *end )
        {
            send( begin, end - begin );
        }
        boost::uint16_t send( const std::vector<boost::uint8_t> &packet )
        {
            send( packet.data(), packet.size() );
        }

        ConnectionInfo receive( bool is_nonblocking = false );
        ConnectionInfo receive_data( int size );
        bool isReadable();
    };



}

#endif
