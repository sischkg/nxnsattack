#ifndef TCPV4CLIENT_HPP
#define TCPV4CLIENT_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <vector>

namespace tcpv4
{
    struct PacketInfo
    {
        std::string     source_address;
        std::string     destination_address;
        boost::uint16_t source_port;
        boost::uint16_t destination_port;
        std::vector<boost::uint8_t> payload;

        /*!
         * @return payload length of UDP packet(bytes)
         */
        boost::uint16_t getPayloadLength() const
        {
            return payload.size();
        }

        /*!
         * @return UDP packet length(bytes)
         */
        boost::uint16_t getLength() const
        {
            // payload length + UDPv4 Header Size
            return getPayloadLength();
        }

        const boost::uint8_t *getData() const
        {
            return payload.data();
        }

        const boost::uint8_t *begin() const
        {
            return getData();
        }

        const boost::uint8_t *end() const
        {
            return begin() + payload.size();
        }
    };

    class Packet
    {
    private:
        std::vector<boost::uint8_t> data;

    public:
        Packet( const std::vector<boost::uint8_t> &d )
            : data( d )
        {}

        Packet( const boost::uint8_t *header,  boost::uint16_t header_size,
		const boost::uint8_t *payload, boost::uint16_t payload_size );

        const boost::uint8_t *getData() const
        {
            return data.data();
        }

        boost::uint16_t getLength() const
        {
            return data.size();
        }

        const boost::uint8_t *begin() const
        {
            return getData();
        }

        const boost::uint8_t *end() const
        {
            return getData() + getLength();
        }

        const boost::uint8_t *getPayload() const
        {
            return begin();
        }

        boost::uint16_t getPayloadLength() const
        {
            return getLength();
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

        PacketInfo receive( bool is_nonblocking = false );
        bool isReadable();
    };



}

#endif
