#ifndef TCPV4_HPP
#define TCPV4_HPP

#include <string>
#include <vector>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>

namespace tcpv4
{

    const boost::uint16_t TCPV4_HEADER_LENGTH = ( 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2 );

    struct PacketInfo
    {
        std::string     source_address;
        std::string     destination_address;
        boost::uint16_t source_port;
        boost::uint16_t destination_port;
	boost::uint32_t sequence_number;
	boost::uint32_t acknowledgment_number;
	bool            urg;
	bool            ack;
	bool            psh;
	bool            rst;
	bool            syn;
	bool            fin;
	boost::uint16_t window;
	boost::uint16_t checksum;
	boost::uint16_t urgent_pointer;

        std::vector<boost::uint8_t> payload;

        /*!
         * @return payload length of TCP packet(bytes)
         */
        boost::uint16_t getPayloadLength() const
        {
            return payload.size();
        }

        /*!
         * @return TCP packet length(bytes)
         */
        boost::uint16_t getLength() const
        {
            // payload length + TCPv4 Header Size
            return getPayloadLength() + TCPV4_HEADER_LENGTH;
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
            return begin() + TCPV4_HEADER_LENGTH;
        }

        boost::uint16_t getPayloadLength() const
        {
            return getLength() - TCPV4_HEADER_LENGTH;
        }
    };

    Packet generate_tcpv4_packet( const PacketInfo & );

}

#endif
