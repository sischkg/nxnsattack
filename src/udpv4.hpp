#ifndef UDPV4_HPP
#define UDPV4_HPP

#include <string>
#include <vector>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>

namespace udpv4
{

    const boost::uint16_t UDPV4_HEADER_LENGTH = ( 2 + 2 + 2 + 2 );

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
            return getPayloadLength() + UDPV4_HEADER_LENGTH;
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
            return begin() + UDPV4_HEADER_LENGTH;
        }

        boost::uint16_t getPayloadLength() const
        {
            return getLength() - UDPV4_HEADER_LENGTH;
        }
    };

    Packet generate_udpv4_packet( const PacketInfo & );

    Packet generate_udpv4_packet( const std::string          &source_address,
                                  const std::string          &destination_address,
                                  boost::uint16_t            source_port,
                                  boost::uint16_t            destination_port,
                                  const std::vector<uint8_t> &payload );

}

#endif
