#ifndef TCPV4_HPP
#define TCPV4_HPP

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <string>
#include <vector>

namespace tcpv4
{

    const uint16_t TCPV4_HEADER_LENGTH = ( 2 + 2 + 4 + 4 + 2 + 2 + 2 + 2 );

    struct PacketInfo {
        std::string source_address;
        std::string destination_address;
        uint16_t    source_port;
        uint16_t    destination_port;
        uint32_t    sequence_number;
        uint32_t    acknowledgment_number;
        bool        urg;
        bool        ack;
        bool        psh;
        bool        rst;
        bool        syn;
        bool        fin;
        uint16_t    window;
        uint16_t    checksum;
        uint16_t    urgent_pointer;

        std::vector<uint8_t> payload;

        /*!
         * @return payload length of TCP packet(bytes)
         */
        uint16_t getPayloadLength() const
        {
            return payload.size();
        }

        /*!
         * @return TCP packet length(bytes)
         */
        uint16_t getLength() const
        {
            // payload length + TCPv4 Header Size
            return getPayloadLength() + TCPV4_HEADER_LENGTH;
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
    };

    class Packet
    {
    private:
        std::vector<uint8_t> data;

    public:
        Packet( const std::vector<uint8_t> &d ) : data( d )
        {
        }

        Packet( const uint8_t *header, uint16_t header_size, const uint8_t *payload, uint16_t payload_size );

        const uint8_t *getData() const
        {
            return data.data();
        }

        uint16_t getLength() const
        {
            return data.size();
        }

        const uint8_t *begin() const
        {
            return getData();
        }

        const uint8_t *end() const
        {
            return getData() + getLength();
        }

        const uint8_t *getPayload() const
        {
            return begin() + TCPV4_HEADER_LENGTH;
        }

        uint16_t getPayloadLength() const
        {
            return getLength() - TCPV4_HEADER_LENGTH;
        }
    };

    Packet generate_tcpv4_packet( const PacketInfo & );
}

#endif
