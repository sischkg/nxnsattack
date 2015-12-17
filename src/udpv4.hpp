#ifndef UDPV4_HPP
#define UDPV4_HPP

#include <string>
#include <vector>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>

namespace udpv4
{

    const uint16_t UDPV4_HEADER_LENGTH = ( 2 + 2 + 2 + 2 );

    struct PacketInfo
    {
        std::string          source_address;
        std::string          destination_address;
        uint16_t             source_port;
        uint16_t             destination_port;
        std::vector<uint8_t> payload;

        /*!
         * @return payload length of UDP packet(bytes)
         */
        uint16_t getPayloadLength() const
        {
            return payload.size();
        }

        /*!
         * @return UDP packet length(bytes)
         */
        uint16_t getLength() const
        {
            // payload length + UDPv4 Header Size
            return getPayloadLength() + UDPV4_HEADER_LENGTH;
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
        Packet( const std::vector<uint8_t> &d )
            : data( d )
        {}

        Packet( const uint8_t *header,  uint16_t header_size,
                const uint8_t *payload, uint16_t payload_size );

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
            return begin() + UDPV4_HEADER_LENGTH;
        }

        uint16_t getPayloadLength() const
        {
            return getLength() - UDPV4_HEADER_LENGTH;
        }
    };

    struct ChecksumCalculatable
    {
        virtual ~ChecksumCalculatable() {}
        virtual uint16_t operator()( const PacketInfo & ) const = 0;
    };

    struct StandardChecksumCalculator : public ChecksumCalculatable
    {
        virtual uint16_t operator()( const PacketInfo & ) const;
    };

    struct BadChecksumCalculator : public ChecksumCalculatable
    {
        virtual uint16_t operator()( const PacketInfo & ) const;
    };

    Packet generate_udpv4_packet( const PacketInfo &,
                                  const ChecksumCalculatable &checksum = StandardChecksumCalculator() );
}

#endif
