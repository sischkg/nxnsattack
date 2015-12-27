#ifndef IPV4_HPP
#define IPV4_HPP

#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <stdexcept>
#include <string>
#include <vector>

namespace ipv4
{

    typedef uint8_t IPROTOCOL;
    const IPROTOCOL IP_PROTOCOL_IP      = 0;  // Internet protocol
    const IPROTOCOL IP_PROTOCOL_ICMP    = 1;  // Internet control message protocol
    const IPROTOCOL IP_PROTOCOL_GGP     = 3;  // Gateway-gateway protocol
    const IPROTOCOL IP_PROTOCOL_TCP     = 6;  // Transmission control protocol
    const IPROTOCOL IP_PROTOCOL_EGP     = 8;  // Exterior gateway protocol
    const IPROTOCOL IP_PROTOCOL_PUP     = 12; // PARC universal packet protocol
    const IPROTOCOL IP_PROTOCOL_UDP     = 17; // User datagram protocol
    const IPROTOCOL IP_PROTOCOL_HMP     = 20; // Host monitoring protocol
    const IPROTOCOL IP_PROTOCOL_XNS_IDP = 22; // Xerox NS IDP
    const IPROTOCOL IP_PROTOCOL_RDP     = 27; // "reliable datagram" protocol
    const IPROTOCOL IP_PROTOCOL_RVD     = 66; // MIT remote virtual disk

    struct PacketInfo {
    public:
        uint8_t              tos;
        uint16_t             id;
        uint8_t              flag;
        uint16_t             offset;
        uint8_t              ttl;
        IPROTOCOL            protocol;
        std::string          source;
        std::string          destination;
        std::vector<uint8_t> payload;

        PacketInfo() : tos( 0 ), id( 0 ), flag( 0 ), offset( 0 ), ttl( 0 ), protocol( 0 )
        {
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

        int getPayloadLength() const
        {
            return payload.size();
        }
    };

    struct Packet {
    private:
        std::vector<uint8_t>         data;
        boost::shared_array<uint8_t> header;
        uint16_t                     header_length;
        boost::shared_array<uint8_t> payload;
        uint16_t                     payload_length;

    public:
        Packet( const uint8_t *d, uint16_t len )
            : data( d, d + len ), header( (uint8_t *)NULL ), header_length( 0 ), payload( (uint8_t *)NULL ),
              payload_length( 0 )
        {
        }

        Packet( const uint8_t *header, uint16_t header_length, const uint8_t *payload, uint16_t payload_length );
        Packet( boost::shared_array<uint8_t> header, uint16_t header_length, boost::shared_array<uint8_t> payload,
                uint16_t payload_length );

        const uint8_t *getData() const
        {
            return data.data();
        }

        uint16_t getLength() const
        {
            return data.size();
        }

        const uint8_t *getPayload() const
        {
            return payload.get();
        }
        const uint8_t *getHeader() const
        {
            return header.get();
        }
        const uint16_t getPayloadSize() const
        {
            return payload_length;
        }
        const uint16_t getHeaderSize() const
        {
            return header_length;
        }
    };

    Packet generate_ipv4_packet( const PacketInfo & );

    PacketInfo parse_ipv4_packet( const uint8_t *, uint16_t length );
}

#endif
