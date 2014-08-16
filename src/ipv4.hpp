#ifndef IPV4_HPP
#define IPV4_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>

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


    struct PacketInfo
    {
    public:
        boost::uint8_t  tos;
        boost::uint16_t id;
        boost::uint8_t  flag;
        boost::uint16_t offset;
        boost::uint8_t  ttl;
        IPROTOCOL       protocol;
        std::string     source;
        std::string     destination;
        std::vector<boost::uint8_t> payload;

        PacketInfo()
            : tos( 0 ), id( 0 ), flag( 0 ), offset( 0 ),
              ttl( 0 ), protocol( 0 )
        {}

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

        int getPayloadLength() const
        {
            return payload.size();
        }
    };

    struct Packet
    {
    private:
        std::vector<boost::uint8_t> data;

    public:
        Packet( const boost::uint8_t *d, boost::uint16_t len )
            : data( d, d + len )
        {}

        Packet( const boost::uint8_t *header,  boost::uint16_t header_length,
                const boost::uint8_t *payload, boost::uint16_t payload_length );

        const boost::uint8_t *getData() const
        {
            return data.data();
        }

        boost::uint16_t getLength() const
        {
            return data.size();
        }
    };


    Packet generate_ipv4_packet( const PacketInfo & );

    PacketInfo parse_ipv4_packet( const boost::uint8_t *, boost::uint16_t length );

}

#endif
