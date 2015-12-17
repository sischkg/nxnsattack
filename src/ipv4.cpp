#include "ipv4.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <cstdio>
#include "utils.hpp"

namespace ipv4
{

    struct IPv4HeaderField
    {
        uint8_t   header_length: 4;
        uint8_t   version:       4;
        uint8_t   tos;
        uint16_t  length;
        uint16_t  id;
        uint16_t  offset:       13;
        uint8_t   flag:          3;
        uint8_t   ttl;
        IPROTOCOL protocol;
        uint16_t  checksum;
        in_addr   source;
        in_addr   destination;
    };

    union IPv4Header
    {
        struct IPv4HeaderField field;
        uint8_t data[0];
    };

    uint16_t compute_ipv4_checksum( IPv4Header header );

    void print_header( IPv4Header header )
    {
        for ( int i = 0 ; i< 20 ; i++ ) {
            std::printf( "%x ", header.data[i] );
        }
        std::printf( "\n" );
    }


    Packet::Packet( const uint8_t *header,  uint16_t header_length,
                    const uint8_t *payload, uint16_t payload_length )
    {
        data.resize( header_length + payload_length );
        std::copy( header,  header + header_length,   data.data() );
        std::copy( payload, payload + payload_length, data.data() + header_length );
    }

    Packet::Packet( boost::shared_array<uint8_t> h, uint16_t hl,
                    boost::shared_array<uint8_t> p, uint16_t pl )
        : header(h), header_length(hl), payload(p), payload_length(pl)
    {}


    Packet generate_ipv4_packet( const PacketInfo &info )
    {
        IPv4Header header;

        int header_length          = 20;
        int packet_length          = header_length + info.getPayloadLength();
        header.field.version       = 4;
        header.field.header_length = header_length / 4;
        header.field.tos           = info.tos;
        header.field.length        = htons( packet_length );
        header.field.id            = htons( info.id );
        header.field.flag          = info.flag;
        header.field.offset        = htons( info.offset );
        header.field.ttl           = info.ttl;
        header.field.protocol      = info.protocol;
        header.field.checksum      = 0;
        header.field.source        = convert_address_string_to_binary( info.source );
        header.field.destination   = convert_address_string_to_binary( info.destination );

        if ( packet_length > 0xffff ) {
            throw InvalidPayloadLengthError( "invalid playload length", info.getPayloadLength() );
        }

        header.field.checksum = compute_ipv4_checksum( header );

        return Packet( reinterpret_cast<const uint8_t *>( &header ), header_length,
                       info.getData(), info.getPayloadLength() );
    }


    uint16_t compute_ipv4_checksum( IPv4Header header )
    {
        header.field.checksum = 0;
        return compute_checksum( header.data, header.field.header_length * 4 );
    }


    PacketInfo parse_ipv4_packet( const uint8_t *data, uint16_t length )
    {
        const IPv4Header *header = reinterpret_cast<const IPv4Header *>( data );
        int header_length  = header->field.header_length * 4;
        int payload_length = ntohs( header->field.length ) - header_length;
        const uint8_t *payload = data + header_length;

        if ( payload_length < 0 || payload_length > 0xffff ) {
            throw InvalidPayloadLengthError( "received packet is invalid payload length", payload_length );
        }
        if ( length < header_length + payload_length ) {
            throw InvalidPayloadLengthError( "data < header + payload", payload_length );
        }
        if ( length > header_length + payload_length ) {
            throw InvalidPayloadLengthError( "data > header + payload", payload_length );
        }

        PacketInfo packet;
        packet.payload.insert( packet.payload.end(), payload, payload + payload_length );

        packet.tos            = header->field.tos;
        packet.id             = ntohs( header->field.id );
        packet.flag           = header->field.flag;
        packet.offset         = ntohs( header->field.offset );
        packet.ttl            = header->field.ttl;
        packet.protocol       = header->field.protocol;

        char source_addr[INET_ADDRSTRLEN];
        char destination_addr[INET_ADDRSTRLEN];

        if ( NULL == inet_ntop( AF_INET, &header->field.source, source_addr, sizeof(source_addr) ) ) {
            throw InvalidAddressFormatError( "cannot parse source address" );
        }
        if ( NULL == inet_ntop( AF_INET, &header->field.destination, destination_addr, sizeof(destination_addr) ) ) {
            throw InvalidAddressFormatError( "cannot parse destination address" );
        }

        packet.source      = source_addr;
        packet.destination = destination_addr;

        return packet;
    }

}
