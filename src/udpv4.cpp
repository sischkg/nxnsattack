#include "udpv4.hpp"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include "utils.hpp"
#include <iostream>

namespace udpv4
{

    struct PseudoUDPv4HeaderField
    {
        in_addr  source_address;
        in_addr  destination_address;
        uint8_t  padding;
        uint8_t  protocol;
        uint16_t length;
    };

    struct UDPv4HeaderField {
        uint16_t source_port;
        uint16_t destination_port;
        uint16_t length;
        uint16_t checksum;
    };

    union UDPv4Header {
        UDPv4HeaderField field;
        uint8_t data[sizeof(UDPv4HeaderField)];
    };

    void print_pseudo_udpv4_header( PseudoUDPv4HeaderField header )
    {
        uint8_t *data = reinterpret_cast<uint8_t *>( &header );
        printf( "pseudoheader:" );
        for ( int i = 0 ; i < sizeof( header ) ; i++ ) {
            printf( " %x", data[i] );
        }
        printf( "\n" );
    }

    void print_udpv4_header( UDPv4Header header )
    {
        uint8_t *data = reinterpret_cast<uint8_t *>( &header );
        printf( "udpv4header:" );
        for ( int i = 0 ; i < sizeof( header ) ; i++ ) {
            printf( " %x", data[i] );
        }
        printf( "\n" );
    }

    void print_payload( const uint8_t *data, uint16_t length )
    {
        printf( "length: %hd\n", length );
        printf( "payload:" );
        for ( int i = 0 ; i < length ; i++ ) {
            printf( " \"%c\"", data[i] );
        }
        printf( "\n" );
    }

    uint16_t compute_udpv4_checksum( const PacketInfo & );

    Packet::Packet( const uint8_t *header,  uint16_t header_size,
		    const uint8_t *payload, uint16_t payload_size )
    {
	data.resize( header_size + payload_size );
	std::copy( header, header + header_size, data.data() );
	std::copy( payload, payload + payload_size, data.data() + header_size );
    }


    Packet generate_udpv4_packet( const PacketInfo &info,
				  const ChecksumCalculatable &checksum_calcurator )
    {
        UDPv4Header udpv4_header;
        udpv4_header.field.source_port      = htons( info.source_port );
        udpv4_header.field.destination_port = htons( info.destination_port );
        udpv4_header.field.length           = htons( info.getLength() );
        udpv4_header.field.checksum         = checksum_calcurator( info );

        return Packet( reinterpret_cast<const uint8_t *>( &udpv4_header ),  sizeof(udpv4_header),
		       info.getData(), info.getPayloadLength() );
    }


    uint16_t compute_udpv4_checksum( const PacketInfo &info )
    {
        PseudoUDPv4HeaderField pseudo_header;
        pseudo_header.source_address      = convert_address_string_to_binary( info.source_address );
        pseudo_header.destination_address = convert_address_string_to_binary( info.destination_address );
        pseudo_header.padding             = 0;
        pseudo_header.protocol            = 17; // UDP Protocol Number
        pseudo_header.length              = htons( info.getLength() );

        UDPv4Header udpv4_header;
        udpv4_header.field.source_port      = htons( info.source_port );
        udpv4_header.field.destination_port = htons( info.destination_port );
        udpv4_header.field.length           = htons( info.getLength() );
        udpv4_header.field.checksum         = 0;

        size_t checksum_buffer_length = sizeof(pseudo_header) + info.getLength();
        std::vector<uint8_t> checksum_buffer( checksum_buffer_length );
        std::memcpy( checksum_buffer.data(), &pseudo_header, sizeof(pseudo_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header),
                     udpv4_header.data,
                     sizeof(udpv4_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header) + sizeof(udpv4_header),
                     info.getData(),
                     info.getPayloadLength() );

        uint16_t checksum = compute_checksum( checksum_buffer.data(), checksum_buffer.size() );
        return checksum;
    }

    uint16_t StandardChecksumCalculator::operator()( const PacketInfo &info ) const
    {
	return compute_udpv4_checksum( info );
    }

}

