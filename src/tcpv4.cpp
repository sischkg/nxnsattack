#include "tcpv4.hpp"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include "utils.hpp"

namespace tcpv4
{

    struct PseudoTCPv4HeaderField
    {
        in_addr  source_address;
        in_addr  destination_address;
        uint8_t  padding;
        uint8_t  protocol;
        uint16_t length;
    };

    struct TCPv4HeaderField {
        uint16_t source_port;
        uint16_t destination_port;
	uint32_t sequence_number;
	uint32_t acknowledgment_number;
	uint8_t  reserved_1: 4;
	uint8_t  offset:     4;
	uint8_t  fin:        1;
	uint8_t  syn:        1;
	uint8_t  rst:        1;
	uint8_t  psh:        1;
	uint8_t  ack:        1;
	uint8_t  urg:        1;
	uint8_t  reserved_2: 2;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
    };

    union TCPv4Header {
        TCPv4HeaderField field;
        uint8_t data[sizeof(TCPv4HeaderField)];
    };

    void print_pseudo_tcpv4_header( PseudoTCPv4HeaderField header )
    {
        uint8_t *data = reinterpret_cast<uint8_t *>( &header );
        printf( "pseudoheader:" );
        for ( int i = 0 ; i < sizeof( header ) ; i++ ) {
            printf( " %x", data[i] );
        }
        printf( "\n" );
    }

    void print_tcpv4_header( TCPv4Header header )
    {
        uint8_t *data = reinterpret_cast<uint8_t *>( &header );
        printf( "tcpv4header:" );
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

    uint16_t compute_tcpv4_checksum( const PacketInfo & );

    Packet::Packet( const uint8_t *header,  uint16_t header_size,
		    const uint8_t *payload, uint16_t payload_size )
    {
	data.resize( header_size + payload_size );
	std::copy( header,  header  + header_size,  data.data() );
	std::copy( payload, payload + payload_size, data.data() + header_size );
    }


    Packet generate_tcpv4_packet( const PacketInfo &info )
    {
        TCPv4Header tcpv4_header;
        tcpv4_header.field.source_port           = htons( info.source_port );
        tcpv4_header.field.destination_port      = htons( info.destination_port );
        tcpv4_header.field.sequence_number       = htonl( info.sequence_number );
        tcpv4_header.field.acknowledgment_number = htonl( info.acknowledgment_number );
        tcpv4_header.field.offset                = TCPV4_HEADER_LENGTH/4;
        tcpv4_header.field.reserved_1            = 0;
        tcpv4_header.field.reserved_2            = 0;
	tcpv4_header.field.urg                   = info.urg;
        tcpv4_header.field.ack                   = info.ack;
        tcpv4_header.field.psh                   = info.psh;
        tcpv4_header.field.rst                   = info.rst;
        tcpv4_header.field.syn                   = info.syn;
        tcpv4_header.field.fin                   = info.fin;
	tcpv4_header.field.window                = htons( info.window );
        tcpv4_header.field.checksum              = compute_tcpv4_checksum( info ); 
	tcpv4_header.field.urgent_pointer        = htons( info.urgent_pointer );

        return Packet( reinterpret_cast<const uint8_t *>( &tcpv4_header ),  sizeof(tcpv4_header),
		       info.getData(), info.getPayloadLength() );
    }


    uint16_t compute_tcpv4_checksum( const PacketInfo &info )
    {
        PseudoTCPv4HeaderField pseudo_header;
        pseudo_header.source_address      = convert_address_string_to_binary( info.source_address );
        pseudo_header.destination_address = convert_address_string_to_binary( info.destination_address );
        pseudo_header.padding             = 0;
        pseudo_header.protocol            = 6; // TCP Protocol Number
        pseudo_header.length              = htons( info.getLength() );

        TCPv4Header tcpv4_header;
        tcpv4_header.field.source_port           = htons( info.source_port );
        tcpv4_header.field.destination_port      = htons( info.destination_port );
        tcpv4_header.field.sequence_number       = htonl( info.sequence_number );
        tcpv4_header.field.acknowledgment_number = htonl( info.acknowledgment_number );
        tcpv4_header.field.offset                = TCPV4_HEADER_LENGTH/4;
        tcpv4_header.field.reserved_1            = 0;
        tcpv4_header.field.reserved_2            = 0;
	tcpv4_header.field.urg                   = info.urg;
        tcpv4_header.field.ack                   = info.ack;
        tcpv4_header.field.psh                   = info.psh;
        tcpv4_header.field.rst                   = info.rst;
        tcpv4_header.field.syn                   = info.syn;
        tcpv4_header.field.fin                   = info.fin;
	tcpv4_header.field.window                = htons( info.window );
        tcpv4_header.field.checksum              = 0;
	tcpv4_header.field.urgent_pointer        = htons( info.urgent_pointer );

        size_t checksum_buffer_length = sizeof(pseudo_header) + info.getLength();
        std::vector<uint8_t> checksum_buffer( checksum_buffer_length );
        std::memcpy( checksum_buffer.data(), &pseudo_header, sizeof(pseudo_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header),
                     tcpv4_header.data,
                     sizeof(tcpv4_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header) + sizeof(tcpv4_header),
                     info.getData(),
                     info.getPayloadLength() );

        uint16_t checksum = compute_checksum( checksum_buffer.data(), checksum_buffer.size() );
        return checksum;
    }
}

