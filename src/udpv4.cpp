#include "udpv4.hpp"
#include <cstring>
#include <cstdio>
#include <algorithm>
#include "utils.hpp"

namespace udpv4
{

    struct PseudoUDPv4HeaderField
    {
        in_addr         source_address;
        in_addr         destination_address;
        boost::uint8_t  padding;
        boost::uint8_t  protocol;
        boost::uint16_t length;
    };

    struct UDPv4HeaderField {
        boost::uint16_t source_port;
        boost::uint16_t destination_port;
        boost::uint16_t length;
        boost::uint16_t checksum;
    };

    union UDPv4Header {
        UDPv4HeaderField field;
        boost::uint8_t data[sizeof(UDPv4HeaderField)];
    };

    void print_pseudo_udpv4_header( PseudoUDPv4HeaderField header )
    {
        boost::uint8_t *data = reinterpret_cast<boost::uint8_t *>( &header );
        printf( "pseudoheader:" );
        for ( int i = 0 ; i < sizeof( header ) ; i++ ) {
            printf( " %x", data[i] );
        }
        printf( "\n" );
    }

    void print_udpv4_header( UDPv4Header header )
    {
        boost::uint8_t *data = reinterpret_cast<boost::uint8_t *>( &header );
        printf( "udpv4header:" );
        for ( int i = 0 ; i < sizeof( header ) ; i++ ) {
            printf( " %x", data[i] );
        }
        printf( "\n" );
    }

    void print_payload( const boost::uint8_t *data, boost::uint16_t length )
    {
        printf( "length: %hd\n", length );
        printf( "payload:" );
        for ( int i = 0 ; i < length ; i++ ) {
            printf( " \"%c\"", data[i] );
        }
        printf( "\n" );
    }

    boost::uint16_t compute_udpv4_checksum( const PacketInfo & );

    boost::uint16_t compute_udpv4_checksum( const std::string          &source_address,
                                            const std::string          &destination_address,
                                            boost::uint16_t            source_port,
                                            boost::uint16_t            destination_port,
                                            const std::vector<uint8_t> &payload );


    Packet::Packet( const boost::uint8_t *header,  boost::uint16_t header_size,
		    const boost::uint8_t *payload, boost::uint16_t payload_size )
    {
	data.resize( header_size + payload_size );
	std::copy( header, header + header_size, data.data() );
	std::copy( payload, payload + payload_size, data.data() + header_size );
    }


    Packet generate_udpv4_packet( const PacketInfo &info )
    {
        UDPv4Header udpv4_header;
        udpv4_header.field.source_port      = htons( info.source_port );
        udpv4_header.field.destination_port = htons( info.destination_port );
        udpv4_header.field.length           = htons( info.getLength() );
        udpv4_header.field.checksum         = compute_udpv4_checksum( info );

        return Packet( reinterpret_cast<const boost::uint8_t *>( &udpv4_header ),  sizeof(udpv4_header),
		       info.getData(), info.getPayloadLength() );
    }


    boost::uint16_t compute_udpv4_checksum( const PacketInfo &info )
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
        std::vector<boost::uint8_t> checksum_buffer( checksum_buffer_length );
        std::memcpy( checksum_buffer.data(), &pseudo_header, sizeof(pseudo_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header),
                     udpv4_header.data,
                     sizeof(udpv4_header) );
        std::memcpy( checksum_buffer.data() + sizeof(pseudo_header) + sizeof(udpv4_header),
                     info.getData(),
                     info.getPayloadLength() );

        boost::uint16_t checksum = compute_checksum( checksum_buffer.data(), checksum_buffer.size() );
        return checksum;
    }
}

