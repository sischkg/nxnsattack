#include "dns.hpp"
#include "utils.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <endian.h>

namespace dns
{
    static const uint8_t *
    parseCharacterString( const uint8_t *begin, const uint8_t *packet_end, std::string &ref_output )
    {
        if ( begin == NULL || packet_end == NULL )
            throw std::logic_error( "begin, packet end must not be NULL" );
        if ( begin == packet_end )
            throw FormatError( "character-string length >= 1" );

        const uint8_t *pos  = begin;
        uint8_t        size = get_bytes<uint8_t>( &pos );

        if ( pos + size > packet_end )
            throw FormatError( "character-string size is too long than end of packet" );

        ref_output.assign( reinterpret_cast<const char *>( pos ), size );
        pos += size;
        return pos;
    }

    uint16_t QuestionSectionEntry::size() const
    {
        return q_domainname.size() + sizeof(q_type) + sizeof(q_class);
    }

    uint16_t ResponseSectionEntry::size() const
    {
        return r_domainname.size() + sizeof(r_type) + sizeof(r_class) + sizeof(r_ttl) +
	    sizeof(uint16_t) +       // size of resource data size
	    r_resource_data->size();
    }


    PacketData generate_dns_packet( const PacketInfo &info )
    {
        WireFormat message;
        generate_dns_packet( info, message );
        return message.get();
    }

    void generate_dns_packet( const PacketInfo &info, WireFormat &message )
    {
        PacketHeaderField header;
        header.id                   = htons( info.id );
        header.opcode               = info.opcode;
        header.query_response       = info.query_response;
        header.authoritative_answer = info.authoritative_answer;
        header.truncation           = info.truncation;
        header.recursion_desired    = info.recursion_desired;
        header.recursion_available  = info.recursion_available;
        header.zero_field           = 0;
        header.authentic_data       = info.authentic_data;
        header.checking_disabled    = info.checking_disabled;
        header.response_code        = info.response_code;

        std::vector<ResponseSectionEntry> additional = info.additional_infomation_section;

        if ( info.edns0 ) {
            additional.push_back( generate_opt_pseudo_record( info.opt_pseudo_rr ) );
        }

        header.question_count              = htons( info.question_section.size() );
        header.answer_count                = htons( info.answer_section.size() );
        header.authority_count             = htons( info.authority_section.size() );
        header.additional_infomation_count = htons( additional.size() );

        message.pushBuffer( reinterpret_cast<const uint8_t *>( &header ),
                            reinterpret_cast<const uint8_t *>( &header ) + sizeof( header ) );

        for ( auto q = info.question_section.begin(); q != info.question_section.end(); ++q ) {
            generate_question_section( *q, message );
        }
        for ( auto q = info.answer_section.begin(); q != info.answer_section.end(); ++q ) {
            generate_response_section( *q, message );
        }
        for ( auto q = info.authority_section.begin(); q != info.authority_section.end(); ++q ) {
            generate_response_section( *q, message );
        }
        for ( auto q = additional.begin(); q != additional.end(); ++q ) {
            generate_response_section( *q, message );
        }
    }

    PacketInfo parse_dns_packet( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *packet = begin;

        PacketInfo               packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( begin );

        packet_info.id                   = ntohs( header->id );
        packet_info.query_response       = header->query_response;
        packet_info.opcode               = header->opcode;
        packet_info.authoritative_answer = header->authoritative_answer;
        packet_info.truncation           = header->truncation;
        packet_info.recursion_available  = header->recursion_available;
        packet_info.recursion_desired    = header->recursion_desired;
        packet_info.checking_disabled    = header->checking_disabled;
        packet_info.authentic_data       = header->authentic_data;
        packet_info.response_code        = header->response_code;

        int question_count              = ntohs( header->question_count );
        int answer_count                = ntohs( header->answer_count );
        int authority_count             = ntohs( header->authority_count );
        int additional_infomation_count = ntohs( header->additional_infomation_count );

        packet += sizeof( PacketHeaderField );
        for ( int i = 0; i < question_count; i++ ) {
            QuestionSectionEntryPair pair = parse_question_section( begin, packet );
            packet_info.question_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < answer_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.answer_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < authority_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.authority_section.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0; i < additional_infomation_count; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            if ( pair.first.r_type == TYPE_OPT ) {
                packet_info.edns0 = true;
		packet_info.opt_pseudo_rr.domainname   = pair.first.r_domainname;
		packet_info.opt_pseudo_rr.payload_size = pair.first.r_class;
		packet_info.opt_pseudo_rr.rcode        = ( 0xff000000 & pair.first.r_ttl ) >> 24;
		packet_info.opt_pseudo_rr.version      = ( 0x00ff0000 & pair.first.r_ttl ) >> 16;
		packet_info.opt_pseudo_rr.dobit        = ( 0x00008000 & pair.first.r_ttl ) ? true : false;
		packet_info.opt_pseudo_rr.record_options_data = pair.first.r_resource_data;
		
            }
            if ( pair.first.r_type == TYPE_TSIG && pair.first.r_class == CLASS_IN ) {
                packet_info.tsig    = true;
                packet_info.tsig_rr = dynamic_cast<const RecordTSIGData &>( *( pair.first.r_resource_data ) );
            }
            packet_info.additional_infomation_section.push_back( pair.first );
            packet = pair.second;
        }

        return packet_info;
    }

    PacketData convert_domainname_string_to_binary( const std::string &domainname, uint32_t compress_offset )
    {
        PacketData bin;
        PacketData label;

        if ( domainname == "." || domainname == "" ) {
            if ( compress_offset == NO_COMPRESSION ) {
                bin.push_back( 0 );
                return bin;
            } else {
                bin.push_back( 0xC0 | ( uint8_t )( compress_offset >> 8 ) );
                bin.push_back( 0xff & (uint8_t)compress_offset );
            }
        }

        for ( auto i = domainname.begin(); i != domainname.end(); ++i ) {
            if ( *i == '.' ) {
                if ( label.size() != 0 ) {
                    bin.push_back( boost::numeric_cast<uint8_t>( label.size() ) );
                    bin.insert( bin.end(), label.begin(), label.end() );
                    label.clear();
                }
            } else {
                label.push_back( boost::numeric_cast<uint8_t>( *i ) );
            }
        }
        if ( !label.empty() ) {
            bin.push_back( boost::numeric_cast<uint8_t>( label.size() ) );
            bin.insert( bin.end(), label.begin(), label.end() );
            if ( compress_offset != NO_COMPRESSION ) {
                bin.push_back( 0xC0 | ( compress_offset >> 8 ) );
                bin.push_back( 0xff & compress_offset );
            } else {
                bin.push_back( 0 );
            }
        }

        return bin;
    }

    std::pair<std::string, const uint8_t *>
    convert_domainname_binary_to_string( const uint8_t *packet, const uint8_t *begin, int recur ) throw( FormatError )
    {
        if ( recur > 100 ) {
            throw FormatError( "detected domainname decompress loop" );
        }
        std::string    domainname;
        const uint8_t *p = begin;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                int offset = ntohs( *( reinterpret_cast<const uint16_t *>( p ) ) ) & 0x0bff;
                if ( packet + offset > begin - 2 ) {
                    throw FormatError( "detected forword reference of domainname decompress" );
                }

                std::pair<std::string, const uint8_t *> pair =
                    convert_domainname_binary_to_string( packet, packet + offset, recur + 1 );
                return std::pair<std::string, const uint8_t *>( domainname + pair.first, p + 2 );
            }

            uint8_t label_length = *p;
            p++;
            for ( uint8_t i = 0; i < label_length; i++, p++ ) {
                domainname.push_back( *p );
            }
            domainname.push_back( '.' );
        }
        if ( domainname != "" )
            domainname.resize( domainname.size() - 1 );

        p++;
        return std::pair<std::string, const uint8_t *>( domainname, p );
    }

    PacketData generate_question_section( const QuestionSectionEntry &question )
    {
        PacketData message;
        question.q_domainname.outputWireFormat( message, question.q_offset );
        message.resize( message.size() + sizeof( uint16_t ) + sizeof( uint16_t ) );
        uint8_t *p = message.data() + message.size() - sizeof( uint16_t ) - sizeof( uint16_t );
        p          = dns::set_bytes<uint16_t>( htons( question.q_type ), p );
        p          = dns::set_bytes<uint16_t>( htons( question.q_class ), p );

        return message;
    }

    void generate_question_section( const QuestionSectionEntry &question, WireFormat &message )
    {
        question.q_domainname.outputWireFormat( message, question.q_offset );
        message.pushUInt16HtoN( question.q_type );
        message.pushUInt16HtoN( question.q_class );
    }

    QuestionSectionEntryPair parse_question_section( const uint8_t *packet, const uint8_t *p )
    {
        QuestionSectionEntry question;
        const uint8_t *      pos = Domainname::parsePacket( question.q_domainname, packet, p );

        question.q_type  = ntohs( get_bytes<uint16_t>( &pos ) );
        question.q_class = ntohs( get_bytes<uint16_t>( &pos ) );

        return QuestionSectionEntryPair( question, pos );
    }

    PacketData generate_response_section( const ResponseSectionEntry &response )
    {
        if ( response.r_resource_data ) {
            WireFormat w;
            response.r_resource_data->outputWireFormat( w );

            PacketData packet_name = response.r_domainname.getPacket( response.r_offset );
            PacketData packet_rd   = w.get();
            PacketData packet( packet_name.size() + 2 + 2 + 4 + 2 + packet_rd.size() );
            uint8_t *  p = packet.data();

            std::memcpy( p, packet_name.data(), packet_name.size() );
            p += packet_name.size();

            p = dns::set_bytes<uint16_t>( htons( response.r_type ), p );
            p = dns::set_bytes<uint16_t>( htons( response.r_class ), p );
            p = dns::set_bytes<uint32_t>( htonl( response.r_ttl ), p );
            p = dns::set_bytes<uint16_t>( htons( packet_rd.size() ), p );

            std::memcpy( p, packet_rd.data(), packet_rd.size() );

            return packet;
        } else {
            PacketData packet_name = response.r_domainname.getPacket( response.r_offset );
            PacketData packet( packet_name.size() + 2 + 2 + 4 + 2 );
            uint8_t *  p = packet.data();

            std::memcpy( p, packet_name.data(), packet_name.size() );
            p += packet_name.size();

            p = dns::set_bytes<uint16_t>( htons( response.r_type ), p );
            p = dns::set_bytes<uint16_t>( htons( response.r_class ), p );
            p = dns::set_bytes<uint32_t>( htonl( response.r_ttl ), p );
            p = dns::set_bytes<uint16_t>( htons( 0 ), p );

            return packet;
        }
    }

    void generate_response_section( const ResponseSectionEntry &response, WireFormat &message )
    {
        response.r_domainname.outputWireFormat( message, response.r_offset );
        message.pushUInt16HtoN( response.r_type );
        message.pushUInt16HtoN( response.r_class );
        message.pushUInt32HtoN( response.r_ttl );
        if ( response.r_resource_data ) {
            message.pushUInt16HtoN( response.r_resource_data->size() );
            response.r_resource_data->outputWireFormat( message );
        } else {
            message.pushUInt16HtoN( 0 );
        }
    }

    ResponseSectionEntryPair parse_response_section( const uint8_t *packet, const uint8_t *begin )
    {
        ResponseSectionEntry sec;

        const uint8_t *pos   = Domainname::parsePacket( sec.r_domainname, packet, begin );
        sec.r_type           = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.r_class          = ntohs( get_bytes<uint16_t>( &pos ) );
        sec.r_ttl            = ntohl( get_bytes<uint32_t>( &pos ) );
        uint16_t data_length = ntohs( get_bytes<uint16_t>( &pos ) );

        ResourceDataPtr parsed_data;
        switch ( sec.r_type ) {
        case TYPE_A:
            parsed_data = RecordA::parse( pos, pos + data_length );
            break;
        case TYPE_AAAA:
            parsed_data = RecordAAAA::parse( pos, pos + data_length );
            break;
        case TYPE_NS:
            parsed_data = RecordNS::parse( packet, pos, pos + data_length );
            break;
        case TYPE_CNAME:
            parsed_data = RecordCNAME::parse( packet, pos, pos + data_length );
            break;
        case TYPE_NAPTR:
            parsed_data = RecordNAPTR::parse( packet, pos, pos + data_length );
            break;
        case TYPE_DNAME:
            parsed_data = RecordDNAME::parse( packet, pos, pos + data_length );
            break;
        case TYPE_MX:
            parsed_data = RecordMX::parse( packet, pos, pos + data_length );
            break;
        case TYPE_TXT:
            parsed_data = RecordTXT::parse( packet, pos, pos + data_length );
            break;
        case TYPE_SOA:
            parsed_data = RecordSOA::parse( packet, pos, pos + data_length );
            break;
        case TYPE_DNSKEY:
            parsed_data = RecordDNSKey::parse( packet, pos, pos + data_length );
            break;
        case TYPE_TSIG:
            parsed_data = RecordTSIGData::parse( packet, pos, pos + data_length, sec.r_domainname );
            break;
        case TYPE_OPT:
            parsed_data = RecordOptionsData::parse( packet, pos, pos + data_length );
            break;
        default:
            std::ostringstream msg;
            msg << "not support type \"" << sec.r_type << "\".";
            throw std::runtime_error( msg.str() );
        }
        pos += data_length;

        sec.r_resource_data = parsed_data;
        return ResponseSectionEntryPair( sec, pos );
    }

    std::ostream &print_header( std::ostream &os, const PacketInfo &packet )
    {
        os << "ID: " << packet.id << std::endl
           << "Query/Response: " << ( packet.query_response == 0 ? "Query" : "Response" ) << std::endl
           << "OpCode:" << packet.opcode << std::endl
           << "Authoritative Answer:" << packet.authoritative_answer << std::endl
           << "Truncation: " << packet.truncation << std::endl
           << "Recursion Desired: " << packet.recursion_desired << std::endl
           << "Recursion Available: " << packet.recursion_available << std::endl
           << "Checking Disabled: " << packet.checking_disabled << std::endl
           << "Response Code: " << response_code_to_string( packet.response_code ) << std::endl;

        return os;
    }

    std::string type_code_to_string( Type t )
    {
        std::string res;

        switch ( t ) {
        case TYPE_A:
            res = "A";
            break;
        case TYPE_NS:
            res = "NS";
            break;
        case TYPE_CNAME:
            res = "CNAME";
            break;
        case TYPE_NAPTR:
            res = "NAPTR";
            break;
        case TYPE_DNAME:
            res = "DNAME";
            break;
        case TYPE_MX:
            res = "MX";
            break;
        case TYPE_TXT:
            res = "TXT";
            break;
        case TYPE_SOA:
            res = "SOA";
            break;
        case TYPE_KEY:
            res = "KEY";
            break;
        case TYPE_AAAA:
            res = "AAAA";
            break;
        case TYPE_OPT:
            res = "OPT";
            break;
        case TYPE_RRSIG:
            res = "RRSIG";
            break;
        case TYPE_DNSKEY:
            res = "DNSKEY";
            break;
        case TYPE_TSIG:
            res = "TSIG";
            break;
        case TYPE_TKEY:
            res = "TKEY";
            break;
        case TYPE_IXFR:
            res = "IXFR";
            break;
        case TYPE_AXFR:
            res = "AXFR";
            break;
        case TYPE_ANY:
            res = "ANY";
            break;
        default:
            res = boost::lexical_cast<std::string>( t );
        }
        return res;
    }

    std::string response_code_to_string( uint8_t rcode )
    {
        std::string res;

        const char *rcode2str[] = {
            "NoError   No Error",
            "FormErr   Format Error",
            "ServFail  Server Failure",
            "NXDomain  Non-Existent Domain",
            "NotImp    Not Implemented",
            "Refused   Query Refused",
            "YXDomain  Name Exists when it should not",
            "YXRRSet   RR Set Exists when it should not",
            "NXRRSet   RR Set that should exist does not",
            "NotAuth   Server Not Authoritative for zone",
            "NotZone   Name not contained in zone",
            "11        available for assignment",
            "12        available for assignment",
            "13        available for assignment",
            "14        available for assignment",
            "15        available for assignment",
            "BADVERS   Bad OPT Version",
            "BADSIG    TSIG Signature Failure",
            "BADKEY    Key not recognized",
            "BADTIME   Signature out of time window",
            "BADMODE   Bad TKEY Mode",
            "BADNAME   Duplicate key name",
            "BADALG    Algorithm not supported",
        };

        if ( rcode < sizeof( rcode2str ) / sizeof( char * ) )
            res = rcode2str[ rcode ];
        else
            res = "n         available for assignment";

        return res;
    }

    Type string_to_type_code( const std::string &t )
    {
        if ( t == "A" )      return TYPE_A;
        if ( t == "AAAA" )   return TYPE_AAAA;
        if ( t == "NS" )     return TYPE_NS;
        if ( t == "CNAME" )  return TYPE_CNAME;
        if ( t == "NAPTR" )  return TYPE_NAPTR;
        if ( t == "DNAME" )  return TYPE_DNAME;
        if ( t == "MX" )     return TYPE_MX;
        if ( t == "TXT" )    return TYPE_TXT;
        if ( t == "SOA" )    return TYPE_SOA;
        if ( t == "KEY" )    return TYPE_KEY;
        if ( t == "OPT" )    return TYPE_OPT;
        if ( t == "DS" )     return TYPE_DS;
        if ( t == "RRSIG" )  return TYPE_RRSIG;
        if ( t == "DNSKEY" ) return TYPE_DNSKEY;
        if ( t == "NSEC" )   return TYPE_NSEC;
        if ( t == "TSIG" )   return TYPE_TSIG;
        if ( t == "TKEY" )   return TYPE_TKEY;
        if ( t == "IXFR" )   return TYPE_IXFR;
        if ( t == "AXFR" )   return TYPE_AXFR;
        if ( t == "ANY" )    return TYPE_ANY;

        throw std::runtime_error( "unknown type \"" + t + "\"" );
    }


    std::ostream &operator<<( std::ostream &os, const PacketInfo &res )
    {
        os << "ID: " << res.id << std::endl
           << "Query/Response: " << ( res.query_response ? "Response" : "Query" ) << std::endl
           << "OpCode:" << res.opcode << std::endl
           << "Authoritative Answer: " << res.authoritative_answer << std::endl
           << "Truncation: " << res.truncation << std::endl
           << "Recursion Desired: " << res.recursion_desired << std::endl
           << "Recursion Available: " << res.recursion_available << std::endl
           << "Checking Disabled: " << res.checking_disabled << std::endl
           << "Response Code: " << response_code_to_string( res.response_code ) << std::endl;

        for ( auto q : res.question_section )
            os << "Query: " << q.q_domainname << " " << type_code_to_string( q.q_type ) << "  ?" << std::endl;
        for ( auto a : res.answer_section )
            std::cout << "Answer: " << a.r_domainname << " " << a.r_ttl << " " << type_code_to_string( a.r_type )
                      << " " << a.r_resource_data->toString() << std::endl;
        for ( auto a : res.authority_section )
            std::cout << "Authority: " << a.r_ttl << " " << type_code_to_string( a.r_type ) << " "
                      << a.r_resource_data->toString() << std::endl;
        for ( auto a : res.additional_infomation_section )
            std::cout << "Additional: " << a.r_domainname << " " << a.r_ttl << " " << type_code_to_string( a.r_type )
                      << " " << a.r_resource_data->toString() << std::endl;

        return os;
    }

    std::string RecordRaw::toString() const
    {
        std::ostringstream os;
        os << "type: " << rrtype << ", data: ";
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            os << std::hex << (unsigned int)data[ i ] << " ";
        }
        return os.str();
    }

    void RecordRaw::outputWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( data );
    }

    RecordA::RecordA( uint32_t addr ) : sin_addr( addr )
    {
    }

    RecordA::RecordA( const std::string &addr )
    {
        in_addr a = convert_address_string_to_binary( addr );
        std::memcpy( &sin_addr, &a, sizeof( sin_addr ) );
    }

    std::string RecordA::toString() const
    {
        char buf[ 256 ];
        std::snprintf( buf,
                       sizeof( buf ),
                       "%d.%d.%d.%d",
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 1 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 2 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 3 ) );
        return std::string( buf );
    }

    void RecordA::outputWireFormat( WireFormat &message ) const
    {
        message.push_back( ( sin_addr >> 0 ) & 0xff );
        message.push_back( ( sin_addr >> 8 ) & 0xff );
        message.push_back( ( sin_addr >> 16 ) & 0xff );
        message.push_back( ( sin_addr >> 24 ) & 0xff );
    }

    std::string RecordA::getAddress() const
    {
	return toString();
    }

    ResourceDataPtr RecordA::parse( const uint8_t *begin, const uint8_t *end )
    {
        return ResourceDataPtr( new RecordA( *( reinterpret_cast<const uint32_t *>( begin ) ) ) );
    }

    RecordAAAA::RecordAAAA( const uint8_t *addr )
    {
        std::memcpy( sin_addr, addr, sizeof( sin_addr ) );
    }

    RecordAAAA::RecordAAAA( const std::string &addr )
    {
        in_addr a = convert_address_string_to_binary( addr );
        std::memcpy( &sin_addr, &a, sizeof( sin_addr ) );
    }

    std::string RecordAAAA::toString() const
    {
        std::stringstream buff;
        buff << std::hex << (uint32_t)sin_addr[ 0 ];
        for ( unsigned int i = 1; i < sizeof( sin_addr ); i++ ) {
            buff << ":" << (uint32_t)sin_addr[ i ];
        }
        return buff.str();
    }

    void RecordAAAA::outputWireFormat( WireFormat &message ) const
    {
        message.pushBuffer( reinterpret_cast<const uint8_t *>( &sin_addr ),
                            reinterpret_cast<const uint8_t *>( &sin_addr ) + sizeof( sin_addr ) );
    }

    std::string RecordAAAA::getAddress() const
    {
	return toString();
    }

    ResourceDataPtr RecordAAAA::parse( const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin != 16 )
            throw FormatError( "invalid AAAA Record length" );
        return ResourceDataPtr( new RecordAAAA( begin ) );
    }

    RecordNS::RecordNS( const Domainname &name, Offset off ) : domainname( name ), offset( off )
    {
    }

    std::string RecordNS::toString() const
    {
        return domainname.toString();
    }

    void RecordNS::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message, offset );
    }

    ResourceDataPtr RecordNS::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return ResourceDataPtr( new RecordNS( name ) );
    }

    RecordMX::RecordMX( uint16_t pri, const Domainname &name, Offset off )
        : priority( pri ), domainname( name ), offset( off )
    {
    }

    std::string RecordMX::toString() const
    {
        std::ostringstream os;
        os << priority << " " << domainname.toString();
        return os.str();
    }

    void RecordMX::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( priority );
        domainname.outputWireFormat( message, offset );
    }

    ResourceDataPtr RecordMX::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 3 )
            throw FormatError( "too few length for MX record," );
        const uint8_t *pos      = begin;
        uint16_t       priority = get_bytes<uint16_t>( &pos );

        Domainname name;
        Domainname::parsePacket( name, packet, pos );
        return ResourceDataPtr( new RecordMX( priority, name ) );
    }

    RecordTXT::RecordTXT( const std::string &d )
    {
        data.push_back( d );
    }

    RecordTXT::RecordTXT( const std::vector<std::string> &d ) : data( d )
    {
    }

    std::string RecordTXT::toString() const
    {
        std::ostringstream os;
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            os << "\"" << data[ i ] << "\" ";
        }

        return os.str();
    }

    void RecordTXT::outputWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < data.size(); i++ ) {
            message.push_back( data[ i ].size() & 0xff );
            for ( unsigned int j = 0; j < data[ i ].size(); j++ )
                message.push_back( data[ i ][ j ] );
        }
    }

    uint16_t RecordTXT::size() const
    {
        uint16_t s = 0;
        for ( auto i = data.begin(); i != data.end(); i++ ) {
            s++;
            s += i->size();
        }
        return s;
    }

    ResourceDataPtr RecordTXT::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 1 )
            throw FormatError( "too few length for TXT record" );
        const uint8_t *          pos = begin;
        std::vector<std::string> txt_data;

        while ( pos < end ) {
            uint8_t length = get_bytes<uint8_t>( &pos );
            if ( pos + length > end )
                throw FormatError( "bad charactor-code length" );
            txt_data.push_back( std::string( pos, pos + length ) );
            pos += length;
        }
        return ResourceDataPtr( new RecordTXT( txt_data ) );
    }

    RecordCNAME::RecordCNAME( const Domainname &name, uint16_t off ) : domainname( name ), offset( off )
    {
    }

    std::string RecordCNAME::toString() const
    {
        return domainname.toString();
    }

    void RecordCNAME::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message, offset );
    }

    ResourceDataPtr RecordCNAME::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return ResourceDataPtr( new RecordCNAME( name ) );
    }

    RecordNAPTR::RecordNAPTR( uint16_t           in_order,
                              uint16_t           in_preference,
                              const std::string &in_flags,
                              const std::string &in_services,
                              const std::string &in_regexp,
                              const Domainname  &in_replacement,
                              uint16_t           in_offset )
        : order( in_order ), preference( in_preference ), flags( in_flags ), services( in_services ),
          regexp( in_regexp ), replacement( in_replacement ), offset( in_offset )
    {
    }

    std::string RecordNAPTR::toString() const
    {
        std::stringstream os;
        os << "order: " << order << ", preference: " << preference << "flags: " << flags << ", services: " << services
           << "regexp: " << regexp << ", replacement: " << replacement;
        return os.str();
    }

    void RecordNAPTR::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( order );
        message.pushUInt16HtoN( preference );
        message.pushUInt8( flags.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( flags.c_str() ),
                            reinterpret_cast<const uint8_t *>( flags.c_str() ) + flags.size() );
        message.pushUInt8( regexp.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( regexp.c_str() ),
                            reinterpret_cast<const uint8_t *>( regexp.c_str() ) + regexp.size() );
        replacement.outputWireFormat( message, offset );
    }

    uint16_t RecordNAPTR::size() const
    {
        return sizeof( order ) + sizeof( preference ) + 1 + flags.size() + 1 + regexp.size() +
               replacement.size( offset );
    }

    ResourceDataPtr RecordNAPTR::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        if ( end - begin < 2 + 2 + 1 + 1 + 1 + 1 )
            throw FormatError( "too short for NAPTR RR" );

        const uint8_t *pos           = begin;
        uint16_t       in_order      = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t       in_preference = ntohs( get_bytes<uint16_t>( &pos ) );

        std::string in_flags, in_services, in_regexp;
        pos = parseCharacterString( pos, end, in_flags );
        pos = parseCharacterString( pos, end, in_services );
        pos = parseCharacterString( pos, end, in_regexp );

        Domainname in_replacement;
        Domainname::parsePacket( in_replacement, packet, pos );
        return ResourceDataPtr(
            new RecordNAPTR( in_order, in_preference, in_flags, in_services, in_regexp, in_replacement ) );
    }

    RecordDNAME::RecordDNAME( const Domainname &name, uint16_t off ) : domainname( name ), offset( off )
    {
    }

    std::string RecordDNAME::toString() const
    {
        return domainname.toString();
    }

    void RecordDNAME::outputWireFormat( WireFormat &message ) const
    {
        domainname.outputWireFormat( message, offset );
    }

    ResourceDataPtr RecordDNAME::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname name;
        Domainname::parsePacket( name, packet, begin );
        return ResourceDataPtr( new RecordDNAME( name ) );
    }

    RecordSOA::RecordSOA( const Domainname &mn,
                          const Domainname &rn,
                          uint32_t          sr,
                          uint32_t          rf,
                          uint32_t          rt,
                          uint32_t          ex,
                          uint32_t          min,
                          Offset            moff,
                          Offset            roff )
        : mname( mn ), rname( rn ), serial( sr ), refresh( rf ), retry( rt ), expire( ex ), minimum( min ),
          mname_offset( moff ), rname_offset( roff )
    {
    }

    std::string RecordSOA::toString() const
    {
        std::ostringstream soa_str;
        soa_str << mname.toString() << " " << rname.toString() << " " << serial << " " << refresh << " " << retry << " "
                << expire << " " << minimum;
        return soa_str.str();
    }

    void RecordSOA::outputWireFormat( WireFormat &message ) const
    {
        mname.outputWireFormat( message, mname_offset );
        rname.outputWireFormat( message, rname_offset );
        message.pushUInt32HtoN( serial );
        message.pushUInt32HtoN( refresh );
        message.pushUInt32HtoN( retry );
        message.pushUInt32HtoN( expire );
        message.pushUInt32HtoN( minimum );
    }

    uint16_t RecordSOA::size() const
    {
        return mname.size( mname_offset ) + rname.size( rname_offset ) + sizeof( serial ) + sizeof( refresh ) +
               sizeof( retry ) + sizeof( expire ) + sizeof( minimum );
    }

    ResourceDataPtr RecordSOA::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        Domainname     mname_result, rname_result;
        const uint8_t *pos = begin;
        pos                = Domainname::parsePacket( mname_result, packet, pos );
        pos                = Domainname::parsePacket( rname_result, packet, pos );
        uint32_t serial    = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t refresh   = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t retry     = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t expire    = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t minimum   = ntohl( get_bytes<uint32_t>( &pos ) );

        return ResourceDataPtr( new RecordSOA( mname_result, rname_result, serial, refresh, retry, expire, minimum ) );
    }

    std::string RecordAPL::toString() const
    {
        std::ostringstream os;
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            os << ( i->negation ? "!" : "" ) << i->address_family << ":" << printPacketData( i->afd ) << " ";
        }
        return os.str();
    }

    void RecordAPL::outputWireFormat( WireFormat &message ) const
    {
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            message.pushUInt16HtoN( i->address_family );
            message.pushUInt8( i->prefix );
            message.pushUInt8( ( i->negation ? ( 1 << 7 ) : 0 ) | i->afd.size() );
            message.pushBuffer( i->afd );
        }
    }

    uint16_t RecordAPL::size() const
    {
        uint16_t s = 0;
        for ( auto i = apl_entries.begin(); i != apl_entries.end(); i++ ) {
            s += ( 2 + 1 + 1 + i->afd.size() );
        }
        return s;
    }

    ResourceDataPtr RecordAPL::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        std::vector<APLEntry> entries;
        const uint8_t *       pos = begin;

        while ( pos < end ) {
            if ( end - pos < 4 )
                throw FormatError( "too short length of APL RDdata" );

            APLEntry entry;
            entry.address_family = ntohs( get_bytes<uint16_t>( &pos ) );
            entry.prefix         = get_bytes<uint8_t>( &pos );
            uint8_t neg_afd_len  = get_bytes<uint8_t>( &pos );
            entry.negation       = ( neg_afd_len & 0x01 ) == 0x01;
            uint8_t afd_length   = ( neg_afd_len >> 1 );

            if ( end - pos < afd_length )
                throw FormatError( "invalid AFD Data length" );

            PacketData in_afd;
            entry.afd.insert( in_afd.end(), pos, pos + afd_length );
            pos += afd_length;
            entries.push_back( entry );
        }

        return ResourceDataPtr( new RecordAPL( entries ) );
    }


    void RecordRRSIG::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( type_covered );
        message.pushUInt8( algorithm );
        message.pushUInt8( label_count );
        message.pushUInt32HtoN( original_ttl );
        message.pushUInt32HtoN( expiration );
        message.pushUInt32HtoN( inception );
        message.pushUInt16HtoN( key_tag );
        signer.outputCanonicalWireFormat( message );
        message.pushBuffer( signature );
    }

    std::string RecordDNSKey::toString() const
    {
        std::string public_key_str;
        encode_to_base64( public_key, public_key_str );

        std::ostringstream os;
        os << "KSK/ZSK: "     << ( flag & KSK ? "KSK" : "ZSK" ) << ", "
           << "Protocal: "    << 3 << ", "
           << "Algorithm: "   << algorithm << ", "
           << "Public Key:: " << public_key_str;
        return os.str();
    }

    void RecordDNSKey::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( flag );
        message.pushUInt8( 3 );
        message.pushUInt8( algorithm );
        message.pushBuffer( public_key );
    }

    ResourceDataPtr RecordDNSKey::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *      pos   = begin;
        uint16_t             f     = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t              proto = get_bytes<uint8_t>( &pos );
        uint8_t              algo  = get_bytes<uint8_t>( &pos );
        std::vector<uint8_t> key;
        key.insert( key.end(), pos, end );

        return ResourceDataPtr( new RecordDNSKey( f, algo, key ) );
    }

    std::string RecordDS::toString() const
    {
        std::string digest_str;
        encode_to_base64( digest, digest_str );

        std::ostringstream os;
        os << "keytag: " << key_tag << ", "
           << "algorithm: " << algorithm << ", "
           << "digest type: " << digest_type << ", "
           << "digest: " << digest_str;
        return os.str();
    }

    void RecordDS::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( key_tag );
        message.pushUInt8( algorithm );
        message.pushUInt8( digest_type );
        message.pushBuffer( digest );
    }

    ResourceDataPtr RecordDS::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *      pos   = begin;
        uint16_t             tag   = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t              algo  = get_bytes<uint8_t>( &pos );
        uint8_t              dtype = get_bytes<uint8_t>( &pos );
        std::vector<uint8_t> d;
        d.insert( d.end(), pos, end );

        return ResourceDataPtr( new RecordDS( tag, algo, dtype, d ) );
    }


    void NSECBitmapField::Window::add( Type t )
    {
	types.push_back( t );
    }

    uint8_t NSECBitmapField::Window::getWindowSize() const
    {
	uint8_t max_bytes = 0;
	for ( Type t : types ) {
	    max_bytes = std::max<uint8_t>( max_bytes, typeToBitmapIndex( t ) / 8 + 1 );
	}
	return max_bytes;
    }

    uint16_t NSECBitmapField::Window::size() const
    {
        return getWindowSize() + 2;
    }

    void NSECBitmapField::Window::outputWireFormat( WireFormat &message ) const
    {
	message.pushUInt8( index );
	message.pushUInt8( getWindowSize() );

	std::vector<uint8_t> bitmaps;
	bitmaps.resize( getWindowSize());
	for ( uint8_t &v : bitmaps )
	    v = 0;
	for ( Type t : types ) {
	    uint8_t index = 7 - ( typeToBitmapIndex( t ) % 8 );
	    uint8_t flag  = 1 << index;
	    bitmaps.at( typeToBitmapIndex( t ) / 8 ) |= flag;
	}
	message.pushBuffer( bitmaps );
    }

    std::string NSECBitmapField::Window::toString() const
    {
	std::ostringstream os;
	for ( Type t : types ) {
	    os << type_code_to_string( t ) << ",";
	}

	std::string result( os.str() );
	result.pop_back();
	return result;
    }

    uint8_t NSECBitmapField::Window::typeToBitmapIndex( Type t )
    {
	return (0xff & t);
    }

    const uint8_t *NSECBitmapField::Window::parse( NSECBitmapField::Window &ref_win, const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
	uint8_t window_index = *begin++;
	uint8_t window_size  = *begin++;
	if ( begin + window_size >= end )
	    throw std::runtime_error( "Bad NSEC bitmap size" );

	ref_win.setIndex( window_index );
	for ( uint8_t bitmap_index = 0 ; bitmap_index / 8 < window_size ; bitmap_index++ ) {
	    uint8_t flag = 1 << ( ( bitmap_index - 1 ) % 8 );
	    if( *( begin + ( bitmap_index / 8 ) ) & flag ) {
		Type t = 0x0100 * window_index + bitmap_index;
		ref_win.add( t );
	    }
	}
    };

    void NSECBitmapField::add( Type t )
    {
	uint8_t window_index = typeToWindowIndex( t );
	auto window = windows.find( window_index );
	if ( window == windows.end() ) {
	    windows.insert( std::make_pair( window_index, Window( window_index ) ) );
	}
	window = windows.find( window_index );
	window->second.add( t );
    }

    void NSECBitmapField::addWindow( const NSECBitmapField::Window &win )
    {
	uint8_t window_index = win.getIndex();
	auto window = windows.find( window_index );
	if ( window == windows.end() ) {
	    windows.insert( std::make_pair( window_index, win ) );
	}
	else {
	    std::ostringstream os;
	    os << "Bad NSEC record( mutiple window index \"" << (int)window_index << "\" is found.";
	    throw std::runtime_error( os.str() );
	}
    }

    std::vector<Type> NSECBitmapField::getTypes() const
    {
        std::vector<Type> types;
        for ( auto bitmap : windows ) {
            types.insert( types.end(), bitmap.second.getTypes().begin(), bitmap.second.getTypes().end() );
        }
        return types;
    }

    std::string NSECBitmapField::toString() const
    {
	std::ostringstream os;
	for ( auto win : windows )
	    os << win.second.toString() << ",";
	std::string result( os.str() );
	result.pop_back();
	return result;
    }

    uint16_t NSECBitmapField::size() const
    {
	uint16_t s = 0;
	for ( auto win : windows )
	    s += win.second.size();
	return s;
    }

    void NSECBitmapField::outputWireFormat( WireFormat &message ) const
    {
	for ( auto win : windows )
	    win.second.outputWireFormat( message );
    }

    uint8_t NSECBitmapField::typeToWindowIndex( Type t )
    {
	return (0xff00 & t) >> 8;
    }

    const uint8_t *NSECBitmapField::parse( NSECBitmapField &ref_bitmaps, const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
	while ( begin < end ) {
	    NSECBitmapField::Window win;
	    begin = NSECBitmapField::Window::parse( win, packet, begin, end );
	    ref_bitmaps.addWindow( win );
	}
	return begin;
    }

    RecordNSEC::RecordNSEC( const Domainname &next, const std::vector<Type> &types )
	: next_domainname( next )
    {
	for ( Type t : types )
	    bitmaps.add( t );
    }


    std::string RecordNSEC::toString() const
    {
	return next_domainname.toString() + "( " + bitmaps.toString() + " )";
    }

    void RecordNSEC::outputWireFormat( WireFormat &message ) const
    {
	next_domainname.outputWireFormat( message );
	bitmaps.outputWireFormat( message );
    }

    uint16_t RecordNSEC::size() const
    {
	return next_domainname.size() + bitmaps.size();
    }

    ResourceDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
	Domainname next;
	const uint8_t *pos = Domainname::parsePacket( next, packet, begin );
	NSECBitmapField bitmaps;
	NSECBitmapField::parse( bitmaps, packet, pos, end );
	return ResourceDataPtr( new RecordNSEC( next, bitmaps ) );
    }


    std::string RecordOptionsData::toString() const
    {
        std::ostringstream os;

        for ( auto i = options.begin(); i != options.end(); ++i )
            os << ( *i )->toString();

        return os.str();
    }


    uint16_t RecordOptionsData::size() const
    {
        uint16_t rr_size = 0;
        for ( auto i = options.begin(); i != options.end(); i++ ) {
            rr_size += ( *i )->size();
        }
        return rr_size;
    }

    void RecordOptionsData::outputWireFormat( WireFormat &message ) const
    {
        for ( auto i = options.begin(); i != options.end(); i++ ) {
            ( *i )->outputWireFormat( message );
        }
    }

    ResourceDataPtr RecordOptionsData::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        std::vector<OptPseudoRROptPtr> options;
        while ( pos < end ) {
            if ( end - pos < 4 ) {
                std::ostringstream os;
                os << "remains data " << end - pos << " is too few size.";
                throw FormatError( os.str() );
            }
            uint16_t option_code = ntohs( get_bytes<uint16_t>( &pos ) );
            uint16_t option_size = ntohs( get_bytes<uint16_t>( &pos ) );

            if ( option_size == 0 )
                continue;
            if ( pos + option_size > end ) {
                std::ostringstream os;
                os << "option data size is missmatch: option_size: " << option_size << "; remain size " << end - pos;
                throw FormatError( os.str() );
            }

            switch ( option_code ) {
            case OPT_NSID:
                options.push_back( NSIDOption::parse( pos, pos + option_size ) );
                break;
            default:
                break;
            }
            pos += option_size;
        }

        return ResourceDataPtr( new RecordOptionsData( options ) );
    }

    ResponseSectionEntry generate_opt_pseudo_record( const OptPseudoRecord &opt )
    {
        ResponseSectionEntry entry;
        entry.r_domainname    = opt.domainname;
        entry.r_type          = TYPE_OPT;
        entry.r_class         = opt.payload_size;
        entry.r_ttl           = ( ( (uint32_t)opt.rcode ) << 24 ) + ( opt.dobit ? ( (uint32_t)1 << 15 ) : 0 );
        entry.r_resource_data = opt.record_options_data;
        entry.r_offset        = opt.offset;

        return entry;
    }

    OptPseudoRecord parse_opt_pseudo_record( const ResponseSectionEntry &record )
    {
        OptPseudoRecord opt;
        opt.domainname          = record.r_domainname;
        opt.payload_size        = record.r_class;
        opt.rcode               = record.r_ttl >> 24;
        opt.version             = 0xff & ( record.r_ttl >> 16 );
        opt.dobit               = ( ( 1 << 7 ) & ( record.r_ttl >> 8 ) ) ? true : false; 
        opt.record_options_data = record.r_resource_data;

        std::cerr << "TTL: " << record.r_ttl << std::endl;
        return opt;
    }

    void NSIDOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_NSID );
        message.pushUInt16HtoN( nsid.size() );
        message.pushBuffer( reinterpret_cast<const uint8_t *>( nsid.c_str() ),
                            reinterpret_cast<const uint8_t *>( nsid.c_str() ) + nsid.size() );
    }

    OptPseudoRROptPtr NSIDOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        std::string nsid( begin, end );
        return OptPseudoRROptPtr( new NSIDOption( nsid ) );
    }

    unsigned int ClientSubnetOption::getAddressSize( uint8_t prefix )
    {
        return ( prefix + 7 ) / 8;
    }

    void ClientSubnetOption::outputWireFormat( WireFormat &message ) const
    {
        message.pushUInt16HtoN( OPT_CLIENT_SUBNET );
        message.pushUInt16HtoN( size() );
        message.pushUInt16HtoN( family );
        message.pushUInt8( source_prefix );
        message.pushUInt8( scope_prefix );

        if ( family == IPv4 ) {
            uint8_t addr_buf[ 4 ];
            inet_pton( AF_INET, address.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( source_prefix ) );
        } else {
            uint8_t addr_buf[ 16 ];
            inet_pton( AF_INET6, address.c_str(), addr_buf );
            message.pushBuffer( addr_buf, addr_buf + getAddressSize( source_prefix ) );
        }
    }

    uint16_t ClientSubnetOption::size() const
    {
        return 2 + 1 + 1 + getAddressSize( source_prefix ) + 4;
    }

    std::string ClientSubnetOption::toString() const
    {
        std::ostringstream os;
        os << "EDNSClientSubnet: "
           << "source:  " << (int)source_prefix << "scope:   " << (int)scope_prefix << "address: " << address;
        return os.str();
    }

    OptPseudoRROptPtr ClientSubnetOption::parse( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *pos = begin;

        uint16_t fam    = ntohs( get_bytes<uint16_t>( &pos ) );
        uint8_t  source = get_bytes<uint8_t>( &pos );
        uint8_t  scope  = get_bytes<uint8_t>( &pos );

        if ( fam == IPv4 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "0.0.0.0" ) );

            uint8_t addr_buf[ 4 ];
            char    addr_str[ INET_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else if ( fam == IPv6 ) {
            if ( source > 32 ) {
                throw FormatError( "invalid source prefix length of EDNS-Client-Subet" );
            }
            if ( scope > 32 ) {
                throw FormatError( "invalid scope prefix length of EDNS-Client-Subet" );
            }

            if ( source == 0 )
                return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, "::0" ) );

            uint8_t addr_buf[ 16 ];
            char    addr_str[ INET6_ADDRSTRLEN ];

            std::memset( addr_buf, 0, sizeof( addr_buf ) );
            std::memset( addr_str, 0, sizeof( addr_str ) );

            std::memcpy( addr_buf, pos, getAddressSize( source ) );
            inet_ntop( AF_INET6, addr_buf, addr_str, sizeof( addr_buf ) );

            return OptPseudoRROptPtr( new ClientSubnetOption( fam, source, scope, addr_str ) );
        } else {
            throw FormatError( "invalid family of EDNS-Client-Subet" );
        }
    }

    uint16_t RecordTKey::size() const
    {
        return algorithm.size() + //
               4 +                // inception
               4 +                // expiration
               2 +                // mode
               2 +                // error
               2 +                // key size
               key.size() +       // key
               2 +                // other data size
               other_data.size();
    }

    void RecordTKey::outputWireFormat( WireFormat &message ) const
    {
        algorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( inception );
        message.pushUInt32HtoN( expiration );
        message.pushUInt16HtoN( mode );
        message.pushUInt16HtoN( error );
        message.pushUInt16HtoN( key.size() );
        message.pushBuffer( key );
        message.pushUInt16HtoN( other_data.size() );
        message.pushBuffer( other_data );
    }

    uint16_t RecordTSIGData::size() const
    {
        return algorithm.size() + // ALGORITHM
               6 +                // signed time
               2 +                // FUDGE
               2 +                // MAC SIZE
               mac.size() +       // MAC
               2 +                // ORIGINAL ID
               2 +                // ERROR
               2 +                // OTHER LENGTH
               other.size();      // OTHER
    }

    void RecordTSIGData::outputWireFormat( WireFormat &message ) const
    {
        uint32_t time_high = signed_time >> 16;
        uint32_t time_low  = ( ( 0xffff & signed_time ) << 16 ) + fudge;

        algorithm.outputCanonicalWireFormat( message );
        message.pushUInt32HtoN( time_high );
        message.pushUInt32HtoN( time_low );
        message.pushUInt16HtoN( mac_size );
        message.pushBuffer( mac );
        message.pushUInt16HtoN( original_id );
        message.pushUInt16HtoN( error );
        message.pushUInt16HtoN( other_length );
        message.pushBuffer( other );
    }

    std::string RecordTSIGData::toString() const
    {
        std::ostringstream os;
        os << "key name: " << key_name << ", "
           << "algorigthm: " << algorithm << ", "
           << "signed time: " << signed_time << ", "
           << "fudge: " << fudge << ", "
           << "MAC: " << printPacketData( mac ) << ", "
           << "Original ID: " << original_id << ", "
           << "Error: " << error;

        return os.str();
    }

    ResourceDataPtr
    RecordTSIGData::parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end, const Domainname &key_name )
    {
        const uint8_t *pos = begin;

        Domainname algorithm;
        pos = Domainname::parsePacket( algorithm, packet, pos );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );

        uint64_t time_high = ntohl( get_bytes<uint32_t>( &pos ) );
        uint32_t time_low  = ntohl( get_bytes<uint32_t>( &pos ) );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );
        uint64_t signed_time = ( time_high << 16 ) + ( time_low >> 16 );
        uint16_t fudge       = time_low;

        uint16_t mac_size = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos + mac_size >= end )
            throw FormatError( "too short message for TSIG RR" );
        PacketData mac;
        mac.insert( mac.end(), pos, pos + mac_size );
        pos += mac_size;

        uint16_t original_id = ntohs( get_bytes<uint16_t>( &pos ) );
        uint16_t error       = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos >= end )
            throw FormatError( "too short message for TSIG RR" );

        uint16_t other_length = ntohs( get_bytes<uint16_t>( &pos ) );
        if ( pos + other_length > end )
            throw FormatError( "too short message for TSIG RR" );
        PacketData other;
        other.insert( other.end(), pos, pos + other_length );
        pos += other_length;

        return ResourceDataPtr( new RecordTSIGData( key_name.toString(),
                                                    algorithm.toString(),
                                                    signed_time,
                                                    fudge,
                                                    mac_size,
                                                    mac,
                                                    original_id,
                                                    error,
                                                    other_length,
                                                    other ) );
    }

    struct TSIGHash {
        Domainname name;
        Domainname algorithm;
        uint64_t   signed_time;
        uint16_t   fudge;
        uint16_t   error;
        uint16_t   other_length;
        PacketData other;

        PacketData getPacket() const;
        uint16_t   size() const;
    };

    uint16_t TSIGHash::size() const
    {
        return name.size() + 2 + 4 + algorithm.size() + 6 + 2 + 2 + 2 + other.size();
    }

    PacketData TSIGHash::getPacket() const
    {
        PacketData packet;
        packet.resize( size() );

        PacketData name_data      = name.getCanonicalWireFormat();
        PacketData algorithm_data = algorithm.getCanonicalWireFormat();

        uint32_t time_high = signed_time >> 16;
        uint32_t time_low  = ( ( 0xffff & signed_time ) << 16 ) + fudge;

        uint8_t *pos = &packet[ 0 ];
        pos          = std::copy( name_data.begin(), name_data.end(), pos );
        pos          = set_bytes<uint16_t>( htons( CLASS_ANY ), pos );
        pos          = set_bytes<uint32_t>( htonl( 0 ), pos );
        pos          = std::copy( algorithm_data.begin(), algorithm_data.end(), pos );
        pos          = set_bytes<uint32_t>( htonl( time_high ), pos );
        pos          = set_bytes<uint32_t>( htonl( time_low ), pos );
        pos          = set_bytes<uint16_t>( htons( error ), pos );
        pos          = set_bytes<uint16_t>( htons( other_length ), pos );
        pos          = std::copy( other.begin(), other.end(), pos );

        return packet;
    }


    PacketData getTSIGMAC( const TSIGInfo &tsig_info, const PacketData &message, const PacketData &query_mac )
    {
        PacketData   mac( EVP_MAX_MD_SIZE );
        unsigned int mac_size = EVP_MAX_MD_SIZE;

        PacketData hash_data = query_mac;

        PacketData         presigned_message = message;
        PacketHeaderField *h                 = reinterpret_cast<PacketHeaderField *>( &presigned_message[ 0 ] );
        h->id                                = htons( tsig_info.original_id );
        hash_data.insert( hash_data.end(), presigned_message.begin(), presigned_message.end() );

        TSIGHash tsig_hash;
        tsig_hash.name            = tsig_info.name;
        tsig_hash.algorithm       = tsig_info.algorithm;
        tsig_hash.signed_time     = tsig_info.signed_time;
        tsig_hash.fudge           = tsig_info.fudge;
        tsig_hash.error           = tsig_info.error;
        tsig_hash.other_length    = tsig_info.other.size();
        tsig_hash.other           = tsig_info.other;
        PacketData tsig_hash_data = tsig_hash.getPacket();

        hash_data.insert( hash_data.end(), tsig_hash_data.begin(), tsig_hash_data.end() );

        OpenSSL_add_all_digests();
        HMAC( EVP_get_digestbyname( "md5" ),
              &tsig_info.key[ 0 ],
              tsig_info.key.size(),
              reinterpret_cast<const unsigned char *>( &hash_data[ 0 ] ),
              hash_data.size(),
              reinterpret_cast<unsigned char *>( &mac[ 0 ] ),
              &mac_size );
        EVP_cleanup();
        mac.resize( mac_size );

        return mac;
    }

    void addTSIGResourceRecord( const TSIGInfo &tsig_info, WireFormat &message, const PacketData &query_mac )
    {
        PacketData mac = getTSIGMAC( tsig_info, message.get(), query_mac );

        ResponseSectionEntry entry;
        entry.r_domainname    = tsig_info.name;
        entry.r_type          = TYPE_TSIG;
        entry.r_class         = CLASS_ANY;
        entry.r_ttl           = 0;
        entry.r_resource_data = ResourceDataPtr( new RecordTSIGData( tsig_info.name,
                                                                     tsig_info.algorithm,
                                                                     tsig_info.signed_time,
                                                                     tsig_info.fudge,
                                                                     mac.size(),
                                                                     mac,
                                                                     tsig_info.original_id,
                                                                     tsig_info.error,
                                                                     tsig_info.other.size(),
                                                                     tsig_info.other ) );
        entry.r_offset = NO_COMPRESSION;

        PacketData         packet  = message.get();
        PacketHeaderField *header  = reinterpret_cast<PacketHeaderField *>( &packet[ 0 ] );
        uint16_t           adcount = ntohs( header->additional_infomation_count );
        adcount++;
        header->additional_infomation_count = htons( adcount );

        PacketData tsig_packet = generate_response_section( entry );
        packet.insert( packet.end(), tsig_packet.begin(), tsig_packet.end() );

        message.clear();
        message.pushBuffer( packet );
    }

    bool verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const PacketInfo &packet_info, const WireFormat &message )
    {
        PacketData hash_data = message.get();

        PacketHeaderField *header = reinterpret_cast<PacketHeaderField *>( &hash_data[ 0 ] );
        header->id                = htons( tsig_info.original_id );
        uint16_t adcount          = ntohs( header->additional_infomation_count );
        if ( adcount < 1 ) {
            throw FormatError( "adcount of message with TSIG record must not be 0" );
        }
        header->additional_infomation_count = htons( adcount - 1 );

        const uint8_t *pos = &hash_data[ 0 ];
        pos += sizeof( PacketHeaderField );

        // skip question section
        for ( uint16_t i = 0; i < packet_info.question_section.size(); i++ )
            pos = parse_question_section( &hash_data[ 0 ], pos ).second;

        // skip answer section
        for ( uint16_t i = 0; i < packet_info.answer_section.size(); i++ )
            pos = parse_response_section( &hash_data[ 0 ], pos ).second;

        // skip authority section
        for ( uint16_t i = 0; i < packet_info.authority_section.size(); i++ )
            pos = parse_response_section( &hash_data[ 0 ], pos ).second;

        // skip non TSIG Record in additional section
        bool is_found_tsig = false;
        for ( uint16_t i = 0; i < packet_info.additional_infomation_section.size(); i++ ) {
            ResponseSectionEntryPair parsed_rr_pair = parse_response_section( &hash_data[ 0 ], pos );
            if ( parsed_rr_pair.first.r_type == TYPE_TSIG ) {
                is_found_tsig = true;
                break;
            } else {
                pos = parsed_rr_pair.second;
            }
        }

        if ( !is_found_tsig ) {
            throw FormatError( "not found tsig record" );
        }
        // remove TSIG RR( TSIG must be final RR in message )
        hash_data.resize( pos - &hash_data[ 0 ] );

        PacketData mac = getTSIGMAC( tsig_info, hash_data, PacketData() );

        if ( mac.size() != tsig_info.mac_size )
            return false;

        for ( unsigned int i = 0; mac.size(); i++ ) {
            if ( mac[ i ] != tsig_info.mac[ i ] )
                return false;
        }

        return true;
    }
}
