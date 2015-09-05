#include "dns.hpp"
#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <arpa/inet.h>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/lexical_cast.hpp>

namespace dns
{

    PacketData generate_dns_packet( const PacketHeaderField &header,
				    const std::vector<QuestionSectionEntry> &question,
				    const std::vector<ResponseSectionEntry> &answer,
				    const std::vector<ResponseSectionEntry> &authority,
				    const std::vector<ResponseSectionEntry> &additional )
    {
	PacketHeaderField h = header;
        h.question_count              = htons( question.size() );
        h.answer_count                = htons( answer.size() );
        h.authority_count             = htons( authority.size() );
        h.additional_infomation_count = htons( additional.size() );

        PacketData packet;
	std::insert_iterator<PacketData> pos( packet, packet.begin() );
	pos = std::copy( reinterpret_cast<const uint8_t *>( &h ),
			 reinterpret_cast<const uint8_t *>( &h ) + sizeof(h),
			 pos );

        for( std::vector<QuestionSectionEntry>::const_iterator q = question.begin() ;
             q != question.end() ; ++q ) {
            PacketData entry = generate_question_section( *q );
	    pos = std::copy( entry.begin(), entry.end(), pos );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator q = answer.begin() ;
             q != answer.end() ; ++q ) {
            PacketData entry = generate_response_section( *q );
	    pos = std::copy( entry.begin(), entry.end(), pos );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator q = authority.begin() ;
             q != authority.end() ; ++q ) {
            PacketData entry = generate_response_section( *q );
	    pos = std::copy( entry.begin(), entry.end(), pos );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator q = additional.begin() ;
             q != additional.end() ; ++q ) {
            PacketData entry = generate_response_section( *q );
	    pos = std::copy( entry.begin(), entry.end(), pos );
        }

        return packet;
    }


    PacketData generate_dns_packet( const PacketInfo &info )
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
        header.authentic_data       = 0;
        header.checking_disabled    = info.checking_disabled;
        header.response_code        = info.response_code;

	std::vector<ResponseSectionEntry> additional = info.additional_infomation_section;

	if ( info.edns0 ) {
	    additional.push_back( generate_opt_pseudo_record( info.opt_pseudo_rr ) );
	}

        return generate_dns_packet( header,
				    info.question_section,
				    info.answer_section,
				    info.authority_section,
				    additional );
    }


    PacketData generate_dns_query_packet( const QueryPacketInfo &query )
    {
	PacketInfo info;
	info.id                   = query.id;
	info.opcode               = 0;
	info.query_response       = 0;
	info.authoritative_answer = 0;
	info.truncation           = 0;
        info.recursion_desired    = query.recursion;
        info.recursion_available  = 0;
        info.checking_disabled    = 0;
        info.response_code        = 0;

	info.edns0                = query.edns0;
	info.opt_pseudo_rr        = query.opt_pseudo_rr;

	info.question_section = query.question;

	return generate_dns_packet( info );
    }


    PacketData generate_dns_response_packet( const ResponsePacketInfo &response )
    {
	PacketInfo info;
	info.id                   = response.id;
	info.opcode               = 0;
	info.query_response       = 1;
	info.authoritative_answer = response.authoritative_answer;
	info.truncation           = response.truncation;
        info.recursion_desired    = 0;
        info.recursion_available  = response.recursion_available;
        info.checking_disabled    = 0;
        info.response_code        = response.response_code;

	info.edns0                = response.edns0;
	info.opt_pseudo_rr        = response.opt_pseudo_rr;

	info.question_section              = response.question;
	info.answer_section                = response.answer;
	info.authority_section             = response.authority;
	info.additional_infomation_section = response.additional_infomation;

	return generate_dns_packet( info );
    }


    QueryPacketInfo parse_dns_query_packet( const uint8_t *begin, const uint8_t *end )
    {
	const uint8_t *packet = begin;
        QueryPacketInfo packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( packet );

        packet_info.id        = ntohs( header->id );
        packet_info.recursion = header->recursion_desired;

        int question_count              = ntohs( header->question_count );
        // int answer_count                = ntohs( header->answer_count );
        // int authority_count             = ntohs( header->authority_count );
        // int additional_infomation_count = ntohs( header->additional_infomation_count );

        packet += sizeof(PacketHeaderField);
        for ( int i = 0 ; i < question_count ; i++ ) {
            QuestionSectionEntryPair pair = parse_question_section( begin, packet );
            packet_info.question.push_back( pair.first );
            packet = pair.second;
        }
        return packet_info;
    }


    ResponsePacketInfo parse_dns_response_packet( const uint8_t *begin, const uint8_t *end )
    {
        const uint8_t *packet = begin;

        ResponsePacketInfo packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( begin );

        packet_info.id                   = ntohs( header->id );
        packet_info.truncation           = header->truncation;
        packet_info.authoritative_answer = header->authoritative_answer;
        packet_info.response_code        = header->response_code;
        packet_info.checking_disabled    = header->checking_disabled;
        packet_info.authentic_data       = header->authentic_data;
        packet_info.recursion_available  = header->recursion_available;

        int question_count              = ntohs( header->question_count );
        int answer_count                = ntohs( header->answer_count );
        int authority_count             = ntohs( header->authority_count );
        int additional_infomation_count = ntohs( header->additional_infomation_count );

        packet += sizeof(PacketHeaderField);
        for ( int i = 0 ; i < question_count ; i++ ) {
            QuestionSectionEntryPair pair = parse_question_section( begin, packet );
            packet_info.question.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0 ; i < answer_count ; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.answer.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0 ; i < authority_count ; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.authority.push_back( pair.first );
            packet = pair.second;
        }
        for ( int i = 0 ; i < additional_infomation_count ; i++ ) {
            ResponseSectionEntryPair pair = parse_response_section( begin, packet );
            packet_info.additional_infomation.push_back( pair.first );
            packet = pair.second;
        }

        return packet_info;
    }


    PacketData convert_domainname_string_to_binary( const std::string &domainname,
						    uint32_t compress_offset )
    {
        PacketData bin;
        PacketData label;

	if ( domainname == "." || domainname == "" ) {
	    if ( compress_offset == 0xffff ) {
		bin.push_back( 0 );
		return bin;
	    }
	    else {
		bin.push_back( 0xC0 | (uint8_t)( compress_offset >> 8 ) );  
		bin.push_back( 0xff & (uint8_t)compress_offset );
	    }
	}

        for( std::string::const_iterator i = domainname.begin() ; i != domainname.end() ; ++i ) {
            if ( *i == '.' ) {
                if ( label.size() != 0 ) {
                    bin.push_back( boost::numeric_cast<uint8_t>( label.size() ) );
                    bin.insert( bin.end(), label.begin(), label.end() );
                    label.clear();
                }
            }
            else {
                label.push_back( boost::numeric_cast<uint8_t>( *i ) );
            }
        }
        if ( ! label.empty() ) {
	    bin.push_back( boost::numeric_cast<uint8_t>( label.size() ) );
	    bin.insert( bin.end(), label.begin(), label.end() );
	    if ( compress_offset != 0xffff ) {
		bin.push_back( 0xC0 | ( compress_offset >> 8 ) );
		bin.push_back( 0xff & compress_offset );
	    }
	    else {
		bin.push_back( 0 );
	    }
	}

        return bin;
    }


    std::pair<std::string, const uint8_t *> convert_domainname_binary_to_string( const uint8_t *packet,
										 const uint8_t *begin,
										 int recur ) throw(FormatError)
    {
	if ( recur > 100 ) {
	    throw FormatError( "detected domainname decompress loop" );
	}
        std::string domainname;
	const uint8_t *p = begin;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                int offset = ntohs( *( reinterpret_cast<const uint16_t *>( p ) ) ) & 0x0bff;
		if ( packet + offset > begin - 2 ) {
		    throw FormatError( "detected forword reference of domainname decompress" );
		}

                std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet,
												    packet + offset,
												    recur + 1 );
                return std::pair<std::string, const uint8_t *>( domainname + pair.first, p + 2 );
            }

            uint8_t label_length = *p;
            p++;
            for ( uint8_t i = 0 ; i < label_length ; i++, p++ ) {
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
        PacketData packet = convert_domainname_string_to_binary( question.q_domainname );
        packet.resize( packet.size() + sizeof(uint16_t) + sizeof(uint16_t) );
        uint8_t *p = packet.data() + packet.size() - sizeof(uint16_t) - sizeof(uint16_t);
        p = dns::set_bytes<uint16_t>( htons( question.q_type ),  p );
        p = dns::set_bytes<uint16_t>( htons( question.q_class ), p );

        return packet;
    }

    QuestionSectionEntryPair parse_question_section( const uint8_t *packet, const uint8_t *p )
    {
        std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet, p );
        p = pair.second;

        QuestionSectionEntry sec;
        sec.q_domainname = pair.first;
        sec.q_type  = ntohs( get_bytes<uint16_t>( &p ) );
        sec.q_class = ntohs( get_bytes<uint16_t>( &p ) );

        return QuestionSectionEntryPair( sec, p );
    }


    PacketData generate_response_section( const ResponseSectionEntry &response )
    {
        PacketData packet_name = convert_domainname_string_to_binary( response.r_domainname, response.r_offset );
        PacketData packet_rd   = response.r_resource_data->getPacket();
        PacketData packet( packet_name.size() +
			   2 +
			   2 +
			   4 +
			   2 +
			   packet_rd.size() );
        uint8_t *p = packet.data();

        std::memcpy( p, packet_name.data(), packet_name.size() ); p += packet_name.size();

        p = dns::set_bytes<uint16_t>( htons( response.r_type ),  p );
        p = dns::set_bytes<uint16_t>( htons( response.r_class ), p );
        p = dns::set_bytes<uint32_t>( htonl( response.r_ttl ),   p );
        p = dns::set_bytes<uint16_t>( htons( packet_rd.size() ), p );

        std::memcpy( p, packet_rd.data(), packet_rd.size() );

        return packet;
    }

    ResponseSectionEntryPair parse_response_section( const uint8_t *packet, const uint8_t *begin )
    {
        std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet, begin );
        const uint8_t *p = pair.second;

        ResponseSectionEntry sec;
        sec.r_domainname     = pair.first;
        sec.r_type           = ntohs( get_bytes<uint16_t>( &p ) );
        sec.r_class          = ntohs( get_bytes<uint16_t>( &p ) );
        sec.r_ttl            = ntohl( get_bytes<uint32_t>( &p ) );
        uint16_t data_length = ntohs( get_bytes<uint16_t>( &p ) );

        ResourceDataPtr parsed_data;
        switch ( sec.r_type ) {
        case TYPE_A:
            parsed_data = RecordA::parse( p, p + data_length );
            break;
        case TYPE_AAAA:
            parsed_data = RecordAAAA::parse( p, p + data_length );
            break;
        case TYPE_NS:
            parsed_data = RecordNS::parse( packet, p, p + data_length );
            break;
        case TYPE_CNAME:
            parsed_data = RecordCNAME::parse( packet, p, p + data_length );
            break;
        case TYPE_MX:
            parsed_data = RecordMX::parse( packet, p, p + data_length );
            break;
        case TYPE_TXT:
            parsed_data = RecordTXT::parse( packet, p, p + data_length );
            break;
        case TYPE_SOA:
            parsed_data = RecordSOA::parse( packet, p, p + data_length );
            break;
        case TYPE_OPT:
            parsed_data = RecordOptionsData::parse( packet, p, p + data_length );
            break;
        default:
	    std::ostringstream msg;
	    msg << "not support type \"" << sec.r_type << "\".";
            throw std::runtime_error( msg.str() );
        }
        p += data_length;

        sec.r_resource_data = parsed_data;
        return ResponseSectionEntryPair( sec, p );
    }


    std::ostream &print_header( std::ostream &os, const PacketInfo &packet )
    {
	os << "ID: "                   << packet.id                   << std::endl
	   << "Query/Response: "       << ( packet.query_response == 0 ? "Query" : "Response" ) << std::endl
	   << "OpCode:"                << packet.opcode               << std::endl
	   << "Authoritative Answwer:" << packet.authoritative_answer << std::endl
	   << "Truncation: "           << packet.truncation           << std::endl
	   << "Recursion Desired: "    << packet.recursion_desired    << std::endl
	   << "Recursion Available: "  << packet.recursion_available  << std::endl
	   << "Checking Disabled: "    << packet.checking_disabled    << std::endl
	   << "Response Code: "        << response_code_to_string( packet.response_code ) << std::endl;

	return os;
    }

    std::string type_code_to_string( Type t )
    {
	std::string res;

	switch( t ) {
	case TYPE_A:
	    res = "A";
	    break;
	case TYPE_NS:
	    res = "NS";
	    break;
	case TYPE_CNAME:
	    res = "CNAME";
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

	if ( rcode < sizeof(rcode2str)/sizeof(char *) )
	    res = rcode2str[ rcode ];
	else
	    res = "n         available for assignment";

	return res;
    }

    std::ostream &operator<<( std::ostream &os, const QueryPacketInfo &query )
    {
	os << "ID: "                   << query.id        << std::endl
	   << "OpCode:"                << query.opcode    << std::endl
	   << "Query/Response: "       << "Query"         << std::endl
	   << "Recursion Desired: "    << query.recursion << std::endl;

	for ( std::vector<dns::QuestionSectionEntry>::const_iterator i = query.question.begin() ;
	      i != query.question.end() ; ++i )
	    os << "Query: " << i->q_domainname << " " << type_code_to_string( i->q_type ) << std::endl;

	return os;
    }


    std::ostream &operator<<( std::ostream &os, const ResponsePacketInfo &res )
    {
	os << "ID: "                   << res.id                   << std::endl
	   << "Query/Response: "       << "Response"               << std::endl
	   << "OpCode:"                << res.opcode               << std::endl
	   << "Authoritative Answwer:" << res.authoritative_answer << std::endl
	   << "Truncation: "           << res.truncation           << std::endl
	   << "Recursion Available: "  << res.recursion_available  << std::endl
	   << "Checking Disabled: "    << res.checking_disabled    << std::endl
	   << "Response Code: "        << response_code_to_string( res.response_code ) << std::endl;

	for ( std::vector<dns::QuestionSectionEntry>::const_iterator i = res.question.begin() ;
	      i != res.question.end() ; ++i )
	    os << "Query: " << i->q_domainname << " " << type_code_to_string( i->q_type ) << "  ?" << std::endl;
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.answer.begin() ;
	      i != res.answer.end() ; ++i ) {
	    std::cout << "Answer: "
		      << i->r_domainname                  << " "
		      << i->r_ttl                         << " "
		      << type_code_to_string( i->r_type ) << " "
		      << i->r_resource_data->toString()   << std::endl;
	}
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.authority.begin() ;
	      i != res.authority.end() ; ++i ) {
	    std::cout << "Authority: "
		      << i->r_ttl                         << " "
		      << type_code_to_string( i->r_type ) << " "
		      << i->r_resource_data->toString()   << std::endl;
	}
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.additional_infomation.begin() ;
	      i != res.additional_infomation.end() ; ++i ) {
	    std::cout << "Additional: "
		      << i->r_domainname                  << " "
		      << i->r_ttl                         << " "
		      << type_code_to_string( i->r_type ) << " "
		      << i->r_resource_data->toString()   << std::endl;
	}

	return os;
    }


    RecordA::RecordA( uint32_t addr )
        : sin_addr( addr )
    {}

    RecordA::RecordA( const std::string &addr )
    {
        in_addr a = convert_address_string_to_binary( addr );
        std::memcpy( &sin_addr, &a, sizeof(sin_addr) );
    }


    std::string RecordA::toString() const
    {
        char buf[256];
        std::snprintf( buf,
                       sizeof(buf),
                       "%d.%d.%d.%d",
                       *( reinterpret_cast<const uint8_t *>( &sin_addr )     ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 1 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 2 ),
                       *( reinterpret_cast<const uint8_t *>( &sin_addr ) + 3 ) );
        return std::string( buf );
    }


    PacketData RecordA::getPacket() const
    {
        PacketData packet( 4 );
        packet[0] = ( sin_addr >>  0 ) & 0xff;
        packet[1] = ( sin_addr >>  8 ) & 0xff;
        packet[2] = ( sin_addr >> 16 ) & 0xff;
        packet[3] = ( sin_addr >> 24 ) & 0xff;

        return packet;
    }


    ResourceDataPtr RecordA::parse( const uint8_t *begin, const uint8_t*end )
    {
        return ResourceDataPtr( new RecordA( *( reinterpret_cast<const uint32_t *>( begin ) ) ) );
    }


    RecordAAAA::RecordAAAA( const uint8_t *addr )
    {
        std::memcpy( sin_addr, addr, 32 );
    }

    std::string RecordAAAA::toString() const
    {
        std::stringstream buff;
        buff << std::hex << (uint32_t)sin_addr[0];
        for ( unsigned int i = 1 ; i < sizeof(sin_addr) ; i++ ) {
            buff << ":" << (uint32_t)sin_addr[i];
        }
        return buff.str();
    }


    PacketData RecordAAAA::getPacket() const
    {
        return std::vector< uint8_t >( sin_addr,
				       sin_addr + sizeof( sin_addr ) );
    }


    ResourceDataPtr RecordAAAA::parse( const uint8_t *begin, const uint8_t*end )
    {
        return ResourceDataPtr( new RecordAAAA( begin ) );
    }


    RecordNS::RecordNS( const std::string &name )
        : domainname( name )
    {}

    std::string RecordNS::toString() const
    {
        return domainname;
    }


    PacketData RecordNS::getPacket() const
    {
        return convert_domainname_string_to_binary( domainname );
    }


    ResourceDataPtr RecordNS::parse( const uint8_t *packet,
                                     const uint8_t *begin,
                                     const uint8_t *end )
    {
        std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet, begin );
        return ResourceDataPtr( new RecordNS( pair.first ) );
    }


    RecordMX::RecordMX( uint16_t pri, const std::string &name )
        : priority( pri ), domainname( name )
    {}

    std::string RecordMX::toString() const
    {
	std::ostringstream os;
	os << priority << " " << domainname;
        return os.str();
    }


    PacketData RecordMX::getPacket() const
    {
	PacketData packet;
	packet.resize( 2 );
	*( reinterpret_cast<uint16_t *>( &packet[0] ) ) = htons( priority );
	PacketData name = convert_domainname_string_to_binary( domainname );
	packet.insert( packet.end(), name.begin(), name.end() );
	return packet;
    }


    ResourceDataPtr RecordMX::parse( const uint8_t *packet,
				     const uint8_t *begin,
				     const uint8_t *end )
    {
	if ( end - begin < 3 )
	    throw FormatError( "too few length for MX record," );
	const uint8_t *pos = begin;
	uint16_t priority = get_bytes<uint16_t>( &pos );
        std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet, pos );
        return ResourceDataPtr( new RecordMX( priority, pair.first ) );
    }


    RecordTXT::RecordTXT( const std::string &d )
        : data( d )
    {}

    std::string RecordTXT::toString() const
    {
        return data;
    }


    PacketData RecordTXT::getPacket() const
    {
	PacketData d;
	for ( std::string::const_iterator i = data.begin() ; i != data.end() ; ++i )
	    d.push_back( *i );
        return d;
    }


    ResourceDataPtr RecordTXT::parse( const uint8_t *packet,
				      const uint8_t *begin,
				      const uint8_t *end )
    {
	for ( const uint8_t *p = begin ; p != end ; p++ )
	    std::cerr << "\"" << *p << "\"";
	std::cerr << std::endl << (int)( end - begin ) << std::endl;
	if ( end - begin < 4 )
	    throw FormatError( "too few length for TXT record" );
	const uint8_t *pos = begin;
	uint16_t length = ntohs( get_bytes<uint16_t>( &pos ) );
	std::cerr << std::endl << length << std::endl;
	if ( end - begin != 2 + length )
	    throw FormatError( "txt length + 2 dose not equal to rdlength" );

        return ResourceDataPtr( new RecordTXT( std::string( pos, end ) ) );
    }

    RecordCNAME::RecordCNAME( const std::string &name )
        : domainname( name )
    {}

    std::string RecordCNAME::toString() const
    {
        return domainname;
    }


    PacketData RecordCNAME::getPacket() const
    {
        return convert_domainname_string_to_binary( domainname );
    }


    ResourceDataPtr RecordCNAME::parse( const uint8_t *packet,
					const uint8_t *begin,
					const uint8_t *end )
    {
        std::pair<std::string, const uint8_t *> pair = convert_domainname_binary_to_string( packet, begin );
        return ResourceDataPtr( new RecordCNAME( pair.first ) );
    }

    RecordSOA::RecordSOA( const std::string &mn,
			  const std::string &rn,
			  uint32_t sr,
			  uint32_t rf,
			  uint32_t rt,
			  uint32_t ex,
			  uint32_t min )
        : mname( mn ), rname( rn ), serial( sr ), refresh( rf ), retry( rt ), expire( ex ), minimum( min )
    {}


    std::string RecordSOA::toString() const
    {
        std::ostringstream soa_str;
        soa_str << mname   << " "
                << rname   << " "
                << serial  << " "
                << refresh << " "
                << retry   << " "
                << expire  << " "
                << minimum;
        return soa_str.str();
    }


    PacketData RecordSOA::getPacket() const
    {
	PacketData packet;
	std::insert_iterator<PacketData> pos( packet, packet.begin() );

        PacketData mname_packet = convert_domainname_string_to_binary( mname );
        PacketData rname_packet = convert_domainname_string_to_binary( rname );
	pos = std::copy( mname_packet.begin(), mname_packet.end(), pos );
	pos = std::copy( rname_packet.begin(), rname_packet.end(), pos );
	SOAField soa_param;
	soa_param.serial  = htonl( serial );
	soa_param.refresh = htonl( refresh );
	soa_param.retry   = htonl( retry );
	soa_param.expire  = htonl( expire );
	soa_param.minimum = htonl( minimum );

	pos = std::copy( reinterpret_cast<uint8_t *>( &soa_param ),
			 reinterpret_cast<uint8_t *>( &soa_param ) + sizeof( soa_param ),
			 pos );

        return packet;
    }


    ResourceDataPtr RecordSOA::parse( const uint8_t *packet,
                                      const uint8_t *begin,
                                      const uint8_t *end )
    {
        std::pair<std::string, const uint8_t *> mname_pair = convert_domainname_binary_to_string( packet, begin );
        std::pair<std::string, const uint8_t *> rname_pair = convert_domainname_binary_to_string( packet, mname_pair.second );
        const uint8_t *p = rname_pair.second;
        uint32_t serial  = ntohl( get_bytes<uint32_t>( &p ) );
        uint32_t refresh = ntohl( get_bytes<uint32_t>( &p ) );
        uint32_t retry   = ntohl( get_bytes<uint32_t>( &p ) );
        uint32_t expire  = ntohl( get_bytes<uint32_t>( &p ) );
        uint32_t minimum = ntohl( get_bytes<uint32_t>( &p ) );

        return ResourceDataPtr( new RecordSOA( mname_pair.first,
                                               rname_pair.first,
                                               serial,
                                               refresh,
                                               retry,
                                               expire,
                                               minimum ) );
    }
 
    std::string RecordOptionsData::toString() const
    {
	std::ostringstream os;

	for ( std::vector<OptPseudoRROptPtr>::const_iterator i = options.begin(); i != options.end() ; ++i )
	    os << (*i)->toString();
    
	return os.str();
    }


    PacketData RecordOptionsData::getPacket() const
    {
	PacketData packet;
	
	std::insert_iterator<PacketData> pos( packet, packet.begin() );

	for ( std::vector<OptPseudoRROptPtr>::const_iterator i = options.begin();
	      i != options.end() ;
	      ++i ) {
	    PacketData opt_data = (*i)->getPacket();
	    pos = std::copy( opt_data.begin(), opt_data.end(), pos );
	}

	return packet;
    }

    ResourceDataPtr RecordOptionsData::parse( const uint8_t *packet,
					      const uint8_t *begin,
					      const uint8_t *end )
    {
	if ( end - begin < 2 ) {
	    std::ostringstream os;
	    os << "size " << end - begin << " is too few Opt Pseudo RR size.";
	    throw FormatError( os.str() );
	}
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
	entry.r_ttl           = ((uint32_t)opt.rcode) << 24;
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
	opt.record_options_data = record.r_resource_data;

	return opt;
    }


    PacketData NSIDOption::getPacket() const
    {
	PacketData result;
	result.resize( 2 + 2 + nsid.size() );
	uint8_t *pos = &result[0];

	pos = set_bytes<uint16_t>( htons( OPT_NSID ),    pos );
	pos = set_bytes<uint16_t>( htons( nsid.size() ), pos );
	pos = std::copy( nsid.begin(), nsid.end(), pos );

	return result;
    }

    OptPseudoRROptPtr NSIDOption::parse( const uint8_t *begin, const uint8_t *end )
    {
	std::string nsid( begin, end );
	return OptPseudoRROptPtr( new NSIDOption( nsid ) );
    }


    uint16_t RecordTKey::size() const
    {
	PacketData domain_data = convert_domainname_string_to_binary( domain );

	return domain_data.size() + 
	    2 + // TYPE
	    2 + // CLASS
	    4 + // TTL
	    2 + // RDLEN
	    getResourceDataSize(); // ResourceData
    }

    uint16_t RecordTKey::getResourceDataSize() const
    {
	PacketData algorithm_data = convert_domainname_string_to_binary( algorithm );

	return algorithm_data.size() + //
	    4 + // inception
	    4 + // expiration
	    2 + // mode
	    2 + // error
	    2 + // key size
	    key.size() + // key
	    2 + // other data size
	    other_data.size();
    }

    PacketData RecordTKey::getPacket() const
    {
	PacketData packet;
	packet.resize( size() );

	PacketData domain_data    = convert_domainname_string_to_binary( domain );
	PacketData algorithm_data = convert_domainname_string_to_binary( algorithm );

	uint8_t *pos = &packet[0];
	pos = std::copy( domain_data.begin(), domain_data.end(), pos );
	pos = set_bytes<uint16_t>( htons( TYPE_TKEY ),  pos );
	pos = set_bytes<uint16_t>( htons( 1 ),          pos );
	pos = set_bytes<uint32_t>( 0,                   pos );
	pos = set_bytes<uint16_t>( htons( getResourceDataSize() ), pos );
	pos = std::copy( algorithm_data.begin(), algorithm_data.end(), pos );
	pos = set_bytes<uint32_t>( htonl( inception ),  pos );
	pos = set_bytes<uint32_t>( htonl( expiration ), pos );
	pos = set_bytes<uint16_t>( htons( mode ),       pos );
	pos = set_bytes<uint16_t>( htons( error ),      pos );
	pos = set_bytes<uint16_t>( htons( key.size() ), pos );
	pos = std::copy( key.begin(), key.end(), pos );
	pos = set_bytes<uint16_t>( htons( other_data.size() ), pos );
	pos = std::copy( other_data.begin(), other_data.end(), pos );

	return packet;
    }

}

