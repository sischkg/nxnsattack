#include "dns.hpp"
#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <arpa/inet.h>
#include <boost/numeric/conversion/cast.hpp>

namespace dns
{

    std::vector<boost::uint8_t> generate_dns_query_packet( const QueryPacketInfo &query )
    {
	PacketHeaderField header;
        header.id                   = htons( query.id );
	header.opcode               = 0;
        header.query_response       = 0;
        header.authoritative_answer = 0;
        header.truncation           = 0;
        header.recursion_desired    = query.recursion;
        header.recursion_available  = 0;
        header.zero_field           = 0;
        header.authentic_data       = 0;
        header.checking_disabled    = 0;
        header.response_code        = 0;

        header.question_count              = htons( 1 );
        header.answer_count                = htons( 0 );
        header.authority_count             = htons( 0 );
        header.additional_infomation_count = htons( 0 );

        std::vector<boost::uint8_t> packet;
        std::vector<boost::uint8_t> question = generate_question_section( query.question[0] );

        packet.resize( sizeof(header) + question.size() );
        std::memcpy( packet.data(), &header, sizeof(header) );
        std::memcpy( packet.data() + sizeof(header),
                     question.data(), question.size() );

        return packet;
    }


    std::vector<boost::uint8_t> generate_dns_response_packet( const ResponsePacketInfo &response )
    {
	PacketHeaderField header;
        header.id                   = htons( response.id );
	header.opcode               = 0;
        header.query_response       = 1;
        header.authoritative_answer = response.authoritative_answer;
        header.truncation           = response.truncation;
        header.recursion_desired    = 0;
        header.recursion_available  = response.recursion_available;
        header.zero_field           = 0;
        header.authentic_data       = 0;
        header.checking_disabled    = 0;
        header.response_code        = response.response_code;

        header.question_count              = htons( response.question.size() );
        header.answer_count                = htons( response.answer.size() );
        header.authority_count             = htons( response.authority.size() );
        header.additional_infomation_count = htons( response.additional_infomation.size() );

        std::vector<boost::uint8_t> packet;
        std::vector<boost::uint8_t> sections;
        for( std::vector<QuestionSectionEntry>::const_iterator q = response.question.begin() ;
             q != response.question.end() ; ++q ) {
            std::vector<boost::uint8_t> new_sections = generate_question_section( *q );
            sections.insert( sections.end(), new_sections.begin(), new_sections.end() );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator a = response.answer.begin() ;
             a != response.answer.end() ; ++a ) {
            std::vector<boost::uint8_t> new_sections = generate_response_section( *a );
            sections.insert( sections.end(), new_sections.begin(), new_sections.end() );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator a = response.authority.begin() ;
             a != response.authority.end() ; ++a ) {
            std::vector<boost::uint8_t> new_sections = generate_response_section( *a );
            sections.insert( sections.end(), new_sections.begin(), new_sections.end() );
        }
        for( std::vector<ResponseSectionEntry>::const_iterator a = response.additional_infomation.begin() ;
             a != response.additional_infomation.end() ; ++a ) {
            std::vector<boost::uint8_t> new_sections = generate_response_section( *a );
            sections.insert( sections.end(), new_sections.begin(), new_sections.end() );
        }

        packet.resize( sizeof(header) + sections.size() );
        std::memcpy( packet.data(), &header, sizeof(header) );
        std::memcpy( packet.data() + sizeof(header),
                     sections.data(), sections.size() );

        return packet;
    }


    QueryPacketInfo parse_dns_query_packet( const boost::uint8_t *begin, const boost::uint8_t *end )
    {
	const boost::uint8_t *packet = begin;
        QueryPacketInfo packet_info;
        const PacketHeaderField *header = reinterpret_cast<const PacketHeaderField *>( packet );

        packet_info.id        = ntohs( header->id );
        packet_info.recursion = header->recursion_desired;

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
        return packet_info;
    }


    ResponsePacketInfo parse_dns_response_packet( const boost::uint8_t *begin, const boost::uint8_t *end )
    {
        const boost::uint8_t *packet = begin;

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


    std::vector<boost::uint8_t> convert_domainname_string_to_binary( const std::string &domainname )
    {
        std::vector<boost::uint8_t> bin;
        std::vector<boost::uint8_t> label;

        for( std::string::const_iterator i = domainname.begin() ; i != domainname.end() ; ++i ) {
            if ( *i == '.' ) {
                if ( label.size() != 0 ) {
                    bin.push_back( boost::numeric_cast<boost::uint8_t>( label.size() ) );
                    bin.insert( bin.end(), label.begin(), label.end() );
                    label.clear();
                }
            }
            else {
                label.push_back( boost::numeric_cast<boost::uint8_t>( *i ) );
            }
        }
        if ( ! label.empty() ) {
            bin.push_back( boost::numeric_cast<boost::uint8_t>( label.size() ) );
            bin.insert( bin.end(), label.begin(), label.end() );
            bin.push_back( 0 );
        }

        return bin;
    }


    std::pair<std::string, const boost::uint8_t *> convert_domainname_binary_to_string( const boost::uint8_t *packet,
                                                                                        const boost::uint8_t *p )
    {
        std::string domainname;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                int offset = ntohs( *( reinterpret_cast<const boost::uint16_t *>( p ) ) ) & 0x03ff;
                std::pair<std::string, const boost::uint8_t *> pair = convert_domainname_binary_to_string( packet,
                                                                                                           packet + offset );
                return std::pair<std::string, const boost::uint8_t *>( domainname + pair.first, p + 2 );
            }

            boost::uint8_t label_length = *p;
            p++;
            for ( boost::uint8_t i = 0 ; i < label_length ; i++, p++ ) {
                domainname.push_back( *p );
            }
            domainname.push_back( '.' );
        }
        if ( domainname != "" )
            domainname.resize( domainname.size() - 1 );

        p++;
        return std::pair<std::string, const boost::uint8_t *>( domainname, p );
    }

    std::vector<boost::uint8_t> generate_question_section( const QuestionSectionEntry &question )
    {
        std::vector<boost::uint8_t> packet = convert_domainname_string_to_binary( question.q_domainname );
        packet.resize( packet.size() + sizeof(boost::uint16_t) + sizeof(boost::uint16_t) );
        boost::uint8_t *p = packet.data() + packet.size() - sizeof(boost::uint16_t) - sizeof(boost::uint16_t);
        p = dns::set_bytes<boost::uint16_t>( htons( question.q_type ),  p );
        p = dns::set_bytes<boost::uint16_t>( htons( question.q_class ), p );

        return packet;
    }

    QuestionSectionEntryPair parse_question_section( const boost::uint8_t *packet, const boost::uint8_t *p )
    {
        std::pair<std::string, const boost::uint8_t *> pair = convert_domainname_binary_to_string( packet, p );
        p = pair.second;

        QuestionSectionEntry sec;
        sec.q_domainname = pair.first;
        sec.q_type  = get_bytes<boost::uint16_t>( &p );
        sec.q_class = get_bytes<boost::uint16_t>( &p );

        return QuestionSectionEntryPair( sec, p );
    }


    std::vector<boost::uint8_t> generate_response_section( const ResponseSectionEntry &response )
    {
        std::vector<boost::uint8_t> packet_name = convert_domainname_string_to_binary( response.r_domainname );
        std::vector<boost::uint8_t> packet_rd   = response.r_resource_data->getPacket();
        std::vector<boost::uint8_t> packet( packet_name.size() +
                                            sizeof(uint16_t) +
                                            sizeof(uint16_t) +
                                            sizeof(uint32_t) +
                                            sizeof(uint16_t) +
                                            packet_rd.size() );
        boost::uint8_t *p = packet.data();

        std::memcpy( p, packet_name.data(), packet_name.size() ); p += packet_name.size();

        p = dns::set_bytes<boost::uint16_t>( htons( response.r_type ),  p );
        p = dns::set_bytes<boost::uint16_t>( htons( response.r_class ), p );
        p = dns::set_bytes<boost::uint32_t>( htonl( response.r_ttl ),   p );
        p = dns::set_bytes<boost::uint16_t>( htons( packet_rd.size() ), p );

        std::memcpy( p, packet_rd.data(), packet_rd.size() );

        return packet;
    }

    ResponseSectionEntryPair parse_response_section( const boost::uint8_t *packet, const boost::uint8_t *p )
    {
        std::pair<std::string, const boost::uint8_t *> pair = convert_domainname_binary_to_string( packet, p );
        p = pair.second;

        ResponseSectionEntry sec;
        sec.r_domainname     = pair.first;
        sec.r_type           = ntohs( get_bytes<boost::uint16_t>( &p ) );
        sec.r_class          = ntohs( get_bytes<boost::uint16_t>( &p ) );
        sec.r_ttl            = ntohl( get_bytes<boost::uint32_t>( &p ) );
        uint16_t data_length = ntohs( get_bytes<boost::uint16_t>( &p ) );

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
        case TYPE_SOA:
            parsed_data = RecordSOA::parse( packet, p, p + data_length );
            break;
        default:
            std::ostringstream msg;
            msg << "not suppert type \"" << sec.r_type << "\".";
            throw std::runtime_error( msg.str() );
        }
        p += data_length;

        sec.r_resource_data = parsed_data;
        return ResponseSectionEntryPair( sec, p );
    }


    std::ostream &operator<<( std::ostream &os, const QueryPacketInfo &res )
    {
	std::cout << "ID: " << res.id << std::endl;
	for ( std::vector<dns::QuestionSectionEntry>::const_iterator i = res.question.begin() ;
	      i != res.question.end() ; ++i )
	    std::cout << "Query: " << i->q_domainname << std::endl;

	return os;
    }


    std::ostream &operator<<( std::ostream &os, const ResponsePacketInfo &res )
    {
	std::cout << "ID: " << res.id << std::endl;
	for ( std::vector<dns::QuestionSectionEntry>::const_iterator i = res.question.begin() ;
	      i != res.question.end() ; ++i )
	    std::cout << "Query: " << i->q_domainname << std::endl;
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.answer.begin() ;
	      i != res.answer.end() ; ++i ) {
	    std::cout << "Answer: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
	}
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.authority.begin() ;
	      i != res.authority.end() ; ++i ) {
	    std::cout << "Authority: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
	}
	for ( std::vector<dns::ResponseSectionEntry>::const_iterator i = res.additional_infomation.begin() ;
	      i != res.additional_infomation.end() ; ++i ) {
	    std::cout << "Additional: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
	}

	return os;
    }


    RecordA::RecordA( boost::uint32_t addr )
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


    std::vector<boost::uint8_t> RecordA::getPacket() const
    {
        std::vector<boost::uint8_t> packet( 4 );
        packet[0] = ( sin_addr >>  0 ) & 0xff;
        packet[1] = ( sin_addr >>  8 ) & 0xff;
        packet[2] = ( sin_addr >> 16 ) & 0xff;
        packet[3] = ( sin_addr >> 24 ) & 0xff;

        return packet;
    }


    ResourceDataPtr RecordA::parse( const boost::uint8_t *begin, const boost::uint8_t*end )
    {
        return ResourceDataPtr( new RecordA( *( reinterpret_cast<const uint32_t *>( begin ) ) ) );
    }


    RecordAAAA::RecordAAAA( const boost::uint8_t *addr )
    {
        std::memcpy( sin_addr, addr, sizeof(addr) );
    }

    std::string RecordAAAA::toString() const
    {
        std::stringstream buff;
        buff << std::hex << sin_addr[0];
        for ( int i = 1 ; i < sizeof(sin_addr) ; i++ ) {
            buff << ":" << sin_addr[i];
        }
        return buff.str();
    }


    std::vector<boost::uint8_t> RecordAAAA::getPacket() const
    {
        return std::vector< boost::uint8_t >( sin_addr,
                                              sin_addr + sizeof( sin_addr ) );
    }


    ResourceDataPtr RecordAAAA::parse( const boost::uint8_t *begin, const boost::uint8_t*end )
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


    std::vector<boost::uint8_t> RecordNS::getPacket() const
    {
        return convert_domainname_string_to_binary( domainname );
    }


    ResourceDataPtr RecordNS::parse( const boost::uint8_t *packet,
                                     const boost::uint8_t *begin,
                                     const boost::uint8_t *end )
    {
        std::pair<std::string, const boost::uint8_t *> pair = convert_domainname_binary_to_string( packet, begin );
        return ResourceDataPtr( new RecordNS( pair.first ) );
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


    std::vector<boost::uint8_t> RecordSOA::getPacket() const
    {
        std::vector<boost::uint8_t> packet       = convert_domainname_string_to_binary( mname );
        std::vector<boost::uint8_t> rname_packet = convert_domainname_string_to_binary( rname );
        packet.insert( packet.end(), rname_packet.begin(), rname_packet.end() );
        packet.resize( packet.size() + sizeof(SOAField) );
        uint8_t *p = packet.data();
        p = dns::set_bytes<boost::uint32_t>( htonl( serial ),  p );
        p = dns::set_bytes<boost::uint32_t>( htonl( refresh ), p );
        p = dns::set_bytes<boost::uint32_t>( htonl( retry ),   p );
        p = dns::set_bytes<boost::uint32_t>( htonl( expire ),  p );
        p = dns::set_bytes<boost::uint32_t>( htonl( minimum ), p );

        return packet;
    }


    ResourceDataPtr RecordSOA::parse( const boost::uint8_t *packet,
                                      const boost::uint8_t *begin,
                                      const boost::uint8_t *end )
    {
        std::pair<std::string, const boost::uint8_t *> mname_pair = convert_domainname_binary_to_string( packet, begin );
        std::pair<std::string, const boost::uint8_t *> rname_pair = convert_domainname_binary_to_string( packet, mname_pair.second );
        const uint8_t *p = rname_pair.second;
        uint32_t serial  = htonl( get_bytes<boost::uint32_t>( &p ) );
        uint32_t refresh = htonl( get_bytes<boost::uint32_t>( &p ) );
        uint32_t retry   = htonl( get_bytes<boost::uint32_t>( &p ) );
        uint32_t expire  = htonl( get_bytes<boost::uint32_t>( &p ) );
        uint32_t minimum = htonl( get_bytes<boost::uint32_t>( &p ) );

        return ResourceDataPtr( new RecordSOA( mname_pair.first,
                                               rname_pair.first,
                                               serial,
                                               refresh,
                                               retry,
                                               expire,
                                               minimum ) );
    }

}

