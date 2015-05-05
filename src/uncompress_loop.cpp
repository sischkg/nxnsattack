#include "dns.hpp"
#include "utils.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <arpa/inet.h>
#include <unistd.h>
#include <boost/numeric/conversion/cast.hpp>
#include "udpv4client.hpp"
#include "tcpv4client.hpp"
#include "dns.hpp"
#include <iostream>
#include <algorithm>
#include <iterator>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
//const char *DNS_SERVER_ADDRESS = "172.16.253.81";
const int QNAME_SIZE = 1400;

std::vector<boost::uint8_t> gen_dns_query_packet( const dns::QueryPacketInfo &query );
std::vector<boost::uint8_t> convert_domainname_string_to_binary();
std::vector<boost::uint8_t> gen_question_section( const dns::QuestionSectionEntry &question );

std::vector<boost::uint8_t> gen_dns_query_packet( const dns::QueryPacketInfo &query )
{
    dns::PacketHeaderField header;
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

    header.question_count              = htons( query.question.size() );
    header.answer_count                = htons( 0 );
    header.authority_count             = htons( 0 );
    header.additional_infomation_count = htons( 0 );

    std::vector<boost::uint8_t> packet;
    std::copy( (boost::uint8_t *)&header, (boost::uint8_t *)&header + sizeof(header), std::back_inserter( packet ) );

    for( std::vector<dns::QuestionSectionEntry>::const_iterator i = query.question.begin() ;
	 i != query.question.end() ; ++i ) {
	std::vector<boost::uint8_t> question = gen_question_section( *i );
	std::copy( question.begin(), question.end(), std::back_inserter( packet ) );
    }

    return packet;
}

std::vector<boost::uint8_t> convert_domainname_string_to_binary( const std::string &domainname, uint16_t reference_offset )
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
	if ( reference_offset != 0xffff ) {
	    bin.push_back( 0xC0 | ( reference_offset >> 8 ) );  
	    bin.push_back( 0xff & reference_offset );  
	}
	else {
	    bin.push_back( 0 );
	}
    }

    return bin;
}

boost::uint8_t *append_label( const char *label, boost::uint8_t *buf )
{
    boost::uint8_t *pos = buf;
    int label_length = std::strlen( label );
    *pos = label_length;
    pos++;
    std::copy( label, label + label_length, buf );
    pos += label_length;

    return pos;
}


std::vector<boost::uint8_t> gen_question_section( const dns::QuestionSectionEntry &question )
{
    std::vector<boost::uint8_t> packet = convert_domainname_string_to_binary( question.q_domainname, question.q_offset );
    packet.resize( packet.size() + sizeof(boost::uint16_t) + sizeof(boost::uint16_t) );
    boost::uint8_t *p = packet.data() + packet.size() - sizeof(boost::uint16_t) - sizeof(boost::uint16_t);
    p = dns::set_bytes<boost::uint16_t>( htons( question.q_type ),  p );
    p = dns::set_bytes<boost::uint16_t>( htons( question.q_class ), p );

    return packet;
}


int main()
{
    std::string qname;

    for ( int i = 0 ; i < 30000 ; i++ ) {
	qname += "1.";
    }
    qname += "siskrn.co";

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = true;

    /*
    dns::QuestionSectionEntry question;
    question.q_domainname = qname;
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;
    //    question.q_offset     = sizeof(dns::PacketHeaderField);
    question.q_offset     = 0xffff;
    query.question.push_back( question );
    */
    const char label[] = "www.siskrn.co";

    dns::QuestionSectionEntry question;
    question.q_domainname = label;
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;
    question.q_offset     = 0xffff;
    query.question.push_back( question );

    question.q_domainname = label;
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;
    question.q_offset     = sizeof(dns::PacketHeaderField);
    query.question.push_back( question );

    for ( int i = 0 ; i < 5 ; i++ ) {
	question.q_domainname = label;
	question.q_type       = dns::TYPE_A;
	question.q_class      = dns::CLASS_IN;
	question.q_offset     = sizeof(dns::PacketHeaderField) + strlen(label) + 6 + ( std::strlen(label) + 7 ) * i;
	query.question.push_back( question );
    }

    std::vector<boost::uint8_t> dns_query_packet = gen_dns_query_packet( query );

    tcpv4::ClientParameters tcp_param;
    tcp_param.destination_address = DNS_SERVER_ADDRESS;
    tcp_param.destination_port    = 53;
    tcpv4::Client tcp( tcp_param );
    boost::uint16_t data_size = htons( boost::numeric_cast<boost::uint16_t>( dns_query_packet.size() ) );
    tcp.send( reinterpret_cast<boost::uint8_t *>(&data_size), 2 );
    tcp.send( dns_query_packet.data(), dns_query_packet.size() );

    tcpv4::PacketInfo received_packet = tcp.receive();
    std::cerr << received_packet.end() - received_packet.begin() << std::endl;
    tcp.closeSocket();
    return 0;
    /*
    udpv4::ClientParameters udp_param;
    udp_param.destination_address = DNS_SERVER_ADDRESS;
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( dns_query_packet.data(), dns_query_packet.size() );

    udpv4::PacketInfo received_packet = udp.receivePacket();
    */
    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin() + 2,
                                                                  received_packet.end() );
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
}

