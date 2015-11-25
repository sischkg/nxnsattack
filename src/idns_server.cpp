#include "udpv4server.hpp"
#include "dns.hpp"
#include <string>
#include <stdexcept>
#include <iostream>

const char *MY_ADDRESS      = "192.168.33.1";
const char *MY_DOMAIN       = "example.com";
const char *BIND_ADDRESS    = "192.168.33.1";
const int   TTL             = 600;
const int   NS_RECORD_COUNT = 8;
const int   SUBDOMAIN_SIZE  = 30;
const int   BUF_SIZE        = 256 * 256;

std::string generate_domainname()
{
    std::string subdomain;
    //    subdomain.resize( SUBDOMAIN_SIZE );
    for ( int i = 0 ; i < SUBDOMAIN_SIZE ; i++ ) {
	subdomain.push_back( 'a' + (char)(std::rand()%26) );
	subdomain.push_back( '.' );
    }
    return "ns." + subdomain + MY_DOMAIN;
}


dns::ResponsePacketInfo generate_response( uint16_t id, const dns::QuestionSectionEntry question_section )
{
    dns::ResponsePacketInfo response;
    response.id = id;
    response.recursion_available = false;
    response.truncation          = false;
    response.authentic_data      = false;
    response.checking_disabled   = false;
    response.response_code       = dns::NO_ERROR;

    dns::QuestionSectionEntry question;
    question.q_domainname = question_section.q_domainname;
    question.q_class      = question_section.q_class;
    question.q_type       = question_section.q_type;
    response.question.push_back( question );

    for ( int i = 0 ; i < NS_RECORD_COUNT ; i++ ) {
	dns::ResponseSectionEntry response_section;
	response_section.r_domainname = question_section.q_domainname;
	response_section.r_class      = dns::CLASS_IN;
	response_section.r_type       = dns::TYPE_NS;
	response_section.r_ttl        = TTL;
	response_section.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( generate_domainname() ) );
	response.authority.push_back( response_section );
    }

    return response;
}


int main( int arc, char **argv )
{
    try {
	udpv4::ServerParameters param;
	param.bind_address = BIND_ADDRESS;
	param.bind_port    = 53;

	udpv4::Server dns_server( param );

	while( true ) {
	    udpv4::PacketInfo recv_data;
	    dns::QueryPacketInfo query;
	    dns::ResponsePacketInfo response;
	    std::vector<uint8_t> response_packet;
	    udpv4::ClientParameters client_info;

	    try {
		recv_data = dns_server.receivePacket();
		query = dns::parse_dns_query_packet( recv_data.begin(), recv_data.end() );
	    }
	    catch( std::bad_cast &e ) {
		std::cerr << "parse query failed," << std::endl;
		std::exit(1 );
	    }

	    try {
		response = generate_response( query.id, query.question[0] );
		response_packet = dns::generate_dns_response_packet( response );
	    }
	    catch( std::bad_cast &e ) {
		std::cerr << "make response failed," << std::endl;
		std::exit(1 );
	    }

	    try {
		client_info.destination_address = recv_data.source_address;
		client_info.destination_port    = recv_data.source_port;
		dns_server.sendPacket( client_info, response_packet );
	    }
	    catch( std::bad_cast &e ) {
		std::cerr << "send response failed," << std::endl;
		std::exit(1 );
	    }
	}
    }
    catch ( std::runtime_error &e ) {
	std::cerr << "caught " << e.what() << std::endl;
    }

    return 0;
}
