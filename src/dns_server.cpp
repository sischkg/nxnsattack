#include "udpv4server.hpp"
#include "dns.hpp"
#include <string>
#include <stdexcept>
#include <iostream>

const char *MY_ADDRESS      = "192.168.0.102";
const char *MY_DOMAIN       = "example.com";
const char *BIND_ADDRESS    = "192.168.0.1";
const int   TTL             = 600;
const int   NS_RECORD_COUNT = 2;
const int   SUBDOMAIN_SIZE  = 30;
const int   BUF_SIZE        = 256 * 256;


dns::ResponsePacketInfo generate_response( uint16_t id, const dns::QuestionSectionEntry question_section )
{
    dns::ResponsePacketInfo response;
    response.id = id;
    response.recursion_available = false;
    response.truncation          = false;
    response.authentic_data      = false;
    response.checking_disabled   = false;
    response.response_code       = dns::NXDOMAIN;

    dns::QuestionSectionEntry question;
    question.q_domainname = question_section.q_domainname;
    question.q_class      = dns::CLASS_IN;
    question.q_type       = dns::TYPE_A;
    response.question.push_back( question );

    return response;
}

struct BadChecksumCalculator : public udpv4::ChecksumCalculatable
{
    uint16_t operator()( const udpv4::PacketInfo & ) const
    {
	return 0;
    }
};


int main( int arc, char **argv )
{
    try {
	udpv4::ServerParameters param;
	param.bind_address = BIND_ADDRESS;
	param.bind_port    = 53;

	udpv4::Receiver dns_receiver( BIND_ADDRESS, 53 );
	udpv4::Sender   dns_sender( udpv4::Sender::ChecksumPtr( new udpv4::StandardChecksumCalculator ) );
	//	udpv4::Sender   dns_sender( udpv4::Sender::ChecksumPtr( new BadChecksumCalculator ) );

	while( true ) {
	    udpv4::PacketInfo recv_data, send_data;
	    dns::QueryPacketInfo query;
	    dns::ResponsePacketInfo response;
	    std::vector<uint8_t> response_packet;

	    try {
		recv_data = dns_receiver.receivePacket();
		query = dns::parse_dns_query_packet( recv_data.begin(), recv_data.end() );
		std::cerr << "received" << std::endl;
	    }
	    catch( std::bad_cast &e ) {
		std::cerr << "parse query failed," << std::endl;
		std::exit( 1 );
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
		send_data.destination_address = recv_data.source_address;
		send_data.destination_port    = recv_data.source_port;
		send_data.source_address      = MY_ADDRESS;
		send_data.source_port         = 53;
		dns_sender.sendPacket( send_data );
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
