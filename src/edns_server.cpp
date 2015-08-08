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


PacketData generate_response( uint16_t id, const dns::QuestionSectionEntry query )
{
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = query.q_domainname;
    question.q_type       = query.q_type;
    question.q_class      = query.q_class;
    question_section.push_back( question );

    dns::ResponseSectionEntry answer;
    answer.r_domainname = query.q_domainname;
    answer.r_type       = dns::TYPE_A;
    answer.r_class      = dns::CLASS_IN;
    answer.r_ttl        = 30;
    answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
    answer_section.push_back( answer );

    dns::ResponseSectionEntry authority;
    authority.r_domainname = query.q_domainname;
    authority.r_type       = dns::TYPE_SOA;
    authority.r_class      = dns::CLASS_IN;
    authority.r_ttl        = 30;
    authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordSOA( query.q_domainname,
									  "hostmaster." + question.q_domainname,
									  1,      // serial
									  300,    // refresh
									  1000,   // retry
									  10000,  // exipire
									  30 ) ); // minimum
    authority_section.push_back( authority );

    std::vector<dns::OptPseudoRROptPtr> edns_options_1, edns_options_2;
    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "aaaaaaaaaaaaa" ) ) );
    edns_options_2.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "bbbbbbbbb" ) ) );

    dns::OptPseudoRecord opt_rr_1, opt_rr_2;
    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
    opt_rr_1.payload_size = 1024;
    opt_rr_2.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_2 ) ); 
    opt_rr_2.payload_size = 1024;
    additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
    additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_2 ) );

    dns::PacketHeaderField header;
    header.id                   = id;
    header.opcode               = 0;
    header.query_response       = 1;
    header.authoritative_answer = 1;
    header.truncation           = 0;
    header.recursion_desired    = 0;
    header.recursion_available  = 0;
    header.zero_field           = 0;
    header.authentic_data       = 1;
    header.checking_disabled    = 1;
    header.response_code        = dns::NO_ERROR;

    return dns::generate_dns_packet( header,
				     question_section,
				     answer_section,
				     authority_section,
				     additional_infomation_section );
}


int main( int arc, char **argv )
{
    try {
	udpv4::ServerParameters param;
	param.bind_address = BIND_ADDRESS;
	param.bind_port    = 53;

	udpv4::ServerParameters server_params;
	server_params.bind_address = "192.168.33.1";
	server_params.bind_port    = 53;
	udpv4::Server dns_receiver( server_params );

	while( true ) {
	    udpv4::PacketInfo recv_data;
	    PacketData response_packet;
	    dns::QueryPacketInfo query;

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
		response_packet = generate_response( query.id, query.question[0] );
	    }
	    catch( std::bad_cast &e ) {
		std::cerr << "make response failed," << std::endl;
		std::exit(1 );
	    }

	    try {
		udpv4::ClientParameters client;
		client.destination_address = recv_data.source_address;
		client.destination_port    = recv_data.source_port;

		dns_receiver.sendPacket( client, response_packet );
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
