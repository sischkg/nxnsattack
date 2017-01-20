#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iostream>

const int   TTL          = 600;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.33.1";
const char *BIND_ADDRESS = "192.168.33.1";

class TC1Server : public dns::DNSServer
{
public:
    TC1Server( const std::string addr, uint16_t port ) : dns::DNSServer( addr, port )
    {
    }

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
	if ( via_tcp ) {
	    dns::PacketInfo           response;
	    dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

	    std::string qname = "a";
	    for ( int i = 0 ; i < 15000 ; i++ ) 
		qname += ".a";

	    dns::QuestionSectionEntry question1;
	    question1.q_domainname = qname;
	    question1.q_type       = dns::TYPE_A;
	    question1.q_class      = dns::CLASS_IN;
	    response.question_section.push_back( question1 );

	    for ( unsigned int i = 0 ; i < 5000 ; i++ ) {
		dns::QuestionSectionEntry question2;
		question2.q_domainname = "a";
		question2.q_type       = dns::TYPE_A;
		question2.q_class      = dns::CLASS_IN;
		question2.q_offset     = sizeof(dns::PacketHeaderField);
		response.question_section.push_back( question2 );
	    }

	    response.id                   = query.id;
	    response.opcode               = 0;
	    response.query_response       = 1;
	    response.authoritative_answer = 1;
	    response.truncation           = 1;
	    response.recursion_desired    = 0;
	    response.recursion_available  = 0;
	    response.zero_field           = 0;
	    response.authentic_data       = 1;
	    response.checking_disabled    = 1;
	    response.response_code        = dns::NO_ERROR;

	    return response;
	}
	else {
	    dns::PacketInfo           response;
	    dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

	    dns::QuestionSectionEntry question;
	    question.q_domainname = query_question.q_domainname;
	    question.q_type       = query_question.q_type;
	    question.q_class      = query_question.q_class;
	    response.question_section.push_back( question );
	
	    response.id                   = query.id;
	    response.opcode               = 0;
	    response.query_response       = 1;
	    response.authoritative_answer = 1;
	    response.truncation           = 1;
	    response.recursion_desired    = 0;
	    response.recursion_available  = 0;
	    response.zero_field           = 0;
	    response.authentic_data       = 1;
	    response.checking_disabled    = 1;
	    response.response_code        = dns::NO_ERROR;

	    return response;
	}
    }
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;

    po::options_description desc( "TC=1 Server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    TC1Server server( bind_address, 53 );
    server.start();

    return 0;
}
