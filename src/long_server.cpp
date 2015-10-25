#include "dns_server.hpp"
#include <boost/program_options.hpp>

const int   TTL          = 600;

class BadVersServer : public dns::DNSServer
{
public:
    BadVersServer( const std::string addr, uint16_t port )
	: dns::DNSServer( addr, port )
    {}

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
	dns::PacketInfo response;
	dns::QuestionSectionEntry query_question = query.question_section[0];

	dns::QuestionSectionEntry question;
	question.q_domainname = query_question.q_domainname;
	question.q_type       = query_question.q_type;
	question.q_class      = query_question.q_class;
	response.question_section.push_back( question );

	std::string cname;
	for ( int i = 0 ; i < 200 ; i++ ) {
	    cname += "a.";
	}
	cname += query_question.q_domainname;

	dns::ResponseSectionEntry answer1;
	answer1.r_domainname    = query_question.q_domainname;
	answer1.r_type          = dns::TYPE_CNAME;
	answer1.r_class         = dns::CLASS_IN;
	answer1.r_ttl           = 30;
	answer1.r_resource_data = dns::ResourceDataPtr( new dns::RecordCNAME( cname ) );
	response.answer_section.push_back( answer1 );

	dns::ResponseSectionEntry answer2;
	answer2.r_domainname    = cname;
	answer2.r_type          = dns::TYPE_A;
	answer2.r_class         = dns::CLASS_IN;
	answer2.r_ttl           = 30;
	answer2.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "172.16.0.1" ) );
	response.answer_section.push_back( answer2 );

  	response.id                   = query.id;
	response.opcode               = 0;
	response.query_response       = 1;
	response.authoritative_answer = 1;
	response.truncation           = 0;
	response.recursion_desired    = 0;
	response.recursion_available  = 0;
	response.zero_field           = 0;
	response.authentic_data       = 1;
	response.checking_disabled    = 1;
	response.response_code        = dns::NO_ERROR;

	return response;
    }
};


int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;

    po::options_description desc("EDNS0 BADVERS Server");
    desc.add_options()
        ("help,h",
         "print this message")

        ("bind,b",
         po::value<std::string>( &bind_address )->default_value( "192.168.33.1" ),
         "bind address")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    BadVersServer server( bind_address, 53 );
    server.start();

    return 0;
}
