#include "dns_server.hpp"
#include <boost/program_options.hpp>


const int   TTL          = 600;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.33.1";
const char *BIND_ADDRESS = "192.168.33.1";

class TC1Server : public dns::DNSServer
{
public:
    TC1Server( const std::string addr, uint16_t port )
	: dns::DNSServer( addr, port )
    {}

    dns::ResponseInfo generateResponse( const dns::QueryPacketInfo &query )
    {
	dns::ResponseInfo response;
	dns::QuestionSectionEntry query_question = query.question[0];

	dns::QuestionSectionEntry question;
	question.q_domainname = query_question.q_domainname;
	question.q_type       = query_question.q_type;
	question.q_class      = query_question.q_class;
	response.question_section.push_back( question );

	dns::ResponseSectionEntry answer;
	answer.r_domainname    = query_question.q_domainname;
	answer.r_type          = dns::TYPE_A;
	answer.r_class         = dns::CLASS_IN;
	answer.r_ttl           = TTL;
	answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
	response.answer_section.push_back( answer );
  
	response.header.id                   = htons( query.id );
	response.header.opcode               = 0;
	response.header.query_response       = 1;
	response.header.authoritative_answer = 1;
	response.header.truncation           = 1;
	response.header.recursion_desired    = 0;
	response.header.recursion_available  = 0;
	response.header.zero_field           = 0;
	response.header.authentic_data       = 1;
	response.header.checking_disabled    = 1;
	response.header.response_code        = dns::NO_ERROR;

	return response;
    }
};


int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    int         case_id;

    po::options_description desc("TC=1 Server");
    desc.add_options()
        ("help,h",
         "print this message")

        ("bind,b",
         po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ),
         "bind address")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    TC1Server server( bind_address, 53 );
    server.start();

    return 0;
}
