#include "dns_server.hpp"
#include <iostream>
#include <boost/program_options.hpp>


const int   TTL          = 600;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.33.1";
const char *BIND_ADDRESS = "192.168.33.1";

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

        dns::ResponseSectionEntry answer;
        answer.r_domainname    = query_question.q_domainname;
        answer.r_type          = dns::TYPE_A;
        answer.r_class         = dns::CLASS_IN;
        answer.r_ttl           = TTL;
        answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
        response.answer_section.push_back( answer );

        std::vector<dns::OptPseudoRROptPtr> edns_options_1;
        edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "aaaaaaaaaaaaa" ) ) );

        dns::OptPseudoRecord opt_rr_1;
        opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
        opt_rr_1.payload_size = 1024;
        opt_rr_1.rcode        = 1;
        response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );

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

    BadVersServer server( bind_address, 53 );
    server.start();

    return 0;
}
