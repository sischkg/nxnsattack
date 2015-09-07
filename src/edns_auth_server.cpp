#include "dns_server.hpp"
#include <boost/program_options.hpp>


const int   TTL          = 600;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.33.1";
const char *BIND_ADDRESS = "192.168.33.1";

class EDNS0AuthServer : public dns::DNSServer
{
private:
    int case_id;

public:
    EDNS0AuthServer( const std::string addr, uint16_t port, int id )
	: dns::DNSServer( addr, port ), case_id( id )
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

	if ( query_question.q_type == dns::TYPE_A && query_question.q_domainname == "www.example.com" ) {
	    dns::ResponseSectionEntry answer;
	    answer.r_domainname    = query_question.q_domainname;
	    answer.r_type          = dns::TYPE_A;
	    answer.r_class         = dns::CLASS_IN;
	    answer.r_ttl           = TTL;
	    answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
	    response.answer_section.push_back( answer );
	}
	else if ( query_question.q_type == dns::TYPE_A && query_question.q_domainname == "ns1.example.com" ) {
	    dns::ResponseSectionEntry answer;
	    answer.r_domainname    = query_question.q_domainname;
	    answer.r_type          = dns::TYPE_A;
	    answer.r_class         = dns::CLASS_IN;
	    answer.r_ttl           = TTL;
	    answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( MY_ADDRESS ) );
	    response.answer_section.push_back( answer );
	}

	dns::ResponseSectionEntry authority;
	authority.r_domainname    = "example.com";
	authority.r_type          = dns::TYPE_NS;
	authority.r_class         = dns::CLASS_IN;
	authority.r_ttl           = TTL;
	authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "ns1.example.com" ) );
	response.authority_section.push_back( authority );

	dns::ResponseSectionEntry additional;
	additional.r_domainname    = "ns1.example.com";
	additional.r_type          = dns::TYPE_A;
	additional.r_class         = dns::CLASS_IN;
	additional.r_ttl           = TTL;
	additional.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( MY_ADDRESS ) );
	response.additional_infomation_section.push_back( additional );

	if ( query_question.q_type == dns::TYPE_A && query_question.q_domainname == "www.example.com" ) {
	    switch ( case_id ) {
	    case 1:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1, edns_options_2;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test 1" ) ) );
		    edns_options_2.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test 2" ) ) );

		    dns::OptPseudoRecord opt_rr_1, opt_rr_2;
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size        = 1280;
		    opt_rr_1.rcode               = 0;
		    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		    opt_rr_2.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_2 ) ); 
		    opt_rr_2.payload_size        = 1280;
		    opt_rr_2.rcode               = 0;
		    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_2 ) );
		}
		break;
	    case 11:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1, edns_options_2;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test 1" ) ) );
		    edns_options_2.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test 2" ) ) );

		    dns::OptPseudoRecord opt_rr_1, opt_rr_2;
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size        = 1280;
		    opt_rr_1.rcode               = 0;
		    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		    opt_rr_2.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_2 ) ); 
		    opt_rr_2.payload_size        = 1500;
		    opt_rr_2.rcode               = 0;
		    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_2 ) );
		}
		break;
	    case 2:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test" ) ) );

		    dns::OptPseudoRecord opt_rr_1;
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size        = 1280;
		    opt_rr_1.rcode               = 0;
		    response.answer_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		}
		break;
	    case 3:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test" ) ) );

		    dns::OptPseudoRecord opt_rr_1;
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size        = 1280;
		    opt_rr_1.rcode               = 0;
		    response.authority_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		}
		break;
	    case 4:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test" ) ) );

		    dns::OptPseudoRecord opt_rr_1;
		    opt_rr_1.domainname          = "www.example.com";
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size        = 1280;
		    opt_rr_1.rcode               = 0;
		    response.authority_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		}
		break;
	    default:
		{
		    std::vector<dns::OptPseudoRROptPtr> edns_options_1;
		    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test" ) ) );

		    dns::OptPseudoRecord opt_rr_1;
		    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
		    opt_rr_1.payload_size = 1280;
		    opt_rr_1.rcode        = 0;
		    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
		}
	    }
	}
	else {
	    std::vector<dns::OptPseudoRROptPtr> edns_options_1;
	    edns_options_1.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( "edns0 test" ) ) );

	    dns::OptPseudoRecord opt_rr_1;
	    opt_rr_1.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( edns_options_1 ) ); 
	    opt_rr_1.payload_size = 1280;
	    opt_rr_1.rcode        = 0;
	    response.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt_rr_1 ) );
	}

	response.header.id                   = htons( query.id );
	response.header.opcode               = 0;
	response.header.query_response       = 1;
	response.header.authoritative_answer = 1;
	response.header.truncation           = 0;
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

    po::options_description desc("EDNS0 Cache Tester");
    desc.add_options()
        ("help,h",
         "print this message")

        ("bind,b",
         po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ),
         "bind address")

        ("test,t",
         po::value<int>( &case_id )->default_value( 0 ),
         "test case ID")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    EDNS0AuthServer server( bind_address, 53, case_id );
    server.start();

    return 0;
}
