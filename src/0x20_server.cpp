#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iostream>

const int   TTL          = 20;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.33.1";
const char *BIND_ADDRESS = "0.0.0.0";

class D0x20AuthServer : public dns::DNSServer
{
private:

public:
    D0x20AuthServer( const std::string addr, uint16_t port ) : dns::DNSServer( addr, port )
    {
    }

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        dns::QuestionSectionEntry question;
        question.q_domainname = query_question.q_domainname;
        question.q_type       = query_question.q_type;
        question.q_class      = query_question.q_class;
        response.question_section.push_back( question );

	dns::Domainname cname1 = query_question.q_domainname;
	cname1.addSubdomain( "C" );
	dns::Domainname cname2 = query_question.q_domainname;
	cname2.addSubdomain( "c" );

	dns::ResponseSectionEntry answer1;
	answer1.r_domainname    = query_question.q_domainname;
	answer1.r_type          = dns::TYPE_CNAME;
	answer1.r_class         = dns::CLASS_IN;
	answer1.r_ttl           = TTL;
	answer1.r_resource_data = dns::ResourceDataPtr( new dns::RecordCNAME( cname1 ) );
	response.answer_section.push_back( answer1 );

	dns::ResponseSectionEntry answer2;
	answer2.r_domainname    = cname2;
	answer2.r_type          = dns::TYPE_A;
	answer2.r_class         = dns::CLASS_IN;
	answer2.r_ttl           = TTL;
	answer2.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
	response.answer_section.push_back( answer2 );

        dns::ResponseSectionEntry authority;
        authority.r_domainname    = "example.com";
        authority.r_type          = dns::TYPE_NS;
        authority.r_class         = dns::CLASS_IN;
        authority.r_ttl           = TTL;
        //authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "ns1.example.com" ) );
	authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "nS1.eXaMpLe.CoM" ) );
        response.authority_section.push_back( authority );

        dns::ResponseSectionEntry additional;
        additional.r_domainname    = "Ns1.ExAmPlE.cOm";
        additional.r_type          = dns::TYPE_A;
        additional.r_class         = dns::CLASS_IN;
        additional.r_ttl           = TTL;
        additional.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( MY_ADDRESS ) );
        response.additional_infomation_section.push_back( additional );

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

    po::options_description desc( "D0x20 Cache Tester" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    D0x20AuthServer server( bind_address, 53 );
    server.start();

    return 0;
}
