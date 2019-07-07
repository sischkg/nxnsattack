
#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>

const int          TTL                 = 600;
const unsigned int PERIOD_MICRO_SECOND = 10;
const char *       RESPONSE_A          = "192.168.33.100";

const std::string SUBDOMAIN1 = "1234567890"
                               "2234567890"
                               "3234567890"
                               "4234567890"
                               "5234567890"
                               "6234567890";
const std::string SUBDOMAIN2 = "1234567890"
                               "2234567890"
                               "3234567890";

class AXFRServer : public dns::DNSServer
{
private:
    unsigned long long rr_count;

    dns::Domainname getQName( const dns::MessageInfo &query ) const
    {
        if ( query.getQuestionSection().size() == 0 ) {
            return dns::Domainname();
        }
        else {
            return query.getQuestionSection()[0].mDomainname;
        }
    }

    void setMessageHeader( dns::MessageInfo &response, uint16_t id ) const
    {
        response.mID                  = id;
        response.mOpcode              = 0;
        response.mQueryResponse       = 1;
        response.mAuthoritativeAnswer = 1;
        response.mTruncation          = 0;
        response.mRecursionDesired    = 0;
        response.mRecursionAvailable  = 0;
        response.mZeroField           = 0;
        response.mAuthenticData       = 1;
        response.mCheckingDisabled    = 1;
        response.mResponseCode        = dns::NO_ERROR;
    }


    dns::RDATAPtr generateSOA( const dns::Domainname &zone_name ) const
    {
	dns::Domainname mname = zone_name;
	mname.addSubdomain( "mname" );
	dns::Domainname rname = zone_name;
	rname.addSubdomain( "ns" );

        uint32_t serial = time( nullptr );
        
	return dns::RDATAPtr( new dns::RecordSOA( mname, rname, serial, 360000, 10000, 3600000, 3600 ) );
    }

    void sendFirstResponse( const dns::MessageInfo &query, tcpv4::ConnectionPtr &conn, dns::RDATAPtr soa ) const
    {
        dns::MessageInfo          response;
        dns::QuestionSectionEntry query_question = query.mQuestionSection[ 0 ];

        dns::QuestionSectionEntry question;
        question.mDomainname = getQName( query );
        question.mType       = query_question.mType;
        question.mClass      = query_question.mClass;
        response.pushQuestionSection( question );

        dns::ResourceRecord answer1;
        answer1.mDomainname = getQName( query );
        answer1.mType       = dns::TYPE_SOA;
        answer1.mClass      = dns::CLASS_IN;
        answer1.mTTL        = TTL;
        answer1.mRData      = soa;
        response.pushAnswerSection( answer1 );

        dns::ResourceRecord answer2;
        answer2.mDomainname = getQName( query );
        answer2.mType       = dns::TYPE_NS;
        answer2.mClass      = dns::CLASS_IN;
        answer2.mTTL        = TTL;
        answer2.mRData      = dns::RDATAPtr( new dns::RecordNS( (dns::Domainname)("www." + getQName( query ).toString() ) ) );
        response.pushAnswerSection( answer2 );

        dns::ResourceRecord answer3;
        answer3.mDomainname = (dns::Domainname)("www." + getQName( query ).toString());
        answer3.mType       = dns::TYPE_A;
        answer3.mClass      = dns::CLASS_IN;
        answer3.mTTL        = TTL;
        answer3.mRData      = dns::RDATAPtr( new dns::RecordA( RESPONSE_A ) );
        response.pushAnswerSection( answer3 );

        setMessageHeader( response, query.mID );

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

    void sendLastResponse( const dns::MessageInfo &query, tcpv4::ConnectionPtr &conn, dns::RDATAPtr soa ) const
    {
        dns::MessageInfo          response;
        dns::QuestionSectionEntry query_question = query.mQuestionSection[ 0 ];

        dns::QuestionSectionEntry question;
        question.mDomainname = getQName( query );
        question.mType       = query_question.mType;
        question.mClass      = query_question.mClass;
        response.pushQuestionSection( question );

        dns::ResourceRecord answer1;
        answer1.mDomainname = getQName( query );
        answer1.mType       = dns::TYPE_SOA;
        answer1.mClass      = dns::CLASS_IN;
        answer1.mTTL        = TTL;
        answer1.mRData      = soa;
        response.pushAnswerSection( answer1 );

        setMessageHeader( response, query.mID );

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

    void sendResponse( const dns::MessageInfo &query, tcpv4::ConnectionPtr &conn, unsigned long long &index ) const
    {
        dns::MessageInfo          response;
        dns::QuestionSectionEntry query_question = query.mQuestionSection[ 0 ];

        dns::QuestionSectionEntry question;
        question.mDomainname = query_question.mDomainname;
        question.mType       = query_question.mType;
        question.mClass      = query_question.mClass;
        response.pushQuestionSection( question );

        std::ostringstream os;
        os << SUBDOMAIN2 << "." << SUBDOMAIN1 << "." << SUBDOMAIN1 << "." << SUBDOMAIN1 << "."
           << query_question.mDomainname;

        dns::ResourceRecord answer;
        answer.mDomainname = (dns::Domainname)os.str();
        answer.mType       = dns::TYPE_A;
        answer.mClass      = dns::CLASS_IN;
        answer.mTTL        = TTL;
        answer.mRData      = dns::RDATAPtr( new dns::RecordA( RESPONSE_A ) );
        response.pushAnswerSection( answer );

        for ( int i = 0; i < 1000; i++ ) {
            dns::ResourceRecord answer2;

            std::ostringstream os2;
            os2 << std::setfill( '0' ) << std::setw( 16 ) << index;
            index++;
            answer2.mDomainname = (dns::Domainname)os2.str();
            answer2.mType       = dns::TYPE_CNAME;
            answer2.mClass      = dns::CLASS_IN;
            answer2.mTTL        = TTL;
            answer2.mRData      = dns::RDATAPtr( new dns::RecordCNAME( answer.mDomainname ) );
            response.pushAnswerSection( answer2 );
        }

        setMessageHeader( response, query.mID );

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

public:
    AXFRServer( const dns::DNSServerParameters &params, unsigned long long count )
        : dns::DNSServer( params ), rr_count( count )
    {
    }

    void generateAXFRResponse( const dns::MessageInfo &query, tcpv4::ConnectionPtr &conn ) const
    {
        unsigned long long index = 0;
        dns::RDATAPtr soa = generateSOA( query.mQuestionSection[0].mDomainname );

        std::cerr << "genearte axfr response" << std::endl;
        sendFirstResponse( query, conn, soa );
        while ( true ) {
            if ( rr_count != 0 && index > rr_count )
                break;
            std::cerr << "sent response: " << index << std::endl;
            sendResponse( query, conn, index );
        }
        sendLastResponse( query, conn, soa );
    }

    dns::MessageInfo generateResponse( const dns::MessageInfo &query, bool via_tcp ) const
    {
        dns::MessageInfo          response;
        dns::QuestionSectionEntry query_question = query.mQuestionSection[ 0 ];

        dns::QuestionSectionEntry question;
        question.mDomainname = query_question.mDomainname;
        question.mType       = query_question.mType;
        question.mClass      = query_question.mClass;
        response.pushQuestionSection( question );

        std::cerr << "received non axfr query: " <<  query_question.mType << std::endl;
        dns::ResourceRecord answer;
        if ( query_question.mType == dns::TYPE_SOA ) {
            answer.mDomainname = query_question.mDomainname;
            answer.mType       = dns::TYPE_SOA;
            answer.mClass      = dns::CLASS_IN;
            answer.mTTL        = TTL;
	    answer.mRData      = generateSOA( query_question.mDomainname );
            response.pushAnswerSection( answer );
        }

        setMessageHeader( response, query.mID );

        return response;
    }
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string        bind_address;
    uint16_t           bind_port;
    unsigned long long rr_count;

    po::options_description desc( "AXFR Server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
        ( "port",   po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )

        ( "count,c", po::value<unsigned long long>( &rr_count )->default_value( 0 ), "rr ount" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::DNSServerParameters params;
    params.mBindAddress = bind_address;
    params.mBindPort    = bind_port;
    AXFRServer server( params, rr_count );
    server.start();

    return 0;
}
