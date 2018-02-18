
#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>

const int          TTL                 = 600;
const char *       RESPONSE_A          = "10.201.8.34";
const char *       MY_ADDRESS          = "10.201.8.34";
const char *       BIND_ADDRESS        = "10.201.8.34";

class AXFRServer : public dns::DNSServer
{
private:
    unsigned long long index;
    unsigned int       period_micro_second;
    unsigned long long rr_count;
    uint32_t           soa_serial;
    dns::NSECBitmapField bitmap;

    dns::RDATAPtr generateSOA( const dns::Domainname &zone_name )
    {
	dns::Domainname mname = zone_name;
	mname.addSubdomain( "ns" );
	dns::Domainname rname = zone_name;
	rname.addSubdomain( "hostmaster" );

	return dns::RDATAPtr( new dns::RecordSOA( mname, rname, soa_serial, 360000, 10000, 3600000, 3600 ) );
    }

    void sendFirstResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        dns::PacketInfo response;
        dns::Domainname apex = query.question_section[0].q_domainname;

        dns::QuestionSectionEntry question;
        question.q_domainname = query.question_section[0].q_domainname;
        question.q_type       = dns::TYPE_AXFR;
        question.q_class      = query.question_section[0].q_class;
        response.question_section.push_back( question );

        std::shared_ptr<dns::RecordSOA> soa = std::dynamic_pointer_cast<dns::RecordSOA>( generateSOA( apex ) );
        dns::ResourceRecord answer1;
        answer1.r_domainname    = apex;
        answer1.r_type          = dns::TYPE_SOA;
        answer1.r_class         = dns::CLASS_IN;
        answer1.r_ttl           = TTL;
        answer1.r_resource_data = soa;
        response.answer_section.push_back( answer1 );

        /*
        dns::ResourceRecord answer2;
        answer2.r_domainname    = apex;
        answer2.r_type          = dns::TYPE_NS;
        answer2.r_class         = dns::CLASS_IN;
        answer2.r_ttl           = TTL;
        answer2.r_resource_data = dns::RDATAPtr( new dns::RecordNS( soa->getMName() ) );
        response.answer_section.push_back( answer2 );

        dns::ResourceRecord answer3;
        answer3.r_domainname    = soa->getMName();
        answer3.r_type          = dns::TYPE_A;
        answer3.r_class         = dns::CLASS_IN;
        answer3.r_ttl           = TTL;
        answer3.r_resource_data = dns::RDATAPtr( new dns::RecordA( RESPONSE_A ) );
        response.answer_section.push_back( answer3 );
        */
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

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

    void sendLastResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];
        dns::Domainname apex = query.question_section[0].q_domainname;

        std::shared_ptr<dns::RecordSOA> soa = std::dynamic_pointer_cast<dns::RecordSOA>( generateSOA( apex ) );
        dns::QuestionSectionEntry question;
        question.q_domainname = query_question.q_domainname;
        question.q_type       = dns::TYPE_AXFR;
        question.q_class      = query_question.q_class;
        response.question_section.push_back( question );

        dns::ResourceRecord answer2;
        answer2.r_domainname    = apex;
        answer2.r_type          = dns::TYPE_NS;
        answer2.r_class         = dns::CLASS_IN;
        answer2.r_ttl           = TTL;
        answer2.r_resource_data = dns::RDATAPtr( new dns::RecordNS( soa->getMName() ) );
        response.answer_section.push_back( answer2 );

        dns::ResourceRecord answer3;
        answer3.r_domainname    = soa->getMName();
        answer3.r_type          = dns::TYPE_A;
        answer3.r_class         = dns::CLASS_IN;
        answer3.r_ttl           = TTL;
        answer3.r_resource_data = dns::RDATAPtr( new dns::RecordA( RESPONSE_A ) );
        response.answer_section.push_back( answer3 );

        dns::ResourceRecord answer1;
        answer1.r_domainname    = query_question.q_domainname;
        answer1.r_type          = dns::TYPE_SOA;
        answer1.r_class         = dns::CLASS_IN;
        answer1.r_ttl           = TTL;
        answer1.r_resource_data = generateSOA( query_question.q_domainname );
        response.answer_section.push_back( answer1 );

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

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

    void sendResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        dns::QuestionSectionEntry question;
        question.q_domainname = query_question.q_domainname;
        question.q_type       = dns::TYPE_AXFR;
        question.q_class      = query_question.q_class;
        response.question_section.push_back( question );

        for ( int i = 0; i < 6; i++ ) {
            std::ostringstream os;
            os << std::setfill( '0' ) << std::setw( 16 ) << index;
            os << i << "." << index << "." << query_question.q_domainname;

            dns::Domainname owner = os.str();
            dns::Domainname next_name = owner;
            next_name.addSubdomain( "a" );

            dns::ResourceRecord answer;
            answer.r_domainname    = owner;
            answer.r_type          = dns::TYPE_NSEC;
            answer.r_class         = dns::CLASS_IN;
            answer.r_ttl           = TTL;
            answer.r_offset        = 0xFFFF;
            answer.r_resource_data = dns::RDATAPtr( new dns::RecordNSEC( next_name, bitmap ) );
            response.answer_section.push_back( answer );
        }
        index++;

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

        WireFormat response_message;
        response.generateMessage( response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

public:
    AXFRServer( const std::string addr, uint16_t port, unsigned int period, unsigned long long count, uint32_t serial = 0 )
        : dns::DNSServer( addr, port ), index( 0 ), period_micro_second( period ), rr_count( count ), soa_serial( serial )
    {
        for ( uint16_t type = 1 ; type < 0xffff ; type++ ) {
            bitmap.add( type );
        }
    }

    void generateAXFRResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        index = 0;
        sendFirstResponse( query, conn );
        std::cerr << "sent first response" << std::endl;
        while ( true ) {
            usleep( period_micro_second * 1000 );
            if ( rr_count != 0 && index > rr_count )
                break;
            std::cerr << "sent response: " << index << std::endl;
            sendResponse( query, conn );
        }
        sendLastResponse( query, conn );
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

        dns::ResourceRecord answer;
        if ( query_question.q_type == dns::TYPE_SOA ) {
            answer.r_domainname    = query_question.q_domainname;
            answer.r_type          = dns::TYPE_SOA;
            answer.r_class         = dns::CLASS_IN;
            answer.r_ttl           = TTL;
	    answer.r_resource_data = generateSOA( query_question.q_domainname );
            response.answer_section.push_back( answer );
        } else {
            answer.r_domainname    = query_question.q_domainname;
            answer.r_type          = dns::TYPE_A;
            answer.r_class         = dns::CLASS_IN;
            answer.r_ttl           = TTL;
            answer.r_resource_data = dns::RDATAPtr( new dns::RecordA( RESPONSE_A ) );
            response.answer_section.push_back( answer );
        }

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

    std::string        bind_address;
    unsigned int       period;
    unsigned long long rr_count;
    uint32_t           serial;

    po::options_description desc( "AXFR Server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" )

        ( "count,c", po::value<unsigned long long>( &rr_count )->default_value( 0 ), "rr ount" )

        ( "period,p", po::value<unsigned int>( &period )->default_value( 0 ), "period" )

        ( "serial,s", po::value<uint32_t>( &serial )->default_value( 0 ), "zone soa serial" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    AXFRServer server( bind_address, 53, period, rr_count, serial );
    server.start();

    return 0;
}
