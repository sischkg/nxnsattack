
#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iomanip>
#include <iostream>

const int          TTL                 = 600;
const unsigned int PERIOD_MICRO_SECOND = 10;
const char *       RESPONSE_A          = "192.168.33.100";
const char *       MY_ADDRESS          = "192.168.33.1";
const char *       BIND_ADDRESS        = "192.168.33.1";

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
    unsigned long long index;
    unsigned int       period_micro_second;
    unsigned long long rr_count;

    void sendFirstResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        dns::QuestionSectionEntry question;
        question.q_domainname = query_question.q_domainname;
        question.q_type       = query_question.q_type;
        question.q_class      = query_question.q_class;
        response.question_section.push_back( question );

        dns::ResponseSectionEntry answer1;
        answer1.r_domainname    = query_question.q_domainname;
        answer1.r_type          = dns::TYPE_SOA;
        answer1.r_class         = dns::CLASS_IN;
        answer1.r_ttl           = TTL;
        answer1.r_resource_data = dns::ResourceDataPtr(
            new dns::RecordSOA( "mname.example.com", "ns.example.com", 0, 360000, 10000, 3600000, 3600 ) );
        response.answer_section.push_back( answer1 );

        dns::ResponseSectionEntry answer2;
        answer2.r_domainname    = "www." + query_question.q_domainname.toString();
        answer2.r_type          = dns::TYPE_A;
        answer2.r_class         = dns::CLASS_IN;
        answer2.r_ttl           = TTL;
        answer2.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
        response.answer_section.push_back( answer2 );

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
        dns::generate_dns_packet( response, response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

    void sendResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        uint16_t offset = sizeof( dns::PacketHeaderField );

        dns::QuestionSectionEntry question;
        question.q_domainname = query_question.q_domainname;
        question.q_type       = query_question.q_type;
        question.q_class      = query_question.q_class;
        response.question_section.push_back( question );

        offset += ( question.q_domainname.size() + 2 + 2 );

        std::ostringstream os;
        os << SUBDOMAIN2 << "." << SUBDOMAIN1 << "." << SUBDOMAIN1 << "." << SUBDOMAIN1 << "."
           << query_question.q_domainname;

        dns::ResponseSectionEntry answer;
        answer.r_domainname    = os.str();
        answer.r_type          = dns::TYPE_A;
        answer.r_class         = dns::CLASS_IN;
        answer.r_ttl           = TTL;
        answer.r_offset        = dns::NO_COMPRESSION;
        answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
        response.answer_section.push_back( answer );

        for ( int i = 0; i < 1000; i++ ) {
            dns::ResponseSectionEntry answer2;

            std::ostringstream os2;
            os2 << std::setfill( '0' ) << std::setw( 16 ) << index;
            index++;
            answer2.r_domainname    = os2.str();
            answer2.r_type          = dns::TYPE_CNAME;
            answer2.r_class         = dns::CLASS_IN;
            answer2.r_ttl           = TTL;
            answer2.r_offset        = offset;
            answer2.r_resource_data = dns::ResourceDataPtr( new dns::RecordCNAME( "", offset ) );
            response.answer_section.push_back( answer2 );
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

        WireFormat response_message;
        dns::generate_dns_packet( response, response_message );

        uint16_t send_size = htons( response_message.size() );
        conn->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
        conn->send( response_message );
    }

public:
    AXFRServer( const std::string addr, uint16_t port, unsigned int period, unsigned long long count )
        : dns::DNSServer( addr, port ), index( 0 ), period_micro_second( period ), rr_count( count )
    {
    }

    void generateAXFRResponse( const dns::PacketInfo &query, tcpv4::ConnectionPtr &conn )
    {
        sendFirstResponse( query, conn );
        std::cerr << "sent first response" << std::endl;
        while ( true ) {
            usleep( period_micro_second * 1000 );
            if ( rr_count != 0 && index > rr_count )
                break;
            std::cerr << "sent response: " << index << std::endl;
            sendResponse( query, conn );
        }
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

        dns::ResponseSectionEntry answer;
        if ( query_question.q_type == dns::TYPE_SOA ) {
            answer.r_domainname    = query_question.q_domainname;
            answer.r_type          = dns::TYPE_SOA;
            answer.r_class         = dns::CLASS_IN;
            answer.r_ttl           = TTL;
            answer.r_resource_data = dns::ResourceDataPtr(
                new dns::RecordSOA( "mname.example.com", "ns.example.com", 0, 360000, 10000, 3600000, 3600 ) );
            response.answer_section.push_back( answer );
        } else {
            answer.r_domainname    = query_question.q_domainname;
            answer.r_type          = dns::TYPE_A;
            answer.r_class         = dns::CLASS_IN;
            answer.r_ttl           = TTL;
            answer.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( RESPONSE_A ) );
            response.answer_section.push_back( answer );
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
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string        bind_address;
    unsigned int       period;
    unsigned long long rr_count;

    po::options_description desc( "AXFR Server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" )

            ( "period,p", po::value<unsigned int>( &period )->default_value( PERIOD_MICRO_SECOND ),
              "period[micro second]" )

                ( "count,c", po::value<unsigned long long>( &rr_count )->default_value( 0 ), "rr ount" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    AXFRServer server( bind_address, 53, period, rr_count );
    server.start();

    return 0;
}
