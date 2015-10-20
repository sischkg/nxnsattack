#include "dns_server.hpp"
#include <iostream>
#include <boost/program_options.hpp>


const int   TTL          = 5;
const char *RESPONSE_A   = "192.168.0.100";
const char *MY_ADDRESS   = "192.168.19.128";
const char *BIND_ADDRESS = "192.168.19.128";
const std::string MY_DOMAIN = "test.siskrn.co";
const std::string CNAME     = "cname." + MY_DOMAIN;

class TXTServer : public dns::DNSServer
{
public:
    TXTServer( const std::string addr, uint16_t port )
	: dns::DNSServer( addr, port )
    {}

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
	dns::PacketInfo response;
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

	dns::QuestionSectionEntry query_question = query.question_section[0];

	dns::QuestionSectionEntry question;
	question.q_domainname = query_question.q_domainname;
	question.q_type       = query_question.q_type;
	question.q_class      = query_question.q_class;
	response.question_section.push_back( question );

        std::vector<std::string> txt_data;
        uint16_t offset = sizeof(dns::PacketHeaderField) +
            ( query_question.q_domainname.size() + 2 + 2 + 2 ) +
            ( query_question.q_domainname.size() + 2 + 2 + 2 + 4 + 2 );

        for ( int i = 0 ; i < 0x40 ; i++ ) {
            std::string data;

            offset++;
	    if ( i == 0 ) {
		data.push_back( 0 );
		data.push_back( 0 );
		data.push_back( 0 );
		uint16_t d = ( 0xC000 + offset );
		data.push_back( (uint8_t)( d >> 8) );
		data.push_back( (uint8_t)( d & 0xff) );
		offset += 5;
	    }
	    else {
		uint16_t d = ( 0xC000 + offset - 3 );
		data.push_back( (uint8_t)( d >> 8) );
		data.push_back( (uint8_t)( d & 0xff) );
		offset += 2;
	    }

	    //            std::cerr << d << std::endl;

            for ( int j = 0 ; j < 240/2 ; j++ ) {
                uint16_t d = ( 0xC000 + offset - 2 );
                data.push_back( (uint8_t)(d >> 8) );
                data.push_back( (uint8_t)(d & 0xff) );
                offset += 2;
		//                std::cerr << std::hex << (int)(d>>8) << "," << (int)(d&0xff) << std::endl;
            }
            txt_data.push_back( data );
        }
                

	dns::ResponseSectionEntry answer1;
	answer1.r_domainname    = query_question.q_domainname;
	answer1.r_type          = dns::TYPE_TXT;
	answer1.r_class         = dns::CLASS_IN;
	answer1.r_ttl           = TTL;
	answer1.r_resource_data = dns::ResourceDataPtr( new dns::RecordTXT( txt_data ) );
	response.answer_section.push_back( answer1 );

	dns::ResponseSectionEntry answer2;
	answer2.r_domainname    = MY_DOMAIN;
	answer2.r_type          = dns::TYPE_NS;
	answer2.r_class         = dns::CLASS_IN;
	answer2.r_ttl           = TTL;
	answer2.r_offset        = offset - 2;
	answer2.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "ns1." + MY_DOMAIN ) );
        response.authority_section.push_back( answer2 );

	dns::ResponseSectionEntry answer3;
	answer3.r_domainname    = "ns1." + MY_DOMAIN;
	answer3.r_type          = dns::TYPE_A;
	answer3.r_class         = dns::CLASS_IN;
	answer3.r_ttl           = TTL;
	answer3.r_offset        = offset - 2;
	answer3.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( MY_ADDRESS ) );
        response.additional_infomation_section.push_back( answer3 );
  
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

    po::options_description desc("CNAME Server");
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

    TXTServer server( bind_address, 53 );
    server.start();

    return 0;
}

