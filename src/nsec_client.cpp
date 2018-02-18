#include "dns.hpp"
#include "udpv4client.hpp"
#include "rrgenerator.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>
#include <time.h>

const char *DNS_SERVER_ADDRESS       = "127.0.0.1";
const uint32_t DEFAULT_INTERVAL_MSEC = 500;

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server;
    uint16_t    target_port;
    std::string basename;
    uint32_t    interval = 0;
    uint32_t    max_query = 0;

    po::options_description desc( "query generator" );
    desc.add_options()( "help,h", "print this message" )

        ( "server,s",
          po::value<std::string>( &target_server )->default_value( DNS_SERVER_ADDRESS ),
          "target server address" )
        ( "port,p",
          po::value<uint16_t>( &target_port )->default_value( 53 ),
          "target server port" )
        ( "base,b",
          po::value<std::string>( &basename ),
          "basename" )
	( "interval,i",
          po::value<uint32_t>( &interval )->default_value( DEFAULT_INTERVAL_MSEC ),
	  "interval of each queries(msec)")
	( "count,c",
          po::value<uint32_t>( &max_query )->default_value( 0 ),
	  "query count. 0 means unlimited")
	;

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::OptionGenerator option_generator;
    unsigned int counter = 0;
    
    while ( true ) {
	if ( max_query != 0 && counter >= max_query )
	    break;
	
	dns::PacketInfo packet_info;

	dns::Domainname qname = basename;
	qname.addSubdomain( std::to_string( counter ) );

	dns::QuestionSectionEntry q;
        q.q_domainname = qname;
        q.q_type       = dns::TYPE_NSEC;
        q.q_class      = dns::CLASS_IN;
        packet_info.question_section.push_back( q );
	
	packet_info.id                   = 1234;
	packet_info.opcode               = 0;
	packet_info.query_response       = 0;
	packet_info.authoritative_answer = 0;
	packet_info.truncation           = 0;
	packet_info.recursion_desired    = 1;
	packet_info.recursion_available  = 0;
	packet_info.zero_field           = 0;
	packet_info.authentic_data       = 0;
	packet_info.checking_disabled    = 1;
	packet_info.response_code        = 0;
	
	WireFormat message;
	packet_info.generateMessage( message );

	udpv4::ClientParameters udp_param;
	udp_param.destination_address = target_server;
	udp_param.destination_port    = target_port;
	udpv4::Client udp( udp_param );
	udp.sendPacket( message );

	timespec wait_time;
	wait_time.tv_sec = 0;
	wait_time.tv_nsec = 1000* 1000 * interval;
	nanosleep( &wait_time, nullptr );

	counter++;
    }

    return 0;
}
