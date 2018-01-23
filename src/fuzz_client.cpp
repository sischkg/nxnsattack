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
          po::value<uint32_t>( &interval )->default_value( DEFAULT_INTERVAL_MSEC ) );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::OptionGenerator option_generator;

    while ( true ) {
	dns::PacketInfo packet_info;

	if ( dns::getRandom( 5 ) ) {
	    packet_info.opt_pseudo_rr.domainname   = ".";
	    packet_info.opt_pseudo_rr.payload_size = dns::getRandom( 0xffff );
	    packet_info.opt_pseudo_rr.rcode        = dns::getRandom( 0xff );
	    packet_info.opt_pseudo_rr.version      = 0;
	    packet_info.opt_pseudo_rr.dobit        = 1;
	    packet_info.edns0 = true;

            unsigned int count = dns::getRandom( 8 );
            for ( unsigned int i = 0 ; i < count ; i++ ) {
                option_generator.generate( packet_info );
            }

            if ( ! dns::getRandom( 7 ) ) {
                packet_info.opt_pseudo_rr.payload_size = dns::getRandom( 11000 );
            }
            if ( ! dns::getRandom( 7 ) ) {
                packet_info.opt_pseudo_rr.rcode = dns::getRandom( 16);
            }
            if ( ! dns::getRandom( 7 ) ) {
                packet_info.opt_pseudo_rr.dobit = dns::getRandom( 1 );
            }
	}

	dns::Domainname qname = basename;
	switch ( dns::getRandom( 7 ) ) {
	case 0:
	    qname.addSubdomain( "www" );
	    break;
	case 1:
	    qname.addSubdomain( "vvv" );
	    break;
	case 2:
	    qname.addSubdomain( "vvv" );
	    switch ( dns::getRandom( 5 ) ) {
	    case 0:
		qname.addSubdomain( "www" );
		break;
	    case 1:
		qname.addSubdomain( "zzz" );
		break;
	    case 2:
		qname.addSubdomain( "ns01" );
		break;
	    case 3:
		qname.addSubdomain( "*" );
		break;
	    }
	    break;
	case 3:
	    qname.addSubdomain( "zzz" );
	    switch ( dns::getRandom( 4 ) ) {
	    case 0:
		qname.addSubdomain( "www" );
		break;
	    case 1:
		qname.addSubdomain( "ns01" );
		break;
	    case 2:
		qname.addSubdomain( "*" );
		break;
	    }
	    break;
	case 4:
	    qname.addSubdomain( "yyyy" );
	    switch ( dns::getRandom( 4 ) ) {
	    case 0:
		qname.addSubdomain( "www" );
		break;
	    case 1:
		qname.addSubdomain( "ns01" );
		break;
	    case 2:
		qname.addSubdomain( "*" );
		break;
	    }
	    break;
	case 5:
	    qname.addSubdomain( "*" );
	    switch ( dns::getRandom( 4 ) ) {
	    case 0:
		qname.addSubdomain( "www" );
		break;
	    case 1:
		qname.addSubdomain( "ns01" );
		break;
	    case 2:
		qname.addSubdomain( "*" );
		break;
	    }
	    break;
	case 6:
	    qname.addSubdomain( "xxxxxxxxxx" );
	    break;
	}

	dns::Type  qtype  = dns::getRandom( 64 );
	dns::Class qclass = dns::CLASS_IN;
	if ( dns::getRandom( 16 ) == 0 )
	    qclass = dns::CLASS_ANY;
	if ( dns::getRandom( 16 ) == 0 )
	    qclass = dns::CLASS_NONE;

	dns::QuestionSectionEntry q;
        q.q_domainname = qname;
        q.q_type       = qtype;
        q.q_class      = qclass;
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
	dns::generate_dns_packet( packet_info, message );

	udpv4::ClientParameters udp_param;
	udp_param.destination_address = target_server;
	udp_param.destination_port    = target_port;
	udpv4::Client udp( udp_param );
	udp.sendPacket( message );

	timespec wait_time;
	wait_time.tv_sec = 0;
	wait_time.tv_nsec = 1000* 1000 * interval;
	nanosleep( &wait_time, nullptr );
    }

    return 0;
}
