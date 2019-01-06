#include "dns.hpp"
#include "udpv4client.hpp"
#include "tcpv4client.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>
#include <time.h>

const char *DNS_SERVER_ADDRESS       = "127.0.0.1";
const uint32_t DEFAULT_INTERVAL_MSEC = 10;

namespace po = boost::program_options;



int main( int argc, char **argv )
{
    std::string target_server;
    uint16_t    target_port;
    uint32_t    interval;
    uint64_t    count = 0;

    po::options_description desc( "query generator" );
    desc.add_options()( "help,h", "print this message" )

        ( "server,s",
          po::value<std::string>( &target_server )->default_value( DNS_SERVER_ADDRESS ),
          "target server address" )
        ( "port,p",
          po::value<uint16_t>( &target_port )->default_value( 53 ),
          "target server port" )
	( "interval,i",
          po::value<uint32_t>( &interval )->default_value( DEFAULT_INTERVAL_MSEC ) );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::MessageInfo packet_info;

    packet_info.mOptPseudoRR.mDomainname  = ".";
    packet_info.mOptPseudoRR.mPayloadSize = 4096;
    packet_info.mOptPseudoRR.mRCode       = 0;
    packet_info.mOptPseudoRR.mVersion     = 0;
    packet_info.mOptPseudoRR.mDOBit       = 1;
    packet_info.mIsEDNS0                  = true;

    std::shared_ptr<dns::RecordOptionsData> options = std::dynamic_pointer_cast<dns::RecordOptionsData>(packet_info.mOptPseudoRR.mOptions);

    std::vector<uint16_t> keytags1, keytags2;
    for ( uint16_t i = 0 ; i < 32000 ; i++ ) {
        keytags1.push_back( i );
    }
    keytags2.push_back( 0xffff );

    packet_info.addOption( std::make_shared<dns::KeyTagOption>(  keytags1 ) );
    packet_info.addOption( std::make_shared<dns::KeyTagOption>(  keytags2 ) );

    dns::QuestionSectionEntry q;
    q.mDomainname = "example.com";
    q.mType       = dns::TYPE_A;
    q.mClass      = dns::CLASS_IN;
    packet_info.mQuestionSection.push_back( q );

    packet_info.mID                  = 10;
    packet_info.mOpcode              = 1;
    packet_info.mQueryResponse       = 0;
    packet_info.mAuthoritativeAnswer = 0;
    packet_info.mTruncation          = 0;
    packet_info.mRecursionDesired    = 1;
    packet_info.mRecursionAvailable  = 0;
    packet_info.mZeroField           = 0;
    packet_info.mAuthenticData       = 0;
    packet_info.mCheckingDisabled    = 0;
    packet_info.mResponseCode        = 0;
	
    WireFormat message;
    packet_info.generateMessage( message );

    while ( true ) {
        try {
	    if ( message.size() < 1500 ) {
		udpv4::ClientParameters udp_param;
		udp_param.mAddress = target_server;
		udp_param.mPort    = target_port;
		udpv4::Client udp( udp_param );
		udp.sendPacket( message );
	    }
	    else {
		tcpv4::ClientParameters tcp_param;
		tcp_param.mAddress = target_server;
		tcp_param.mPort    = target_port;
		tcpv4::Client tcp( tcp_param );
		tcp.openSocket();

		uint16_t query_size_data2 = htons( message.size() );
		tcp.send( reinterpret_cast<const uint8_t *>( &query_size_data2 ), 2 );
		tcp.send( message );

		tcpv4::ConnectionInfo response_size_data = tcp.receive_data( 2 );
		if ( response_size_data.getLength() < 2 )
		    return 1;
		uint16_t response_size = ntohs( *( reinterpret_cast<const uint16_t *>( response_size_data.getData() ) ) );

		PacketData response_data;
		while ( response_data.size() < response_size ) {
		    tcpv4::ConnectionInfo received_data = tcp.receive_data( response_size - response_data.size() );

		    response_data.insert( response_data.end(), received_data.begin(), received_data.end() );
		}

	    }

	    wait_msec( interval );
	}
	catch ( std::runtime_error &e ) {
	    std::cerr << e.what() << std::endl;
	}
        count++;
        if ( count % 10000 == 0 )
            std::cerr << "sent queries: " << count << std::endl;
    }

    return 0;
}
