#include "dns.hpp"
#include "udpv4client.hpp"
#include "tcpv4client.hpp"
#include "rrgenerator.hpp"
#include "shufflebytes.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>
#include <fstream>
#include <time.h>

const uint32_t DEFAULT_INTERVAL_MSEC = 10;

namespace po = boost::program_options;


int main( int argc, char **argv )
{
    std::string target_server;
    uint16_t    target_port;
    std::string source_data;
    uint32_t    interval;
    uint64_t    count = 0;

    po::options_description desc( "query generator" );
    desc.add_options()( "help,h", "print this message" )

        ( "server,s",
          po::value<std::string>( &target_server )->default_value( "127.0.0.1" ),
          "target server address" )
        ( "port,p",
          po::value<uint16_t>( &target_port )->default_value( 53 ),
          "target server port" )
        ( "source,d",
          po::value<std::string>( &source_data ),
          "output filename for recording query messages" )
	( "interval,i",
          po::value<uint32_t>( &interval )->default_value( DEFAULT_INTERVAL_MSEC ) );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    if ( source_data == "" ) {
        std::cerr << "queries source data file must be specified." << std::endl;
        return 1;
    }

    std::fstream fin;
    std::istream *in;
    if ( source_data == "-" )
        in = &std::cin;
    else {
        fin.open( source_data.c_str(), std::fstream::in );
        in = &fin;
    }

    std::vector< std::vector<uint8_t> > queries;
    while ( ! in->eof() ) {
        char buf[100000];
        in->getline( buf, sizeof(buf) );
        uint32_t line_size = std::strlen( buf );
        if ( line_size == 0 )
            continue;

        // YYYY-mm-dd HH:MM:SS,<BASE64-STRING>
        // 12345678890123456789
        uint32_t base64_offset = std::strlen( "YYYY-mm-dd HH:MM:SS," );
        uint32_t base64_size = line_size - base64_offset;
        uint32_t query_size  = base64_size / 4 * 3;
        std::vector<uint8_t> query( query_size );

        std::cerr << "line size: "     << line_size     << ", "
                  << "base64 offset: " << base64_offset << ", "
                  << "base64 size: "   << base64_size   << ", "
                  << "query_size: "    << query_size    << std::endl;
       
        decodeFromBase64( buf + base64_offset, buf + line_size, &query[0] );
        queries.push_back( query );

        try {
            dns::MessageInfo query_info = dns::parseDNSMessage( &query[0], &query[0] + query.size() );
            std::cout << query_info << std::endl;
        }
        catch ( std::runtime_error &e ) {
            std::cerr << "parse error" << std::endl;
            std::cerr << e.what() << std::endl;
        }
        catch ( ... ) {
            std::cerr << "unknown parse error" << std::endl;
        }
    }

    while ( true ) {
        if ( count % 10000 == 0 )
            std::cerr << "sent " << count << std::endl;

        timespec wait_time;
        wait_time.tv_sec = 0;
        wait_time.tv_nsec = 1000* 1000 * interval;
        nanosleep( &wait_time, nullptr );
        count++;

        for ( auto message : queries ) {
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
                        continue;
                    uint16_t response_size = ntohs( *( reinterpret_cast<const uint16_t *>( response_size_data.getData() ) ) );

                    PacketData response_data;
                    while ( response_data.size() < response_size ) {
                        tcpv4::ConnectionInfo received_data = tcp.receive_data( response_size - response_data.size() );

                        response_data.insert( response_data.end(), received_data.begin(), received_data.end() );
                    }
                }

            }
            catch ( std::runtime_error &e )  {
                std::cerr << e.what() << std::endl;
            }
            catch ( ... ) {
                std::cerr << "other error" << std::endl;
            }

            return 0;
        }
    }
    return 0;
}
