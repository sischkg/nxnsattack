#include "dns.hpp"
#include "tcpv4client.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
const char *ZONE_NAME          = "example.com";

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server;
    std::string zone_name;

    po::options_description desc( "AXFR Client" );
    desc.add_options()( "help,h", "print this message" )

        ( "target,t",
          po::value<std::string>( &target_server )->default_value( DNS_SERVER_ADDRESS ),
          "target server address" )

            ( "zone,z", po::value<std::string>( &zone_name )->default_value( ZONE_NAME ), "zone name" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::PacketInfo                        packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = zone_name;
    question.q_type       = dns::TYPE_AXFR;
    question.q_class      = dns::CLASS_IN;
    packet_info.question_section.push_back( question );

    packet_info.id                   = 1234;
    packet_info.opcode               = 0;
    packet_info.query_response       = 0;
    packet_info.authoritative_answer = 0;
    packet_info.truncation           = 0;
    packet_info.recursion_desired    = 0;
    packet_info.recursion_available  = 0;
    packet_info.zero_field           = 0;
    packet_info.authentic_data       = 0;
    packet_info.checking_disabled    = 1;
    packet_info.response_code        = 0;

    WireFormat query_stream;
    dns::generate_dns_packet( packet_info, query_stream );

    tcpv4::ClientParameters tcp_param;
    tcp_param.destination_address = target_server;
    tcp_param.destination_port    = 53;
    tcpv4::Client tcp( tcp_param );

    while ( true ) {

        uint16_t query_size_data = htons( query_stream.size() );
        tcp.send( reinterpret_cast<const uint8_t *>( &query_size_data ), 2 );
        tcp.send( query_stream );

        tcpv4::ConnectionInfo response_size_data = tcp.receive_data( 2 );
        uint16_t response_size = ntohs( *( reinterpret_cast<const uint16_t *>( response_size_data.getData() ) ) );

        PacketData response_data;
        while ( response_data.size() < response_size ) {
            tcpv4::ConnectionInfo received_data = tcp.receive_data( response_size - response_data.size() );

            std::cerr << "received size: " << received_data.getLength() << std::endl;
            response_data.insert( response_data.end(), received_data.begin(), received_data.end() );
        }
        dns::ResponsePacketInfo res =
            dns::parse_dns_response_packet( &response_data[ 0 ], &response_data[ 0 ] + response_data.size() );

        std::cout << res;

        if ( res.answer.size() == 0 || res.answer[ res.answer.size() - 1 ].r_type == dns::TYPE_SOA )
            break;
    }

    return 0;
}
