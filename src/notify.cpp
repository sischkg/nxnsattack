#include "dns.hpp"
#include "udpv4client.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>

const char *DEFAULT_SERVER_ADDRESS = "127.0.0.1";
const char *DEFAULT_ZONE_NAME  = "example.com";

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server;
    std::string zone_name;

    po::options_description desc( "NOTIFY Client" );
    desc.add_options()( "help,h", "print this message" )

        ( "target,t",
          po::value<std::string>( &target_server )->default_value( DEFAULT_SERVER_ADDRESS ),
          "target server address" )

	( "zone,z", po::value<std::string>( &zone_name )->default_value( DEFAULT_ZONE_NAME ), "zone name" );

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
    question.q_type       = dns::TYPE_SOA;
    question.q_class      = dns::CLASS_IN;
    packet_info.question_section.push_back( question );

    packet_info.id                   = 1234;
    packet_info.opcode               = dns::OPCODE_NOTIFY;
    packet_info.query_response       = 0;
    packet_info.authoritative_answer = 0;
    packet_info.truncation           = 0;
    packet_info.recursion_desired    = 0;
    packet_info.recursion_available  = 0;
    packet_info.zero_field           = 0;
    packet_info.authentic_data       = 0;
    packet_info.checking_disabled    = 1;
    packet_info.response_code        = 0;

    WireFormat notify_data;
    dns::generate_dns_packet( packet_info, notify_data );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = target_server;
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );

    udp.sendPacket( notify_data );
    udpv4::PacketInfo recv_data = udp.receivePacket();
	
    dns::PacketInfo res =
	dns::parse_dns_packet( &recv_data[ 0 ], &recv_data[ 0 ] + recv_data.getPayloadLength() );

    std::cout << res;

    return 0;
}
