#include "udpv4client.hpp"
#include "dns.hpp"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
const char *ZONE_NAME          = "example.com";

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server;
    std::string zone_name;

    po::options_description desc("AXFR Client");
    desc.add_options()
        ("help,h",
         "print this message")

        ("target,t",
         po::value<std::string>(&target_server)->default_value( DNS_SERVER_ADDRESS ),
         "target server address")

        ("zone,z",
         po::value<std::string>(&zone_name)->default_value( ZONE_NAME ),
         "zone name")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::PacketInfo packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = "example.com";
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

    std::vector<uint8_t> query = dns::generate_dns_packet( packet_info );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = target_server;
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );

    while ( true ) {
	udp.sendPacket( query.data(), query.size() );
	udpv4::PacketInfo response = udp.receivePacket();

	dns::ResponsePacketInfo res = dns::parse_dns_response_packet( response.begin(), response.end() );
	std::cout << res;

	if ( res.answer.size() == 0 ||
	     res.answer[ res.answer.size() - 1 ].r_type == dns::TYPE_SOA )
	    break;
    }

    return 0;
}
