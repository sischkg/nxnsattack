#include "udpv4client.hpp"
#include "dns.hpp"
#include <cstring>
#include <iostream>
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
// const char *DNS_SERVER_ADDRESS = "192.168.33.11";
// const char *DNS_SERVER_ADDRESS = "172.16.253.81";
// const char *DNS_SERVER_ADDRESS = "49.212.193.254";

namespace po = boost::program_options;

int main( int argc, char **argv )
{
    std::string target_server = DNS_SERVER_ADDRESS;
    int test_version = 0;

    po::options_description desc("UDP Echo client.");
    desc.add_options()
        ("help,h",
         "print this message")

        ("server,s",
         po::value<std::string>(&target_server)->default_value( DNS_SERVER_ADDRESS ),
         "target server address")

        ("test_version,t",
         po::value<int>(&test_version)->default_value( 0 ),
         "test version")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line( argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.com";
    question.q_type       = dns::TYPE_A;
    question.q_class      = dns::CLASS_IN;
    question_section.push_back( question );



    std::vector<dns::OptPseudoRROptPtr> options;
    std::string nsid = "";

    options.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( nsid ) ) );
    dns::OptPseudoRecord opt;
    opt.payload_size = 1280;
    opt.record_options_data = boost::shared_ptr<dns::ResourceData>( new dns::RecordOptionsData( options ) );

    additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt ) );

    dns::PacketHeaderField header;
    header.id                   = htons( 1234 );
    header.opcode               = 0;
    header.query_response       = 0;
    header.authoritative_answer = 0;
    header.truncation           = 0;
    header.recursion_desired    = false;
    header.recursion_available  = 0;
    header.zero_field           = 0;
    header.authentic_data       = 0;
    header.checking_disabled    = 0;
    header.response_code        = 0;

    std::vector<uint8_t> packet = dns::generate_dns_packet( header,
							    question_section,
							    answer_section,
							    authority_section,
							    additional_infomation_section );


    udpv4::ClientParameters udp_param;
    udp_param.destination_address = target_server;
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( packet.data(), packet.size() );

    udpv4::PacketInfo received_packet = udp.receivePacket();

    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );

    std::cout << res;


    return 0;
}
