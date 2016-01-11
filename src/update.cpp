#include "dns.hpp"
#include "udpv4client.hpp"
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
    try {
        std::string target_server;
        std::string zone_name, base64_tsig_key, tsig_key_name;

        po::options_description desc( "Dynamic Update Client" );
        desc.add_options()( "help,h", "print this message" )

            ( "target,t",
              po::value<std::string>( &target_server )->default_value( DNS_SERVER_ADDRESS ),
              "target server address" )

                ( "zone,z", po::value<std::string>( &zone_name )->default_value( ZONE_NAME ), "zone name" )

                    ( "key,k", po::value<std::string>( &base64_tsig_key )->default_value( "" ), "tsig key" )

                        ( "name,n", po::value<std::string>( &tsig_key_name )->default_value( "" ), "tsig key name" )


            ;

        po::variables_map vm;
        po::store( po::parse_command_line( argc, argv, desc ), vm );
        po::notify( vm );

        if ( vm.count( "help" ) ) {
            std::cerr << desc << "\n";
            return 1;
        }

        PacketData tsig_key;
        if ( base64_tsig_key != "" && tsig_key_name != "" ) {
            decode_from_base64( base64_tsig_key, tsig_key );
        }

        dns::PacketInfo packet_info;

        dns::QuestionSectionEntry question;
        question.q_domainname = zone_name;
        question.q_type       = dns::TYPE_SOA;
        question.q_class      = dns::CLASS_IN;
        packet_info.question_section.push_back( question );

        dns::ResponseSectionEntry prerequisite;
        prerequisite.r_domainname = "aaa." + zone_name;
        prerequisite.r_type       = dns::TYPE_A;
        prerequisite.r_class      = dns::UPDATE_NONE;
        prerequisite.r_ttl        = 0xffffffff;
        packet_info.answer_section.push_back( prerequisite );

        dns::ResponseSectionEntry prerequisite2;
        prerequisite2.r_domainname = "aaa." + zone_name;
        prerequisite2.r_type       = dns::TYPE_A;
        prerequisite2.r_class      = dns::UPDATE_EXIST;
        prerequisite2.r_ttl        = 0;
        packet_info.answer_section.push_back( prerequisite2 );

        dns::ResponseSectionEntry update;
        update.r_domainname    = "aaa." + zone_name;
        update.r_type          = dns::TYPE_A;
        update.r_class         = dns::UPDATE_ADD;
        update.r_ttl           = 0;
        update.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "127.0.0.1" ) );
        packet_info.authority_section.push_back( update );

        packet_info.id                   = 0x0f01;
        packet_info.opcode               = dns::OPCODE_UPDATE;
        packet_info.query_response       = 0;
        packet_info.authoritative_answer = 0;
        packet_info.truncation           = 0;
        packet_info.recursion_desired    = 0;
        packet_info.recursion_available  = 0;
        packet_info.zero_field           = 0;
        packet_info.authentic_data       = 0;
        packet_info.checking_disabled    = 0;
        packet_info.response_code        = 0;

        WireFormat message;
        dns::generate_dns_packet( packet_info, message );

        if ( tsig_key.size() != 0 ) {
            dns::TSIGInfo tsig_info;
            tsig_info.name        = tsig_key_name;
            tsig_info.algorithm   = "HMAC-MD5.SIG-ALG.REG.INT";
            tsig_info.key         = tsig_key;
            tsig_info.signed_time = time( NULL );
            tsig_info.fudge       = 300;
            tsig_info.original_id = packet_info.id;

            dns::addTSIGResourceRecord( tsig_info, message );
        }

        udpv4::ClientParameters udp_param;
        udp_param.destination_address = target_server;
        udp_param.destination_port    = 53;
        udpv4::Client udp( udp_param );
        udp.sendPacket( message );

        udpv4::PacketInfo received_packet = udp.receivePacket();

        dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(), received_packet.end() );

        std::cout << res;

    } catch ( std::runtime_error e ) {
        std::cerr << e.what() << std::endl;
    } catch ( ... ) {
    }
    return 0;
}
