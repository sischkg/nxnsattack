#include "dns.hpp"
#include "tcpv4client.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/numeric/conversion/cast.hpp>
#include <cstring>
#include <iostream>

const char *DNS_SERVER_ADDRESS = "192.168.33.10";
// const char *DNS_SERVER_ADDRESS = "172.16.253.81";
// const char *DNS_SERVER_ADDRESS = "49.212.193.254";

int main()
{
    dns::PacketInfo                        packet_info;
    std::vector<dns::QuestionSectionEntry> question_section;
    std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

    dns::QuestionSectionEntry question;
    question.q_domainname = "www.example.com";
    question.q_type       = dns::TYPE_TXT;
    question.q_class      = dns::CLASS_IN;
    packet_info.question_section.push_back( question );

    std::vector<dns::OptPseudoRROptPtr> options;
    std::string                         nsid = "";

    options.push_back( dns::OptPseudoRROptPtr( new dns::NSIDOption( nsid ) ) );
    dns::OptPseudoRecord opt;
    opt.payload_size        = 1280;
    opt.record_options_data = dns::ResourceDataPtr( new dns::RecordOptionsData( options ) );

    packet_info.additional_infomation_section.push_back( dns::generate_opt_pseudo_record( opt ) );

    packet_info.id                   = 1234;
    packet_info.opcode               = 0;
    packet_info.query_response       = 0;
    packet_info.authoritative_answer = 0;
    packet_info.truncation           = 0;
    packet_info.recursion_desired    = false;
    packet_info.recursion_available  = 0;
    packet_info.zero_field           = 0;
    packet_info.authentic_data       = 0;
    packet_info.checking_disabled    = 0;
    packet_info.response_code        = 0;

    std::vector<uint8_t> packet = dns::generate_dns_packet( packet_info );

    tcpv4::ClientParameters tcp_param;
    tcp_param.destination_address = DNS_SERVER_ADDRESS;
    tcp_param.destination_port    = 53;
    tcpv4::Client tcp( tcp_param );
    uint16_t      data_size = htons( boost::numeric_cast<uint16_t>( packet.size() ) );
    tcp.send( reinterpret_cast<uint8_t *>( &data_size ), 2 );
    tcp.send( packet.data(), packet.size() );

    tcpv4::ConnectionInfo received_packet = tcp.receive_data( 2 );
    int                   response_size   = ntohs( *reinterpret_cast<uint16_t *>( &received_packet.stream[ 0 ] ) );
    received_packet                       = tcp.receive_data( response_size );
    tcp.closeSocket();

    dns::PacketInfo res = dns::parse_dns_packet( received_packet.begin(), received_packet.end() );

    std::cout << res;

    return 0;
}
