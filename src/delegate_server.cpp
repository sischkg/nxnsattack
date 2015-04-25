#include "udpv4client.hpp"
#include "dns.hpp"
#include <iostream>

int main()
{
    dns::QuestionSection question;
    question.q_domainname = "dtrj.co.jp";
    question.q_type       = dns::TYPE_SOA;
    question.q_class      = dns::CLASS_IN;

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = true;
    query.question.push_back( question );

    dns::ResponseSection authority;
    authority.r_domainname    = "test01.dtrj.co.jp";
    authority.r_type          = dns::TYPE_NS;
    authority.r_class         = dns::CLASS_IN;
    authority.r_ttl           = 86400;
    authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "ns01.test01.dtrj.co.jp" ) );

    dns::ResponseSection additional_infomation;
    additional_infomation.r_domainname    = "ns01.test01.dtrj.co.jp";
    additional_infomation.r_type          = dns::TYPE_A;
    additional_infomation.r_class         = dns::CLASS_IN;
    additional_infomation.r_ttl           = 86400;
    additional_infomation.r_resource_data = dns::ResourceDataPtr( new dns::RecordA( "192.168.0.2" ) );

    dns::ResponsePacketInfo response;
    response.id                  = 0x1234;
    response.recursion_available = true;
    response.truncation          = false;
    response.authentic_data      = false;
    response.checking_disabled   = false;
    response.response_code       = dns::NO_ERROR;

    response.question.push_back( question );
    response.authority.push_back( authority );
    response.additional_infomation.push_back( additional_infomation );

    std::vector<boost::uint8_t> dns_query_packet    = dns::generate_dns_query_packet( query );
    std::vector<boost::uint8_t> dns_response_packet = dns::generate_dns_response_packet( response );

    udpv4::ClientParameters udp_param;
    udp_param.destination_address = "127.0.0.1";
    udp_param.destination_port    = 53;
    udpv4::Client udp( udp_param );
    udp.sendPacket( dns_query_packet.data(), dns_query_packet.size() );
    udp.sendPacket( dns_response_packet.data(), dns_response_packet.size() );


    udpv4::PacketInfo received_packet = udp.receivePacket();

//    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( dns_response_packet.data(),
//                                                                  dns_response_packet.data() + dns_response_packet.size() );
    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(),
                                                                  received_packet.end() );
    std::cout << "ID: " << res.id << std::endl;
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
