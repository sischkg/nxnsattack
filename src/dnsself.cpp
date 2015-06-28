#include "udpv4client.hpp"
#include "dns.hpp"
#include <iostream>

int main()
{
    dns::QuestionSectionEntry question;
    question.q_domainname = "dtrj.co.jp";
    question.q_type       = dns::TYPE_SOA;
    question.q_class      = dns::CLASS_IN;

    dns::QueryPacketInfo query;
    query.id        = 0x1234;
    query.recursion = true;
    query.question.push_back( question );

    std::vector<uint8_t> dns_query_packet = dns::generate_dns_query_packet( query );

    dns::QueryPacketInfo parsed_query = dns::parse_dns_query_packet( dns_query_packet.data(),
								     dns_query_packet.data() + dns_query_packet.size() );
    std::cout << parsed_query;


    dns::ResponseSectionEntry authority;
    authority.r_domainname    = "test01.dtrj.co.jp";
    authority.r_type          = dns::TYPE_NS;
    authority.r_class         = dns::CLASS_IN;
    authority.r_ttl           = 86400;
    authority.r_resource_data = dns::ResourceDataPtr( new dns::RecordNS( "ns01.test01.dtrj.co.jp" ) );

    dns::ResponseSectionEntry additional_infomation;
    additional_infomation.r_domainname    = "dns01.dtrj.co.jp";
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

    std::vector<uint8_t> dns_response_packet = dns::generate_dns_response_packet( response );


    dns::ResponsePacketInfo res = dns::parse_dns_response_packet( dns_response_packet.data(),
                                                                  dns_response_packet.data() + dns_response_packet.size() );
    std::cout << res;

    return 0;
}
