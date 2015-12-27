#include "dns.hpp"
#include "tcpv4client.hpp"
#include "udpv4client.hpp"
#include <iostream>
#include <sstream>
#include <time.h>

class RecordBadNAPTR : public dns::ResourceData
{
private:
    int             rr_size;
    uint16_t        order;
    uint16_t        preference;
    std::string     flags;
    std::string     services;
    std::string     regexp;
    dns::Domainname replacement;
    uint16_t        offset;

public:
    RecordBadNAPTR( int s, uint16_t in_order, uint16_t in_preference, const std::string &in_flags,
                    const std::string &in_services, const std::string &in_regexp, const dns::Domainname &in_replacement,
                    uint16_t in_offset = dns::NO_COMPRESSION );

    virtual std::string          toString() const;
    virtual std::vector<uint8_t> getPacket() const;
    virtual void                 outputWireFormat( WireFormat & ) const;
    virtual uint16_t             type() const
    {
        return dns::TYPE_NAPTR;
    }
    virtual uint16_t size() const
    {
        return rr_size;
    }
};

RecordBadNAPTR::RecordBadNAPTR( int s, uint16_t in_order, uint16_t in_preference, const std::string &in_flags,
                                const std::string &in_services, const std::string &in_regexp,
                                const dns::Domainname &in_replacement, uint16_t in_offset )
    : rr_size( s ), order( in_order ), preference( in_preference ), flags( in_flags ), services( in_services ),
      regexp( in_regexp ), replacement( in_replacement ), offset( in_offset )
{
}

std::string RecordBadNAPTR::toString() const
{
    std::stringstream os;
    os << "order: " << order << ", preference: " << preference << "flags: " << flags << ", services: " << services
       << "regexp: " << regexp << ", replacement: " << replacement;
    return os.str();
}

PacketData RecordBadNAPTR::getPacket() const
{
    PacketData                       packet;
    std::insert_iterator<PacketData> pos( packet, packet.begin() );

    uint16_t n_order      = htons( order );
    uint16_t n_preference = htons( preference );
    pos                   = std::copy( reinterpret_cast<uint8_t *>( &n_order ),
                     reinterpret_cast<uint8_t *>( &n_order ) + sizeof( n_order ), pos );
    pos = std::copy( reinterpret_cast<uint8_t *>( &n_preference ),
                     reinterpret_cast<uint8_t *>( &n_preference ) + sizeof( n_preference ), pos );

    *pos++ = flags.size();
    pos    = std::copy( flags.c_str(), flags.c_str() + flags.size(), pos );
    *pos++ = services.size();
    pos    = std::copy( services.c_str(), services.c_str() + services.size(), pos );
    *pos++ = rr_size;
    //*pos++ = regexp.size();
    pos = std::copy( regexp.c_str(), regexp.c_str() + regexp.size(), pos );

    //    PacketData replacement_packet = replacement.getPacket( offset );
    PacketData replacement_packet; // = replacement.getPacket( offset );

    const unsigned int label_size = 10;
    for ( int k = 0; k < 21; k++ ) {
        replacement_packet.push_back( label_size );
        for ( unsigned int l = 0; l < label_size; l++ ) {
            replacement_packet.push_back( 40 + k );
        }
    }
    replacement_packet.push_back( 0 );

    pos = std::copy( replacement_packet.begin(), replacement_packet.end(), pos );
    return packet;
}

void RecordBadNAPTR::outputWireFormat( WireFormat &message ) const
{
    PacketData                       packet;
    std::insert_iterator<PacketData> pos( packet, packet.begin() );

    message.pushUInt16HtoN( order );
    message.pushUInt16HtoN( preference );
    message.pushUInt8( flags.size() );
    message.pushBuffer( reinterpret_cast<const uint8_t *>( flags.c_str() ),
                        reinterpret_cast<const uint8_t *>( flags.c_str() ) + flags.size() );
    message.pushUInt8( regexp.size() );
    message.pushBuffer( reinterpret_cast<const uint8_t *>( regexp.c_str() ),
                        reinterpret_cast<const uint8_t *>( regexp.c_str() ) + regexp.size() );
    replacement.outputWireFormat( message, offset );
}

int main()
{
    for ( int i = 0; i < 256 * 256; i++ ) {

        dns::PacketInfo                        packet_info;
        std::vector<dns::QuestionSectionEntry> question_section;
        std::vector<dns::ResponseSectionEntry> answer_section, authority_section, additional_infomation_section;

        std::ostringstream os;
        os << i << ".";

        dns::QuestionSectionEntry question;
        question.q_domainname = os.str() + "www.example.com";
        question.q_type       = dns::TYPE_NAPTR;
        question.q_class      = dns::CLASS_IN;
        packet_info.question_section.push_back( question );

        dns::ResponseSectionEntry additonal;
        additonal.r_domainname = os.str() + "yyy.example.net";
        additonal.r_type       = dns::TYPE_NAPTR;
        additonal.r_class      = dns::CLASS_IN;
        additonal.r_ttl        = 30;
        additonal.r_resource_data =
            dns::ResourceDataPtr( new RecordBadNAPTR( 0xff & i, 0, 0, "a", "app", "regex", "a" ) );
        packet_info.additional_infomation_section.push_back( additonal );

        packet_info.id                   = i;
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

        WireFormat message;
        dns::generate_dns_packet( packet_info, message );

        udpv4::ClientParameters udp_param;
        udp_param.destination_address = "192.168.33.14";
        udp_param.destination_port    = 53;
        udpv4::Client udp( udp_param );
        udp.sendPacket( message );

        udpv4::PacketInfo received_packet = udp.receivePacket();

        dns::ResponsePacketInfo res = dns::parse_dns_response_packet( received_packet.begin(), received_packet.end() );
        std::cout << res;
    }

    return 0;
}
