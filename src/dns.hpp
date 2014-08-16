#ifndef DNS_HPP
#define DNS_HPP

#include <vector>
#include <string>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>

namespace dns
{

    typedef uint16_t Class;
    const Class CLASS_IN = 1;

    typedef uint16_t Type;
    const Type TYPE_A    = 1;
    const Type TYPE_NS   = 2;
    const Type TYPE_SOA  = 6;
    const Type TYPE_AAAA = 28;

    typedef uint8_t ResponseCode;
    const ResponseCode NO_ERROR       = 0;
    const ResponseCode NXRRSET        = 0;
    const ResponseCode FORMAT_ERROR   = 1;
    const ResponseCode SERVER_ERROR   = 2;
    const ResponseCode NAME_ERROR     = 3;
    const ResponseCode NXDOMAIN       = 3;
    const ResponseCode NOT_IMPLEENTED = 4;
    const ResponseCode REFUSED        = 5;

    class ResourceData;
    typedef boost::shared_ptr<ResourceData> ResourceDataPtr;

    class ResourceData
    {
    public:
        virtual ~ResourceData() {}

        virtual std::string toString() const = 0;
        virtual std::vector<boost::uint8_t> getPacket() const = 0;
        virtual Type type() const = 0;
    };


    class RecordA : public ResourceData
    {
    private:
        boost::uint32_t sin_addr;

    public:
        RecordA( boost::uint32_t sin_addr );
        RecordA( const std::string &address );

        virtual std::string toString() const;
        virtual std::vector<boost::uint8_t> getPacket() const;
        virtual Type type() const
        {
            return TYPE_A;
        }

        static ResourceDataPtr parse( const boost::uint8_t *begin, const boost::uint8_t *end );
    };


    class RecordAAAA : public ResourceData
    {
    private:
        boost::uint8_t sin_addr[16];
    public:
        RecordAAAA( const boost::uint8_t *sin_addr );
        RecordAAAA( const std::string &address );

        virtual std::string toString() const;
        virtual std::vector<boost::uint8_t> getPacket() const;
        virtual Type type() const
        {
            return TYPE_AAAA;
        }

        static ResourceDataPtr parse( const boost::uint8_t *begin, const boost::uint8_t *end );
    };

    class RecordNS : public ResourceData
    {
    private:
        std::string domainname;

    public:
        RecordNS( const std::string &name );

        virtual std::string toString() const;
        virtual std::vector<boost::uint8_t> getPacket() const;
        virtual uint16_t type() const
        {
            return TYPE_NS;
        }

        static ResourceDataPtr parse( const boost::uint8_t *packet, const boost::uint8_t *begin, const boost::uint8_t *end );
    };

    class RecordSOA : public ResourceData
    {
    private:
        std::string mname;
        std::string rname;
        boost::uint32_t serial;
        boost::uint32_t refresh;
        boost::uint32_t retry;
        boost::uint32_t expire;
        boost::uint32_t minimum;

    public:
        RecordSOA( const std::string &mname,
                   const std::string &rname,
                   uint32_t serial,
                   uint32_t refresh,
                   uint32_t retry,
                   uint32_t expire,
                   uint32_t minimum );

        virtual std::string toString() const;
        virtual std::vector<boost::uint8_t> getPacket() const;
        virtual uint16_t type() const
        {
            return TYPE_SOA;
        }

        const std::string &getMName() const { return mname; }

        static ResourceDataPtr parse( const boost::uint8_t *packet, const boost::uint8_t *begin, const boost::uint8_t *end );
    };


    struct QuestionSection
    {
        std::string q_domainname;
        uint16_t    q_type;
        uint16_t    q_class;
    };

    struct ResponseSection
    {
        std::string r_domainname;
        uint16_t    r_type;
        uint16_t    r_class;
        uint32_t    r_ttl;
        ResourceDataPtr r_resource_data;
    };

    struct QueryPacketInfo
    {
        boost::uint16_t id;
        bool            recursion;
        std::vector<QuestionSection> question;
    };

    struct ResponsePacketInfo
    {
        boost::uint16_t id;
        bool            recursion_available;
        bool            authoritative_answer;
        bool            truncation;
        bool            authentic_data;
        bool            checking_disabled;
        boost::uint8_t  response_code;

        std::vector<QuestionSection> question;
        std::vector<ResponseSection> answer;
        std::vector<ResponseSection> authority;
        std::vector<ResponseSection> additional_infomation;
    };


    struct PacketInfo
    {
        boost::uint16_t id;

        boost::uint8_t  query_response;
        boost::uint8_t  opcode;
        bool            authoritative_answer;
        bool            truncation;
        bool            recursion_desired;

        bool            recursion_available;
        bool            checking_disabled;
        boost::uint8_t  response_code;

        std::vector<QuestionSection> question_section;
        std::vector<ResponseSection> answer_section;
        std::vector<ResponseSection> authority_section;
        std::vector<ResponseSection> additional_infomation_section;
    };

    std::vector<boost::uint8_t> generate_dns_query_packet( const QueryPacketInfo &query );
    std::vector<boost::uint8_t> generate_dns_response_packet( const ResponsePacketInfo &response );
    ResponsePacketInfo parse_dns_response_packet( const boost::uint8_t *begin, const boost::uint8_t *end );
}

#endif
