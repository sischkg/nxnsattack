#ifndef DNS_HPP
#define DNS_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>

namespace dns
{
    typedef std::vector<boost::uint8_t>::iterator       PacketIterator;
    typedef std::vector<boost::uint8_t>::const_iterator ConstPacketIterator;

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

    /*!
     * DNS Packetのフォーマットエラーを検知した場合にthrowする例外
     */
    class FormatError : public std::runtime_error
    {
    public:
	FormatError( const std::string &msg )
	    : std::runtime_error( msg )
	{}
    };

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


    struct QuestionSectionEntry
    {
        std::string q_domainname;
        uint16_t    q_type;
        uint16_t    q_class;
	uint16_t    q_offset;
    };

    struct ResponseSectionEntry
    {
        std::string r_domainname;
        uint16_t    r_type;
        uint16_t    r_class;
        uint32_t    r_ttl;
        ResourceDataPtr r_resource_data;
	uint16_t    r_offset;
    };

    struct QueryPacketInfo
    {
        boost::uint16_t id;
        bool            recursion;
        std::vector<QuestionSectionEntry> question;
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

        std::vector<QuestionSectionEntry> question;
        std::vector<ResponseSectionEntry> answer;
        std::vector<ResponseSectionEntry> authority;
        std::vector<ResponseSectionEntry> additional_infomation;
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

        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResponseSectionEntry> answer_section;
        std::vector<ResponseSectionEntry> authority_section;
        std::vector<ResponseSectionEntry> additional_infomation_section;
    };

    std::vector<boost::uint8_t> generate_dns_query_packet( const QueryPacketInfo &query );
    std::vector<boost::uint8_t> generate_dns_response_packet( const ResponsePacketInfo &response );
    QueryPacketInfo    parse_dns_query_packet( const boost::uint8_t *begin, const boost::uint8_t *end );
    ResponsePacketInfo parse_dns_response_packet( const boost::uint8_t *begin, const boost::uint8_t *end );
    std::ostream &operator<<( std::ostream &os, const QueryPacketInfo &query );
    std::ostream &operator<<( std::ostream &os, const ResponsePacketInfo &response );

    struct PacketHeaderField
    {
        boost::uint16_t id;

        boost::uint8_t  recursion_desired:    1;
        boost::uint8_t  truncation:           1;
        boost::uint8_t  authoritative_answer: 1;
        boost::uint8_t  opcode:               4;
        boost::uint8_t  query_response:       1;

        boost::uint8_t  response_code:        4;
        boost::uint8_t  checking_disabled:    1;
        boost::uint8_t  authentic_data:       1;
        boost::uint8_t  zero_field:           1;
        boost::uint8_t  recursion_available:  1;

        boost::uint16_t question_count;
        boost::uint16_t answer_count;
        boost::uint16_t authority_count;
        boost::uint16_t additional_infomation_count;
    };

    struct SOAField
    {
        boost::uint32_t serial;
        boost::uint32_t refresh;
        boost::uint32_t retry;
        boost::uint32_t expire;
        boost::uint32_t minimum;
    };

    std::vector<boost::uint8_t> convert_domainname_string_to_binary( const std::string &domainname );
    std::pair<std::string, const boost::uint8_t *> convert_domainname_binary_to_string( const boost::uint8_t *packet,
                                                                                        const boost::uint8_t *domainame,
											int recur = 0 ) throw(FormatError);
    std::vector<boost::uint8_t> generate_question_section( const QuestionSectionEntry &q );
    std::vector<boost::uint8_t> generate_response_section( const ResponseSectionEntry &r );

    typedef std::pair<QuestionSectionEntry, const boost::uint8_t *> QuestionSectionEntryPair;
    typedef std::pair<ResponseSectionEntry, const boost::uint8_t *> ResponseSectionEntryPair;
    QuestionSectionEntryPair parse_question_section( const boost::uint8_t *packet, const boost::uint8_t *section );
    ResponseSectionEntryPair parse_response_section( const boost::uint8_t *packet, const boost::uint8_t *section );

    template<typename Type>
    boost::uint8_t *set_bytes( Type v, boost::uint8_t *pos )
    {
        *reinterpret_cast<Type *>( pos ) = v;
        return pos + sizeof(v);
    }

    template<typename Type>
    Type get_bytes( const boost::uint8_t **pos )
    {
        Type v = *reinterpret_cast<const Type *>( *pos );
        *pos += sizeof(Type);
        return v;
    }

}

#endif
