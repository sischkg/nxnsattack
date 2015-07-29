#ifndef DNS_HPP
#define DNS_HPP

#include <vector>
#include <string>
#include <stdexcept>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>

namespace dns
{
    typedef std::vector<uint8_t>::iterator       PacketIterator;
    typedef std::vector<uint8_t>::const_iterator ConstPacketIterator;

    typedef uint8_t Opcode;
    const Opcode OPCODE_QUERY  = 0;
    const Opcode OPCODE_NOTIFY = 4;

    typedef uint16_t Class;
    const Class CLASS_IN = 1;

    typedef uint16_t Type;
    const Type TYPE_A    = 1;
    const Type TYPE_NS   = 2;
    const Type TYPE_SOA  = 6;
    const Type TYPE_AAAA = 28;
    const Type TYPE_OPT  = 41;

    typedef uint16_t OptType;
    const OptType OPT_NSID = 3;

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
        virtual std::vector<uint8_t> getPacket() const = 0;
        virtual Type type() const = 0;
    };


    class RecordA : public ResourceData
    {
    private:
        uint32_t sin_addr;

    public:
        RecordA( uint32_t in_sin_addr );
        RecordA( const std::string &in_address );

        virtual std::string toString() const;
        virtual std::vector<uint8_t> getPacket() const;
        virtual Type type() const
        {
            return TYPE_A;
        }

        static ResourceDataPtr parse( const uint8_t *begin, const uint8_t *end );
    };


    class RecordAAAA : public ResourceData
    {
    private:
        uint8_t sin_addr[16];
    public:
        RecordAAAA( const uint8_t *sin_addr );
        RecordAAAA( const std::string &address );

        virtual std::string toString() const;
        virtual std::vector<uint8_t> getPacket() const;
        virtual Type type() const
        {
            return TYPE_AAAA;
        }

        static ResourceDataPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordNS : public ResourceData
    {
    private:
        std::string domainname;

    public:
        RecordNS( const std::string &name );

        virtual std::string toString() const;
        virtual std::vector<uint8_t> getPacket() const;
        virtual uint16_t type() const
        {
            return TYPE_NS;
        }

        static ResourceDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };

    class RecordSOA : public ResourceData
    {
    private:
        std::string mname;
        std::string rname;
        uint32_t    serial;
        uint32_t    refresh;
        uint32_t    retry;
        uint32_t    expire;
        uint32_t    minimum;

    public:
        RecordSOA( const std::string &mname,
                   const std::string &rname,
                    uint32_t          serial,
                    uint32_t          refresh,
                    uint32_t          retry,
                    uint32_t          expire,
                    uint32_t          minimum );

        virtual std::string toString() const;
        virtual std::vector<uint8_t> getPacket() const;
        virtual uint16_t type() const
        {
            return TYPE_SOA;
        }

        const std::string &getMName() const { return mname; }

        static ResourceDataPtr parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };


    class OptPseudoRROption
    {
    public:
	virtual ~OptPseudoRROption() {}
	virtual std::string toString() const = 0;
	virtual std::vector<uint8_t> getPacket() const = 0;
	virtual uint16_t code() const = 0;
	virtual uint16_t size() const = 0;
    };

    typedef boost::shared_ptr<OptPseudoRROption> OptPseudoRROptPtr;

    class RAWOption : public OptPseudoRROption
    {
    private:
	uint16_t option_code;
	uint16_t option_size;
	std::vector<uint8_t> option_data;

    public:
	RAWOption( uint16_t in_code,
		   uint16_t in_size,
		   const std::vector<uint8_t> &in_data )
	    : option_code( in_code ),
	      option_size( in_size ),
	      option_data( in_data )
	{}

	virtual std::string toString() const;
	virtual std::vector<uint8_t> getPacket() const;
	virtual uint16_t code() const { return option_code; }
	virtual uint16_t size() const { return option_size; }
    };


    class NSIDOption : public OptPseudoRROption
    {
    private:
	std::string nsid;
    public:
	NSIDOption( const std::string &id = "" ) : nsid(id) {}

	virtual std::string toString() const { return "NSID: \"" + nsid + "\""; }
	virtual std::vector<uint8_t> getPacket() const;
	virtual uint16_t code() const { return OPT_NSID; }
	virtual uint16_t size() const { return 2 + 2 + nsid.size(); }

	static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };


    class RecordOpt : public ResourceData
    {
    private:
	uint16_t payload_size;
	uint8_t rcode;
	std::vector<OptPseudoRROptPtr> options;
	uint16_t rdata_size;

    public:
	RecordOpt( uint16_t in_payload_size                  = 1280,
		   uint8_t  in_rcode                         = 0,
		   const std::vector<OptPseudoRROptPtr> &in_options = std::vector<OptPseudoRROptPtr>(),
		   uint32_t in_rdata_size                    = 0xffffffff );

	virtual std::string toString() const;
	virtual std::vector<uint8_t> getPacket() const;
	virtual uint16_t type() const { return TYPE_OPT; }
	virtual uint16_t size() const { return 1 + 2 + 2 + 4 + 2 + rdata_size; }

	const std::vector<OptPseudoRROptPtr> &getOptions() const { return options; }
        static ResourceDataPtr parse( const uint8_t *packet,
				      const uint8_t *entry_begin,
				      const uint8_t *begin,
				      const uint8_t *end );
    };



    struct QuestionSectionEntry
    {
        std::string     q_domainname;
	uint16_t q_type;
	uint16_t q_class;
	uint16_t q_offset;
    };

    struct ResponseSectionEntry
    {
        std::string r_domainname;
	uint16_t r_type;
	uint16_t r_class;
	uint32_t r_ttl;
        ResourceDataPtr r_resource_data;
	uint16_t r_offset;
    };

    struct QueryPacketInfo
    {
        uint16_t id;
	Opcode          opcode;
        bool            recursion;
	bool            edns0;
        std::vector<QuestionSectionEntry> question;
	RecordOpt       opt_pseudo_rr;

	QueryPacketInfo( uint16_t in_id        = 0,
			 Opcode          in_opcode    = OPCODE_QUERY,
			 bool            in_recursion = false,
			 bool            in_edns0     = false,
			 const std::vector<QuestionSectionEntry> &in_question = std::vector<QuestionSectionEntry>(),
			 const RecordOpt &in_opt_pseudo_rr = RecordOpt() )
	    : id( in_id ),
	      opcode( in_opcode ),
	      recursion( in_recursion ),
	      edns0( in_edns0 ),
	      question( in_question ),
	      opt_pseudo_rr( in_opt_pseudo_rr )
	{}
    };

    struct ResponsePacketInfo
    {
        uint16_t id;
        bool     recursion_available;
        bool     authoritative_answer;
        bool     truncation;
        bool     authentic_data;
        bool     checking_disabled;
        uint8_t  response_code;

        std::vector<QuestionSectionEntry> question;
        std::vector<ResponseSectionEntry> answer;
        std::vector<ResponseSectionEntry> authority;
        std::vector<ResponseSectionEntry> additional_infomation;
    };


    struct PacketInfo
    {
        uint16_t id;

        uint8_t  query_response;
        uint8_t  opcode;
        bool            authoritative_answer;
        bool            truncation;
        bool            recursion_desired;

        bool            recursion_available;
        bool            checking_disabled;
        uint8_t  response_code;

        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResponseSectionEntry> answer_section;
        std::vector<ResponseSectionEntry> authority_section;
        std::vector<ResponseSectionEntry> additional_infomation_section;
    };

    std::vector<uint8_t> generate_dns_query_packet( const QueryPacketInfo &query );
    std::vector<uint8_t> generate_dns_response_packet( const ResponsePacketInfo &response );
    QueryPacketInfo      parse_dns_query_packet( const uint8_t *begin, const uint8_t *end );
    ResponsePacketInfo   parse_dns_response_packet( const uint8_t *begin, const uint8_t *end );
    std::ostream &operator<<( std::ostream &os, const QueryPacketInfo &query );
    std::ostream &operator<<( std::ostream &os, const ResponsePacketInfo &response );

    struct PacketHeaderField
    {
        uint16_t id;

        uint8_t  recursion_desired:    1;
        uint8_t  truncation:           1;
        uint8_t  authoritative_answer: 1;
        uint8_t  opcode:               4;
        uint8_t  query_response:       1;

        uint8_t  response_code:        4;
        uint8_t  checking_disabled:    1;
        uint8_t  authentic_data:       1;
        uint8_t  zero_field:           1;
        uint8_t  recursion_available:  1;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_infomation_count;
    };

    struct SOAField
    {
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    };

    std::vector<uint8_t> convert_domainname_string_to_binary( const std::string &domainname,
							      uint16_t compress_offset = 0xffff );
    std::pair<std::string, const uint8_t *> convert_domainname_binary_to_string( const uint8_t *packet,
										 const uint8_t *domainame,
										 int recur = 0 ) throw(FormatError);
    std::vector<uint8_t> generate_question_section( const QuestionSectionEntry &q );
    std::vector<uint8_t> generate_response_section( const ResponseSectionEntry &r );

    typedef std::pair<QuestionSectionEntry, const uint8_t *> QuestionSectionEntryPair;
    typedef std::pair<ResponseSectionEntry, const uint8_t *> ResponseSectionEntryPair;
    QuestionSectionEntryPair parse_question_section( const uint8_t *packet, const uint8_t *section );
    ResponseSectionEntryPair parse_response_section( const uint8_t *packet, const uint8_t *section );

    template<typename Type>
    uint8_t *set_bytes( Type v, uint8_t *pos )
    {
        *reinterpret_cast<Type *>( pos ) = v;
        return pos + sizeof(v);
    }

    template<typename Type>
    Type get_bytes( const uint8_t **pos )
    {
        Type v = *reinterpret_cast<const Type *>( *pos );
        *pos += sizeof(Type);
        return v;
    }

}

#endif
