#ifndef SIGNED_AUTH_SERVER_HPP
#define SIGNED_AUTH_SERVEE_HPP

#include "dns_server.hpp"
#include "zoneloader.hpp"
#include "signedzone.hpp"

namespace dns
{
    class SignedAuthServer : public dns::DNSServer
    {
    public:
	SignedAuthServer( const std::string &addr, uint16_t port, bool debug )
	    : dns::DNSServer( addr, port, debug )
	{}

	void load( const std::string &apex, const std::string &zone_filename,
                   const std::string &ksk_config_yaml, const std::string &zsk_config_yaml );
	PacketInfo generateResponse( const PacketInfo &query, bool via_tcp );
	virtual PacketInfo modifyResponse( const PacketInfo &query,
					   const PacketInfo &original_response,
					   bool vir_tcp ) const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
    protected:
	typedef uint32_t ConditionFlags;
	const ConditionFlags MATCH_OWNER = 1;
	const ConditionFlags MATCH_TYPE  = 1<<1;
	const ConditionFlags MATCH_CLASS = 1<<2;
	const ConditionFlags MATCH_TTL   = 1<<3;
	const ConditionFlags MATCH_DATA  = 1<<4;

	struct Condition {
	    ConditionFlags flags = 0;
	    Domainname     owner;
	    Type           type  = 0;
	    Class          klass = 0;
	    TTL            ttl   = 0;
	};
        struct Replacement {
            ConditionFlags  flags = 0;
            Domainname      owner;
            Type            type  = 0;
            Class           klass = 0;
            TTL             ttl   = 0;
            RDATAPtr        resource_data;
        };
	bool replace( std::vector<ResponseSectionEntry> &section,
                      const Condition &condition,
                      const Replacement &replace ) const;
	bool erase( std::vector<ResponseSectionEntry> &section,
                    const Condition &condition ) const;
        
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset ) const;
    private:
	std::shared_ptr<SignedZone> zone;
    };
}

#endif
