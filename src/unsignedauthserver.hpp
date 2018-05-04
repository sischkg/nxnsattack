#ifndef UNSIGNED_AUTH_SERVER_HPP
#define UNSIGNED_AUTH_SERVEE_HPP

#include "dns_server.hpp"
#include "zoneloader.hpp"
#include "postsignedzone.hpp"

namespace dns
{
    class PostSignedAuthServer : public dns::DNSServer
    {
    public:
	PostSignedAuthServer( const std::string &addr, uint16_t port, bool debug )
	    : dns::DNSServer( addr, port, true, debug )
	{}

	void load( const std::string &apex, const std::string &zone_filename,
                   const std::string &ksk_config_yaml, const std::string &zsk_config_yaml );
	PacketInfo generateResponse( const PacketInfo &query, bool via_tcp );
	virtual PacketInfo modifyResponse( const PacketInfo &query,
					   const PacketInfo &original_response,
					   bool vir_tcp ) const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
        
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset ) const;
    private:
	std::shared_ptr<PostSignedZone> zone;
    };
}

#endif
