#ifndef UNSIGNED_AUTH_SERVER_HPP
#define UNSIGNED_AUTH_SERVEE_HPP

#include "dns_server.hpp"
#include "zoneloader.hpp"
#include "postsignedzone.hpp"
#include "zonesigner.hpp"

namespace dns
{
    class PostSignedAuthServer : public dns::DNSServer
    {
    public:
	PostSignedAuthServer( const std::string &addr, uint16_t port, unsigned int thread_count )
	    : dns::DNSServer( addr, port, thread_count )
	{}
	PostSignedAuthServer( const DNSServerParameters &params )
	    : dns::DNSServer( params )
	{}

	void load( const std::string &apex, const std::string &zone_filename,
                   const std::string &ksk_config_yaml, const std::string &zsk_config_yaml,
                   const std::vector<uint8_t> &salt, uint16_t iteerate, HashAlgorithm algo,
                   bool enable_nsec, bool enable_nsec3 );
	MessageInfo generateResponse( const MessageInfo &query, bool via_tcp ) const;
	virtual MessageInfo modifyResponse( const MessageInfo &query,
					    const MessageInfo &original_response,
					    bool vir_tcp ) const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
        
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset ) const;
    private:
	std::shared_ptr<PostSignedZone> zone;
    };
}

#endif
