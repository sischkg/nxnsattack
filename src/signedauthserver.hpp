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
	SignedAuthServer( const std::string &addr, uint16_t port, bool debug, unsigned int thread_count )
	    : dns::DNSServer( addr, port, debug, thread_count )
	{}

	void load( const std::string &apex, const std::string &zone_filename,
                   const std::string &ksk_config_yaml, const std::string &zsk_config_yaml,
                   const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo,
                   bool enable_nsec, bool enable_nsec3 );
	PacketInfo generateResponse( const PacketInfo &query, bool via_tcp ) const;
	virtual PacketInfo modifyResponse( const PacketInfo &query,
					   const PacketInfo &original_response,
					   bool vir_tcp ) const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	std::shared_ptr<RRSet> signRRSet( const RRSet &rrset ) const;
    private:
	std::shared_ptr<SignedZone> zone;
    };
}

#endif
