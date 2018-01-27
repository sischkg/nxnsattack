#ifndef CRAFTED_SIGNED_AUTH_SERVER_HPP
#define CRAFTED_SIGNED_AUTH_SERVEE_HPP

#include "dns_server.hpp"
#include "zonesigner.hpp"

namespace dns
{
    class CraftedSignedAuthServer : public dns::DNSServer
    {
    public:
	CraftedSignedAuthServer( const std::string &apex,
				 const std::string &ksk_config,
				 const std::string &zsk_config,
				 const std::string &addr,
				 uint16_t port,
				 bool debug )
	    : dns::DNSServer( addr, port, true, debug ),
	      mApex( apex ),
	      mSigner( apex, ksk_config, zsk_config )
	{}
	virtual PacketInfo generateResponse( const PacketInfo &query, bool via_tcp ) = 0;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const
	{
	    return mSigner.getDSRecords();
	}
    protected:
        void signSection( std::vector<ResourceRecord> &section ) const;
    private:
	std::string mApex;
	ZoneSigner mSigner;

	std::vector<std::shared_ptr<RRSet> > cumulate( const std::vector<ResourceRecord> &rrs ) const;
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset ) const;
    };
}

#endif
