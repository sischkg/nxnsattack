#ifndef SIGNED_ZONE_IMP_HPP
#define SIGNED_ZONE_IMP_HPP

#include "abstractzoneimp.hpp"
#include "nsecdb.hpp"

namespace dns
{
    class SignedZoneImp : public AbstractZoneImp
    {
    private:
	ZoneSigner mSigner;
	NSECDBPtr  mNSECDB;

    public:
        SignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config );

        virtual void setup();

	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	virtual std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;
	virtual void responseNoData( const Domainname &qname, PacketInfo &response, bool need_wildcard_nsec ) const;
	virtual void responseNXDomain( const Domainname &qname, PacketInfo &response ) const;
	virtual void responseRRSIG( const Domainname &qname, PacketInfo &response ) const;
	virtual void responseNSEC( const Domainname &qname, PacketInfo &response ) const;
        virtual void responseDNSKEY( const Domainname &qname, PacketInfo &response ) const;
        virtual void addRRSIG( PacketInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const;
	virtual RRSetPtr getDNSKEYRRSet() const;
	virtual RRSetPtr generateNSECRRSet( const Domainname &domainname ) const;

        static void initialize();
    };
}

#endif
