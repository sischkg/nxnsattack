#ifndef POST_SIGNED_ZONE_IMP_HPP
#define POST_SIGNED_ZONE_IMP_HPP

#include "abstractzoneimp.hpp"
#include "nsecdb.hpp"
#include "nsec3db.hpp"

namespace dns
{
    class PostSignedZoneImp : public AbstractZoneImp
    {
    private:
	ZoneSigner mSigner;
	NSECDB     mNSECDB;
        NSEC3DB    mNSEC3DB;
        bool       mEnableNSEC;
        bool       mEnableNSEC3;
    public:
        PostSignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config,
                           const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo,
                           bool enable_nsec = true, bool enable_nsec3 = false );

        virtual void setup();

	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	virtual std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;
	virtual void responseNoData( const Domainname &qname, MessageInfo &response, bool need_wildcard_nsec ) const;
	virtual void responseNXDomain( const Domainname &qname, MessageInfo &response ) const;
	virtual void responseRRSIG( const Domainname &qname, MessageInfo &response ) const;
	virtual void responseNSEC( const Domainname &qname, MessageInfo &response ) const;
        virtual void responseDNSKEY( const Domainname &qname, MessageInfo &response ) const;
        virtual void addRRSIG( MessageInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const;
        virtual void addRRSIG( MessageInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset, const Domainname &owner ) const;
	virtual RRSetPtr getDNSKEYRRSet() const;
	virtual RRSetPtr generateNSECRRSet( const Domainname &domainname ) const;

        static void initialize();
    };
}

#endif
