#ifndef UNSIGNED_ZONE_IMP_HPP
#define UNSIGNED_ZONE_IMP_HPP

#include "abstractzoneimp.hpp"
#include "nsecdb.hpp"

namespace dns
{
    class UnsignedZoneImp : public AbstractZoneImp
    {
    public:
        UnsignedZoneImp( const Domainname &zone_name );

        virtual void setup();

	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	virtual std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;
	virtual void responseRRSIG( const Domainname &qname, PacketInfo &response ) const;
	virtual void responseNSEC( const Domainname &qname, PacketInfo &response ) const;
        virtual void responseDNSKEY( PacketInfo &response ) const;
        virtual void addRRSIG( PacketInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const;
	virtual RRSetPtr getDNSKEYRRSet() const;
	virtual RRSetPtr generateNSECRRSet( const Domainname &domainname ) const;

        static void initialize();
    };
}

#endif
