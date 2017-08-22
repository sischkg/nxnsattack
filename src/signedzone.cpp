#include "signedzone.hpp"
#include "signedzoneimp.hpp"

namespace dns
{
    SignedZone::SignedZone( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config )
	: mImp( new SignedZoneImp( zone_name, ksk_config, zsk_config ) )
    {}

    void SignedZone::add( std::shared_ptr<RRSet> rrset )
    {
	mImp->add( rrset );
    }

    PacketInfo SignedZone::getAnswer( const PacketInfo &query ) const
    {
	return mImp->getAnswer( query );
    }

    SignedZone::RRSetPtr SignedZone::findRRSet( const Domainname &domainname, Type type ) const
    {
        return mImp->findRRSet( domainname, type );
    }

    std::vector<std::shared_ptr<RecordDS>> SignedZone::getDSRecords() const
    {
	return mImp->getDSRecords();
    }

    void SignedZone::verify() const
    {
	mImp->verify();
    }
}
