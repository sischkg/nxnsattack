#include "unsignedzone.hpp"
#include "unsignedzoneimp.hpp"

namespace dns
{
    UnsignedZone::UnsignedZone( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config )
	: mImp( new UnsignedZoneImp( zone_name, ksk_config, zsk_config ) )
    {}

    void UnsignedZone::add( std::shared_ptr<RRSet> rrset )
    {
	mImp->add( rrset );
    }

    PacketInfo UnsignedZone::getAnswer( const PacketInfo &query ) const
    {
	return mImp->getAnswer( query );
    }

    UnsignedZone::RRSetPtr UnsignedZone::findRRSet( const Domainname &domainname, Type type ) const
    {
        return mImp->findRRSet( domainname, type );
    }

    std::vector<std::shared_ptr<RecordDS>> UnsignedZone::getDSRecords() const
    {
	return mImp->getDSRecords();
    }

    void UnsignedZone::verify() const
    {
	mImp->verify();
    }

    std::shared_ptr<RRSet> UnsignedZone::signRRSet( const RRSet &rrset )
    {
        return mImp->signRRSet( rrset );
    }

    void UnsignedZone::initialize()
    {
        UnsignedZoneImp::initialize();
    }
}
