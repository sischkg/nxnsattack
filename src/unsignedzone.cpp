#include "unsignedzone.hpp"
#include "unsignedzoneimp.hpp"

namespace dns
{
    UnsignedZone::UnsignedZone( const Domainname &zone_name )
	: mImp( new UnsignedZoneImp( zone_name ) )
    {}

    void UnsignedZone::add( std::shared_ptr<RRSet> rrset )
    {
	mImp->add( rrset );
    }

    PacketInfo UnsignedZone::getAnswer( const PacketInfo &query ) const
    {
	return mImp->getAnswer( query );
    }

    UnsignedZone::NodePtr UnsignedZone::findNode( const Domainname &domainname ) const
    {
        return mImp->findNode( domainname );
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

    const RRSet &UnsignedZone::getSOA() const
    {
	return mImp->getSOA();
    }

    const RRSet &UnsignedZone::getNameServers() const
    {
	return mImp->getNameServers();
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
