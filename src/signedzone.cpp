#include "signedzone.hpp"
#include "signedzoneimp.hpp"

namespace dns
{
    SignedZone::SignedZone( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config,
                            const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo,
                            bool enable_nsec, bool enable_nsec3 )
	: mImp( new SignedZoneImp( zone_name, ksk_config, zsk_config,
                                   salt, iterate, algo,
                                   enable_nsec, enable_nsec3) )
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

    void SignedZone::setup()
    {
	mImp->setup();
    }

    SignedZone::NodePtr SignedZone::findNode( const Domainname &domainname ) const
    {
        return mImp->findNode( domainname );
    }

    std::shared_ptr<RRSet> SignedZone::signRRSet( const RRSet &rrset )
    {
        return mImp->signRRSet( rrset );
    }

    void SignedZone::initialize()
    {
        SignedZoneImp::initialize();
    }
}
