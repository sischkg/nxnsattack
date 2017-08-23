#ifndef SIGNED_ZONE_HPP
#define SIGNED_ZONE_HPP

#include "zone.hpp"

namespace dns
{
    class SignedZoneImp;
    
    class SignedZone : public AbstractZone
    {
    public:
        SignedZone( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config );

        void add( std::shared_ptr<RRSet> rrset );
        PacketInfo getAnswer( const PacketInfo &query ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const; 
        void verify() const;

        static void initialize();
    private:
	std::shared_ptr<SignedZoneImp> mImp;
    };

}

#endif

