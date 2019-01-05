#ifndef UNSIGNED_ZONE_HPP
#define UNSIGNED_ZONE_HPP

#include "zone.hpp"

namespace dns
{
    class UnsignedZoneImp;
    
    class UnsignedZone : public Zone
    {
    public:
        UnsignedZone( const Domainname &zone_name );

        void add( std::shared_ptr<RRSet> rrset );
        MessageInfo getAnswer( const MessageInfo &query ) const;
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const; 
        void verify() const;
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset );

	const RRSet &getSOA() const;
	const RRSet &getNameServers() const;

        static void initialize();
	
    private:
	std::shared_ptr<UnsignedZoneImp> mImp;
    };

}

#endif

