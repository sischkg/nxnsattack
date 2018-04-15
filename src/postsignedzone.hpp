#ifndef POSTSIGNED_ZONE_HPP
#define POSTSIGNED_ZONE_HPP

#include "zone.hpp"

namespace dns
{
    class PostSignedZoneImp;
    
    class PostSignedZone : public Zone
    {
    public:
        PostSignedZone( const Domainname &zone_name, const std::string &ksk_config = "", const std::string &zsk_config = "" );

        void add( std::shared_ptr<RRSet> rrset );
        PacketInfo getAnswer( const PacketInfo &query ) const;
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const; 
        void verify() const;
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset );

	RRSetPtr getSOA() const;
	RRSetPtr getNameServer() const;

        static void initialize();
	
    private:
	std::shared_ptr<PostSignedZoneImp> mImp;
    };

}

#endif

