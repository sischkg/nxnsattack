#ifndef UNSIGNED_ZONE_IMP_HPP
#define UNSIGNED_ZONE_IMP_HPP

#include "zone.hpp"
#include "zonesigner.hpp"

namespace dns
{
    class UnsignedZoneImp
    {
    private:
        typedef std::shared_ptr<RRSet> RRSetPtr;
        typedef std::shared_ptr<Node>  NodePtr;
	typedef std::map<Domainname,   NodePtr> OwnerToNodeContainer;
	typedef std::pair<Domainname,  NodePtr> OwnerToNodePair;

        OwnerToNodeContainer mOwnerToNode;
        Domainname           mApex;

        RRSetPtr mSOA;
        RRSetPtr mNameServers;

        void addEmptyNode( const Domainname & );
        void addRRSet( std::vector<ResourceRecord> &, const RRSet &rrset ) const;
        void addSOAToAuthoritySection( PacketInfo &res ) const;
    public:
        UnsignedZoneImp( const Domainname &zone_name );

        void add( RRSetPtr rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        OwnerToNodeContainer::const_iterator begin() const { return mOwnerToNode.begin(); }
        OwnerToNodeContainer::const_iterator end() const   { return mOwnerToNode.end(); }
	RRSetPtr getSOA() const;
	RRSetPtr getNameServer() const;

        void verify() const;
	std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;

        static void initialize();
    };
}

#endif
