#ifndef ABSTRACT_ZONE_IMP_HPP
#define ABSTRACT_ZONE_IMP_HPP

#include "zone.hpp"
#include "zonesigner.hpp"
#include "nsecdb.hpp"

namespace dns
{
    class AbstractZoneImp
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

	void responseNoData( const Domainname &qname, PacketInfo &response, bool need_wildcard_nsec ) const;
	void responseNXDomain( const Domainname &qname, PacketInfo &response ) const;

    public:
        AbstractZoneImp( const Domainname &zone_name );

        void add( RRSetPtr rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        OwnerToNodeContainer::const_iterator begin() const { return mOwnerToNode.begin(); }
        OwnerToNodeContainer::const_iterator end() const   { return mOwnerToNode.end(); }

        void verify() const;

        virtual void setup() = 0;

	virtual std::shared_ptr<RRSet> signRRSet( const RRSet & ) const = 0;
	virtual void responseRRSIG( const Domainname &qname, PacketInfo &response ) const = 0;
        virtual void addRRSIG( PacketInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const = 0;
	virtual RRSetPtr getDNSKEYRRSet() const = 0;
	virtual RRSetPtr generateNSECRRSet( const Domainname &domainname ) const = 0;
    };
}

#endif
