#ifndef ABSTRACT_ZONE_IMP_HPP
#define ABSTRACT_ZONE_IMP_HPP

#include "zone.hpp"
#include "zonesigner.hpp"
#include "nsecdb.hpp"

namespace dns
{
    class AbstractZoneImp
    {
    public:
        typedef std::shared_ptr<RRSet> RRSetPtr;
        typedef std::shared_ptr<Node>  NodePtr;
	typedef std::map<Domainname,   NodePtr> OwnerToNodeContainer;
	typedef std::pair<Domainname,  NodePtr> OwnerToNodePair;

    private:
        OwnerToNodeContainer mOwnerToNode;
        Domainname           mApex;

        RRSetPtr mSOA;
        RRSetPtr mNameServers;

    protected:
        void addEmptyNode( const Domainname & );
        void addRRSet( std::vector<ResourceRecord> &, const RRSet &rrset ) const;
        void addSOAToAuthoritySection( PacketInfo &res ) const;

    public:
        AbstractZoneImp( const Domainname &zone_name );

        const Domainname &getApex() const { return mApex; }
        const RRSet &getSOA() const { return *mSOA; }
        const RRSet &getNameServers() const { return *mNameServers; }

        void add( RRSetPtr rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;
	
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        OwnerToNodeContainer::const_iterator begin() const { return mOwnerToNode.begin(); }
        OwnerToNodeContainer::const_iterator end() const   { return mOwnerToNode.end(); }

        void verify() const;

        virtual void setup() = 0;

	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const = 0;
	virtual std::shared_ptr<RRSet> signRRSet( const RRSet & ) const = 0;
	virtual void responseDelegation( const Domainname &qname, PacketInfo &response, const RRSet &ns_rrset ) const;
	virtual void responseNoData( const Domainname &qname, PacketInfo &response, bool need_wildcard_nsec ) const = 0;
	virtual void responseNXDomain( const Domainname &qname, PacketInfo &response ) const = 0;
	virtual void responseRRSIG( const Domainname &qname, PacketInfo &response ) const = 0;
	virtual void responseNSEC( const Domainname &qname, PacketInfo &response ) const = 0;
        virtual void addRRSIG( PacketInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const = 0;
	virtual RRSetPtr getDNSKEYRRSet() const = 0;
	virtual RRSetPtr generateNSECRRSet( const Domainname &domainname ) const = 0;
    };
}

#endif
