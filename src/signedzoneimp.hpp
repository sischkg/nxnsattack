#ifndef SIGNED_ZONE_IMP_HPP
#define SIGNED_ZONE_IMP_HPP

#include "zone.hpp"
#include "zonesigner.hpp"
#include "nsecdb.hpp"

namespace dns
{
    class SignedZoneImp
    {
    private:
        typedef std::shared_ptr<RRSet> RRSetPtr;
        typedef std::shared_ptr<Node>  NodePtr;
	typedef std::map<Domainname,   NodePtr> OwnerToNodeContainer;
	typedef std::pair<Domainname,  NodePtr> OwnerToNodePair;

        OwnerToNodeContainer mOwnerToNode;
        Domainname           mApex;
	ZoneSigner           mSigner;

        RRSetPtr mSOA;
        RRSetPtr mNameServers;

	NSECDB mNSECDB;

        void addEmptyNode( const Domainname & );
        void addRRSet( std::vector<ResourceRecord> &, const RRSet &rrset ) const;
        void addRRSIG( PacketInfo &, std::vector<ResourceRecord> &, const RRSet &original_rrset ) const;
        void addSOAToAuthoritySection( PacketInfo &res ) const;
	RRSetPtr getDNSKEYRRSet() const;
	RRSetPtr generateNSECRRSet( const Domainname &domainname ) const;
    public:
        SignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config );

        void add( RRSetPtr rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
	
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        OwnerToNodeContainer::const_iterator begin() const { return mOwnerToNode.begin(); }
        OwnerToNodeContainer::const_iterator end() const   { return mOwnerToNode.end(); }

        void verify();
	std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;

	virtual void responseDNSKEY( PacketInfo &response ) const;
	virtual void responseRRSIG( const Domainname &qname, PacketInfo &response ) const;

	void responseNoData( const Domainname &qname, PacketInfo &response, bool need_wildcard_nsec ) const;
	void responseNXDomain( const Domainname &qname, PacketInfo &response ) const;

        static void initialize();
    };
}

#endif
