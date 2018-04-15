#ifndef POSTSIGNED_ZONE_IMP_HPP
#define POSTSIGNED_ZONE_IMP_HPP

#include "zone.hpp"
#include "zonesigner.hpp"

namespace dns
{
    class PostSignedZoneImp
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

        void addEmptyNode( const Domainname & );
        void addRRSet( std::vector<ResourceRecord> &, const RRSet &rrset ) const;
        void addRRSIG( std::vector<ResourceRecord> &, const RRSet &original_rrset ) const;
        void addSOAToAuthoritySection( PacketInfo &res ) const;

	RRSetPtr generateNSECRRSet( const Domainname &domainname ) const;
    public:
        PostSignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config );

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
