#ifndef ZONE_HPP
#define ZONE_HPP

#include "dns.hpp"
#include <map>
#include <vector>

namespace dns
{
    class RRSet
    {
    public:
        typedef std::vector<ResourceDataPtr> ResourceDataContainer;
  
    private:
        Domainname owner;
        Class      klass;
        Type       type;
        TTL        ttl;
        ResourceDataContainer resource_data;

    public:
        RRSet( const Domainname &name, Class c, Type t, TTL tt )
            : owner( name ), klass( c ), type( t ), ttl( tt )
        {}

        const Domainname &getOwner() const { return owner; }
        Domainname getCanonicalOwer() const { return owner.getCanonicalDomainname(); }

        Class getClass() const { return klass; }
        Type  getType()  const { return type; }
        TTL   getTTL()   const { return ttl; } 
        uint16_t count() const { return resource_data.size(); }

        ResourceDataContainer::const_iterator begin() const { return resource_data.begin(); }
        ResourceDataContainer::const_iterator end()   const { return resource_data.end(); }

        void add( ResourceDataPtr data ) { resource_data.push_back( data ); }
    };


    class Node
    {
    public:
        typedef std::shared_ptr<RRSet>    RRSetPtr;
        typedef std::map<Type,  RRSetPtr> RRSetContainer;
        typedef std::pair<Type, RRSetPtr> RRSetPair;

    private:
        RRSetContainer rrsets;

    public:
        RRSetContainer::iterator begin() { return rrsets.begin(); }
        RRSetContainer::iterator end()   { return rrsets.end(); }
        RRSetPtr find( Type t ) const;

        RRSetContainer::const_iterator begin() const { return rrsets.begin(); }
        RRSetContainer::const_iterator end()   const { return rrsets.end(); }

        bool empty( Type t ) const { return ! find( t ); }
        bool exist( Type t ) const { return ! empty( t ); } 

        void add( std::shared_ptr<RRSet> rrset ) { rrsets.insert( RRSetPair( rrset->getType(), rrset ) ); }
    };

    class Zone
    {
    private:
        typedef std::shared_ptr<RRSet> RRSetPtr;
        typedef std::shared_ptr<Node>  NodePtr;
	typedef std::map<Domainname,   NodePtr> OwnerToNodeContainer;
	typedef std::pair<Domainname,  NodePtr> OwnerToNodePair;

        OwnerToNodeContainer owner_to_node;
        Domainname canonical_apex;

        RRSetPtr soa;
        RRSetPtr name_servers;

        void addSOAToAuthoritySection( PacketInfo &res ) const;
        void addEmptyNode( const Domainname & );
    public:
        Zone( const Domainname &apex );

        void add( std::shared_ptr<RRSet> rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;

        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        NodePtr  findNode( const Domainname &domainname ) const;
    };

}

#endif

