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
        typedef std::vector<std::shared_ptr<ResourceData>> ResourceDataContainer;
  
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

        Class getCllass() const { return klass; }
        Type  getType()   const { return type; }
        TTL   getTTL()    const { return ttl; } 

        ResourceDataContainer::const_iterator begin() const { return resource_data.begin(); }
        ResourceDataContainer::const_iterator end()   const { return resource_data.end(); }

        void add( std::shared_ptr<ResourceData> data ) { resource_data.push_back( data ); }
    };


    class Node
    {
    public:
        typedef std::map<Type, std::shared_ptr<RRSet>>  RRSetContainer;
        typedef std::pair<Type, std::shared_ptr<RRSet>> RRSetPair;

    private:
        RRSetContainer rrsets;

    public:
        RRSetContainer::iterator begin() { return rrsets.begin(); }
        RRSetContainer::iterator end()   { return rrsets.end(); }
        RRSetContainer::iterator find( Type t ) { return rrsets.find( t ); }

        RRSetContainer::const_iterator begin() const { return rrsets.begin(); }
        RRSetContainer::const_iterator end()   const { return rrsets.end(); }
        RRSetContainer::const_iterator find( Type t ) const { return rrsets.find( t ); }

        bool exist( Type t ) const { return find( t ) != end(); } 
        bool empty( Type t ) const { return find( t ) == end(); }

        void add( std::shared_ptr<RRSet> rrset ) { rrsets.insert( RRSetPair( rrset->getType(), rrset ) ); }
    };


    class Response
    {
    public:
        enum ResponseType {
            SUCCESS,
            REFERRAL,
            NODATA,
            NXDOMAIN,
        };

        ResponseType response_type;
    private:
        std::vector<std::shared_ptr<ResourceData>> answers;

    public:
        Response( ResponseType type,
                  const std::vector<std::shared_ptr<ResourceData>> &a = std::vector<std::shared_ptr<ResourceData>>() )
            : response_type( type ), answers( a )
        {}

        ResponseType getResponseType() const { return response_type; }
        std::vector<std::shared_ptr<ResourceData>> getAnswers() const { return answers; }
    };


    class Zone
    {
    private:
	typedef std::map<Domainname, std::shared_ptr<Node>> OwnerToNodeContainer;
	typedef std::pair<Domainname, std::shared_ptr<Node>> OwnerToNodePair;

        OwnerToNodeContainer owner_to_node;
        Domainname canonical_apex;

        std::shared_ptr<ResourceData> soa;
        std::vector<std::shared_ptr<ResourceData>> name_servers;
    public:
        Zone( const Domainname &apex );

        void add( std::shared_ptr<RRSet> rrest );
        Response find( const Domainname &qname, Type qtype ) const;

        std::shared_ptr<ResourceData> getSOA() const { return soa; }
        std::vector<std::shared_ptr<ResourceData>> getNameServers() const { return name_servers; }        
    };

}

#endif

