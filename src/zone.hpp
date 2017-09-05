#ifndef ZONE_HPP
#define ZONE_HPP

#include "dns.hpp"
#include <map>
#include <vector>

namespace dns
{
    class ZoneError : std::runtime_error
    {
    public:
        ZoneError( const std::string &msg )
            : std::runtime_error( msg )
        {}
    };

    class RRSet
    {
    public:
        typedef std::vector<RDATAPtr> RDATAContainer;
  
    private:
        Domainname owner;
        Class      klass;
        Type       type;
        TTL        ttl;
        RDATAContainer resource_data;

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
        std::string toString() const;

        RDATAContainer::const_iterator begin() const { return resource_data.begin(); }
        RDATAContainer::const_iterator end()   const { return resource_data.end(); }

	RDATAPtr operator[]( int index ) { return resource_data[index]; }
	ConstRDATAPtr operator[]( int index ) const { return resource_data[index]; }
	const RDATAContainer &getRRSet() const { return resource_data; }

        void add( RDATAPtr data ) { resource_data.push_back( data ); }
    };

    std::ostream &operator<<( std::ostream &os, const RRSet &rrset );

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
        bool empty() const { return   rrsets.empty(); }
        bool exist() const { return ! rrsets.empty(); }

        void add( std::shared_ptr<RRSet> rrset ) { rrsets.insert( RRSetPair( rrset->getType(), rrset ) ); }
    };

    class AbstractZone
    {
    public:
        typedef std::shared_ptr<RRSet> RRSetPtr;

        virtual ~AbstractZone() {}
 
        virtual void add( std::shared_ptr<RRSet> rrset ) = 0;
        virtual PacketInfo getAnswer( const PacketInfo &query ) const = 0;
        virtual RRSetPtr findRRSet( const Domainname &domainname, Type type ) const = 0;
	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const = 0;
        virtual void verify() const = 0;
    };


    class Zone : public AbstractZone
    {
    private:
        typedef std::shared_ptr<Node>  NodePtr;
	typedef std::map<Domainname,   NodePtr> OwnerToNodeContainer;
	typedef std::pair<Domainname,  NodePtr> OwnerToNodePair;

        OwnerToNodeContainer owner_to_node;
        Domainname           apex;

        RRSetPtr soa;
        RRSetPtr name_servers;

        void addSOAToAuthoritySection( PacketInfo &res ) const;
        void addEmptyNode( const Domainname & );
	void addRRSetToAnswerSection( PacketInfo &response, const RRSet &rrset ) const;
        void addRRSet( std::vector<ResponseSectionEntry> &, const RRSet &rrset ) const;
        void addRRSIG( std::vector<ResponseSectionEntry> &, const RRSet &rrsig, Type covered_type ) const;
	//    	void generateFoundAnswer( PacketInfo &response ) const;
	//	void generateNoDataAnswer( PacketInfo &response ) const;
        void addNSECAndRRSIG( PacketInfo &response, const Domainname & ) const;

    public:
        Zone( const Domainname &zone_name );

        void add( std::shared_ptr<RRSet> rrest );
        PacketInfo getAnswer( const PacketInfo &query ) const;
	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const
        {
            return std::vector<std::shared_ptr<RecordDS> >();
        }

        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
        NodePtr  findNode( const Domainname &domainname ) const;
        OwnerToNodeContainer::const_iterator begin() const { return owner_to_node.begin(); }
        OwnerToNodeContainer::const_iterator end() const   { return owner_to_node.end(); }

	RRSetPtr getSOA() const { return soa; }
	RRSetPtr getNameServer() const { return name_servers; }

        void verify() const;
    };

}

#endif

