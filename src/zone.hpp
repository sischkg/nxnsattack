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
        Domainname mOwner;
        Class      mClass;
        Type       mType;
        TTL        mTTL;
        RDATAContainer mResourceData;

    public:
        RRSet( const Domainname &name, Class c, Type t, TTL tt )
            : mOwner( name ), mClass( c ), mType( t ), mTTL( tt )
        {}

        const Domainname &getOwner() const { return mOwner; }
        Domainname getCanonicalOwer() const { return mOwner.getCanonicalDomainname(); }

        Class getClass() const { return mClass; }
        Type  getType()  const { return mType; }
        TTL   getTTL()   const { return mTTL; } 
        uint16_t count() const { return mResourceData.size(); }
        std::string toString() const;

        RDATAContainer::const_iterator begin() const { return mResourceData.begin(); }
        RDATAContainer::const_iterator end()   const { return mResourceData.end(); }

	RDATAPtr operator[]( int index ) { return mResourceData[index]; }
	ConstRDATAPtr operator[]( int index ) const { return mResourceData[index]; }
       	const RDATAContainer &getRRSet() const { return mResourceData; }

        RRSet &add( RDATAPtr data ) { mResourceData.push_back( data ); return *this; }

        void addResourceRecords( std::vector<ResourceRecord> &section ) const;
    };

    std::ostream &operator<<( std::ostream &os, const RRSet &rrset );

    class Node
    {
    public:
        typedef std::shared_ptr<RRSet>    RRSetPtr;
        typedef std::map<Type,  RRSetPtr> RRSetContainer;
        typedef std::pair<Type, RRSetPtr> RRSetPair;

    private:
        RRSetContainer mRRSets;

    public:
        RRSetContainer::iterator begin() { return mRRSets.begin(); }
        RRSetContainer::iterator end()   { return mRRSets.end(); }
        RRSetPtr find( Type t ) const;

        RRSetContainer::const_iterator begin() const { return mRRSets.begin(); }
        RRSetContainer::const_iterator end()   const { return mRRSets.end(); }

        bool empty( Type t ) const { return ! find( t ); }
        bool exist( Type t ) const { return ! empty( t ); } 
        bool empty() const { return   mRRSets.empty(); }
        bool exist() const { return ! mRRSets.empty(); }

        Node &add( std::shared_ptr<RRSet> rrset ) { mRRSets.insert( RRSetPair( rrset->getType(), rrset ) ); return *this; }
    };

    class Zone
    {
    public:
        typedef std::shared_ptr<Node>  NodePtr;
        typedef std::shared_ptr<RRSet> RRSetPtr;

        virtual ~Zone() {}
 
        virtual void add( std::shared_ptr<RRSet> rrset ) = 0;
        virtual MessageInfo getAnswer( const MessageInfo &query ) const = 0;
        virtual NodePtr  findNode( const Domainname &domainname ) const = 0;
        virtual RRSetPtr findRRSet( const Domainname &domainname, Type type ) const = 0;
	virtual std::vector<std::shared_ptr<RecordDS>> getDSRecords() const = 0;
        virtual void verify() const = 0;
    };
}

#endif

