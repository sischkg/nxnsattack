#ifndef NSECDB_HPP
#define NSECDB_HPP

#include "dns.hpp"
#include "zone.hpp"
#include <map>

namespace dns
{
    class NSECStorable
    {
    public:
        virtual ~NSECStorable() {}
        virtual void addNode( const Domainname &name, const Node &node ) = 0;
        virtual ResourceRecord find( const Domainname &name, TTL ttl ) const = 0;
    };

    typedef std::shared_ptr<NSECStorable> NSECDBPtr;
    
    class NSECDB : public NSECStorable
    {
	typedef std::map<Domainname, std::vector<Type>> Container;
    public:
	NSECDB( const Domainname &apex )
	    : mApex( apex )
	{}

	void addNode( const Domainname &name, const Node &node );
	ResourceRecord find( const Domainname &name, TTL ttl ) const;
    private:
	Domainname mApex;
	Container  mNSECEntries;
    };

}

#endif
