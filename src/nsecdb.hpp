#ifndef NSECDB_HPP
#define NSECDB_HPP

#include "dns.hpp"
#include "zone.hpp"
#include <map>

namespace dns
{
    class NSECDB
    {
	typedef std::map<Domainname, std::vector<Type>> Container;
    public:
	NSECDB( const Domainname &apex )
	    : mApex( apex )
	{}

	void addNode( const Domainname &name, const Node &node );
	ResourceRecord findNSEC( const Domainname &name, TTL ttl ) const;
    private:
	Domainname mApex;
	Container mNSECEntries;
    };

}

#endif
