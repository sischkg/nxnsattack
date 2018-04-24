#include "nsecdb.hpp"
#include "zonesignerimp.hpp"

namespace dns
{

    void NSECDB::addNode( const Domainname &owner, const Node &node )
    {
	std::vector<Type> types;
	for ( auto rrset = node.begin() ; rrset != node.end() ; rrset++ ) {
	    types.push_back( rrset->second->getType() );
	}
	types.push_back( TYPE_NSEC );
	types.push_back( TYPE_RRSIG );

	auto nsec_entry = mNSECEntries.find( owner );
	if ( nsec_entry == mNSECEntries.end() ) {
	    std::pair<Domainname, std::vector<Type>> pair( owner, types );
	    mNSECEntries.insert( pair );
	}
	else {
	    std::ostringstream os;
	    os << "detected duplicated nodes\"" << owner << "\"";
	    throwException( os.str() );
	}
    }


    ResourceRecord NSECDB::findNSEC( const Domainname &name, TTL ttl ) const
    {
        if ( mNSECEntries.empty() )
            throw std::logic_error( "nsec must not be empty" );

	Domainname owner, next_name;
	std::vector<Type> types;
	auto nsec_entry = mNSECEntries.lower_bound( name );

        if ( nsec_entry == mNSECEntries.end() ) {
            nsec_entry--;
	    owner = nsec_entry->first.getCanonicalDomainname();
	    types = nsec_entry->second;
	    next_name = mNSECEntries.begin()->first.getCanonicalDomainname();
        }
        else if ( nsec_entry->first == name ) {
	    owner = nsec_entry->first.getCanonicalDomainname();
	    types = nsec_entry->second;
            nsec_entry++;
            if ( nsec_entry == mNSECEntries.end() )
                nsec_entry = mNSECEntries.begin();
	    next_name = nsec_entry->first.getCanonicalDomainname();
        }
        else if ( nsec_entry == mNSECEntries.begin() ) {
	    auto last = mNSECEntries.end();
	    last--;
	    owner = last->first.getCanonicalDomainname();
	    types = last->second;
	    next_name = mNSECEntries.begin()->first.getCanonicalDomainname();
        }
        else {
	    next_name = nsec_entry->first.getCanonicalDomainname();
            nsec_entry--;
	    owner = nsec_entry->first.getCanonicalDomainname();
	    types = nsec_entry->second;
        }

	ResourceRecord rr;
	rr.mDomainname = owner;
	rr.mClass      = CLASS_IN;
	rr.mType       = TYPE_NSEC;
	rr.mTTL        = ttl;
	rr.mRData      = RDATAPtr( new RecordNSEC( next_name, types ) );
	return rr;
    }
}

