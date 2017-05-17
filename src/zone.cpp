#include "zone.hpp"

namespace dns
{
    Zone::Zone( const Domainname &apex )
        : canonical_apex( apex.getCanonicalDomainname() )
    {
	owner_to_node.insert( OwnerToNodePair( canonical_apex, std::shared_ptr<Node>( new Node ) ) );
    }

    void Zone::add( std::shared_ptr<RRSet> rrset )
    {
        Domainname owner = rrset->getOwner();
	if ( ! canonical_apex.isSubDomain( owner ) ) {
	    throw std::runtime_error( "owner " + owner.toString() + "is not contained in " + canonical_apex.toString() );
	}

	Domainname canonical_owner = owner.getCanonicalDomainname();
	Domainname relative_name = canonical_apex.getRelativeDomainname( canonical_owner );
	Domainname node_name = canonical_apex;
	for ( auto r = relative_name.getLabels().rbegin() ; r != relative_name.getLabels().rend() ; ++r ) {
	    node_name.addSubdomain( *r );
	    if ( owner_to_node.find( node_name ) == owner_to_node.end() )
		owner_to_node.insert( OwnerToNodePair( node_name, std::shared_ptr<Node>( new Node ) ) );
	}
	auto node = owner_to_node.find( canonical_owner );
	node->second->add( rrset );
    }

}

