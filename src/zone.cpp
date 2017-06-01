#include "zone.hpp"

namespace dns
{
    Zone::Zone( const Domainname &apex )
        : canonical_apex( apex.getCanonicalDomainname() )
    {
	owner_to_node.insert( OwnerToNodePair( canonical_apex, std::shared_ptr<Node>( new Node ) ) );
    }

    void Zone::addEmptyNode( const Domainname &domainname )
    {
        owner_to_node.insert( OwnerToNodePair( domainname.getCanonicalDomainname(),
                                               NodePtr( new Node ) ) );
    }

    void Zone::add( RRSetPtr rrset )
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
	    if ( ! findNode( node_name ) )
                addEmptyNode( node_name );
	}
	auto node = findNode( canonical_owner );
	node->add( rrset );
    }

    PacketInfo Zone::getAnswer( const PacketInfo &query ) const
    {
        if ( query.question_section.size() != 1 ) {
            throw std::logic_error( "one qname must be exist" );
        }

        Domainname qname  = query.question_section[0].q_domainname;
        Type       qtype  = query.question_section[0].q_type;
        Class      qclass = query.question_section[0].q_class;

        PacketInfo response;

        response.id                   = query.id;
        response.opcode               = query.opcode;
        response.query_response       = 1;
        response.authoritative_answer = 1;
        response.truncation           = 0;
        response.recursion_desired    = query.recursion_desired;
        response.recursion_available  = 0;
        response.zero_field           = 0;
        response.authentic_data       = 1;
        response.checking_disabled    = query.checking_disabled;

        QuestionSectionEntry q;
        q.q_domainname = qname;
        q.q_type       = qtype;
        q.q_class      = qclass;
        response.question_section.push_back( q );

        if ( ! canonical_apex.isSubDomain( qname ) ) {
            response.response_code = REFUSED;
            return response;
        }

        // find qname
        auto node = findNode( qname );
        if ( node ) {
            auto rrset = node->find( qtype );
            if ( rrset ) {
                // found 
                for ( auto data_itr = rrset->begin() ; data_itr != rrset->end() ; data_itr++ ) {
                    ResponseSectionEntry r;
                    r.r_domainname  = rrset->getOwner();
                    r.r_type        = rrset->getType();
                    r.r_class       = rrset->getClass();
                    r.r_ttl         = rrset->getTTL();
                    r.r_resource_data = *data_itr;
                    response.authority_section.push_back( r );                 
                }

                return response;
            }
            else {
                // NoData ( found empty non-terminal or other type )
                response.response_code = NO_ERROR;
                addSOAToAuthoritySection( response );
                return response;
            }
        }
        
        // NXDOMAIN
        response.response_code = NXDOMAIN;
        addSOAToAuthoritySection( response );
        return response;
    }


    Zone::RRSetPtr Zone::findRRSet( const Domainname &name, Type type ) const
    {
        auto node = findNode( name );
        if ( node )
            node->find( type );
        return RRSetPtr();
    }

    Zone::NodePtr Zone::findNode( const Domainname &name ) const
    {
        auto node = owner_to_node.find( name.getCanonicalDomainname() );
        if ( node != owner_to_node.end() ) {
            return node->second;
        }
        return NodePtr();
    }

    void Zone::addSOAToAuthoritySection( PacketInfo &response ) const
    {
        if ( ! soa || soa->count() != 1 )
            throw std::logic_error( "SOA record must be exist in zone" );

        ResponseSectionEntry r;
        r.r_domainname  = soa->getOwner();
        r.r_type        = soa->getType();
        r.r_class       = soa->getClass();
        r.r_ttl         = soa->getTTL();
        for ( auto data_itr = soa->begin() ; data_itr != soa->end() ; data_itr++ ) {
            r.r_resource_data = *data_itr;
        }
        response.authority_section.push_back( r );
    }
}

