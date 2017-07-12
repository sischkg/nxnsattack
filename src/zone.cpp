#include "zone.hpp"
#include <algorithm>

namespace dns
{
    Node::RRSetPtr Node::find( Type t ) const
    {
        auto rrset_itr = rrsets.find( t );
        if ( rrset_itr == rrsets.end() )
            return RRSetPtr();
        return rrset_itr->second;
    }


    Zone::Zone( const Domainname &zone_name )
        : apex( zone_name )
    {
	owner_to_node.insert( OwnerToNodePair( apex, NodePtr( new Node ) ) );
    }

    void Zone::addEmptyNode( const Domainname &domainname )
    {
        owner_to_node.insert( OwnerToNodePair( domainname, NodePtr( new Node ) ) );
    }

    void Zone::add( RRSetPtr rrset )
    {
        Domainname owner = rrset->getOwner();
        if ( ! apex.isSubDomain( owner ) ) {
            throw std::runtime_error( "owner " + owner.toString() + "is not contained in " + apex.toString() );
        }

	Domainname relative_name = apex.getRelativeDomainname( owner );
	Domainname node_name     = apex;
	for ( auto r = relative_name.getCanonicalLabels().rbegin() ; r != relative_name.getCanonicalLabels().rend() ; ++r ) {
	    node_name.addSubdomain( *r );
	    if ( ! findNode( node_name ) )
		addEmptyNode( node_name );
	}
	auto node = findNode( owner );
	if ( node.get() == nullptr )
	    throw std::logic_error( "node must be exist" );
	node->add( rrset );

	if ( rrset->getType() == TYPE_SOA && rrset->getOwner() == apex ) {
	    soa = rrset;
	}
	if ( rrset->getType() == TYPE_NS && rrset->getOwner() == apex ) {
	    name_servers = rrset;
	}
	
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

	if ( query.edns0 ) {
	    OptPseudoRecord opt;
	    opt.payload_size = std::min<uint16_t>( 1280, query.opt_pseudo_rr.payload_size );
	    opt.dobit = query.opt_pseudo_rr.dobit;
	    response.edns0 = true;
	    response.opt_pseudo_rr = opt;
	}
	
        QuestionSectionEntry q;
        q.q_domainname = qname;
        q.q_type       = qtype;
        q.q_class      = qclass;
        response.question_section.push_back( q );

        if ( ! apex.isSubDomain( qname ) ) {
            response.response_code = REFUSED;
            return response;
        }

        // find qname
        auto node = findNode( qname );
        if ( node ) {
	    if ( qtype == TYPE_ANY ) {
		if ( node->exist() ) {
		    for ( auto rrset_itr = node->begin() ; rrset_itr != node->end() ; rrset_itr++ ) {
			addRRSetToAnswerSection( response, *(rrset_itr->second) );
		    }
		}
		else {
		    // NoData ( found empty non-terminal )
		    response.response_code = NO_ERROR;
		    addSOAToAuthoritySection( response );
		}
		return response;
	    }
            auto rrset = node->find( qtype );
            if ( rrset ) {
                // found 
		addRRSetToAnswerSection( response, *rrset );
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
        auto node = owner_to_node.find( name );
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

    void Zone::addRRSetToAnswerSection( PacketInfo &response, const RRSet &rrset ) const
    {
	for ( auto data_itr = rrset.begin() ; data_itr != rrset.end() ; data_itr++ ) {
	    ResponseSectionEntry r;
	    r.r_domainname  = rrset.getOwner();
	    r.r_type        = rrset.getType();
	    r.r_class       = rrset.getClass();
	    r.r_ttl         = rrset.getTTL();
	    r.r_resource_data = *data_itr;
	    response.answer_section.push_back( r );
	}
    }

    void Zone::verify() const
    {
        if ( soa.get() == nullptr )
            throw ZoneError( "No SOA record" );

        if ( name_servers.get() == nullptr )
            throw ZoneError( "No NS records" );
    }
}

