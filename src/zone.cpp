#include "zone.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{
    std::string RRSet::toString() const
    {
        std::ostringstream os;

        os << getOwner().toString() << " "
           << getTTL() << " "
           << type_code_to_string( getType() ) << std::endl;

        for ( auto rr : resource_data )
            os << "  " << rr->toString() << std::endl;

        return os.str();
    }

    std::ostream &operator<<( std::ostream &os, const RRSet &rrset )
    {
        os << rrset.toString();
        return os;
    }


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
                if ( response.isDNSSECOK() ) {
                    if ( auto rrsigs = node->find( TYPE_RRSIG ) ) {
                        addRRSIG( response.answer_section, *rrsigs, qtype );
                    }
                }
                return response;
            }
            else {
                // NoData ( found empty non-terminal or other type )
                response.response_code = NO_ERROR;
                if ( response.isDNSSECOK() ) {
                    auto nsec  = node->find( TYPE_NSEC );
                    auto rrsig = node->find( TYPE_RRSIG );
                    if ( nsec && rrsig ) {
			addRRSet( response.authority_section, *nsec );
                        addRRSIG( response.authority_section, *rrsig, TYPE_NSEC );
                    }
                }
                addSOAToAuthoritySection( response );
                return response;
            }
        }
        
        // NXDOMAIN
        response.response_code = NXDOMAIN;
        addNSECAndRRSIG( response, qname );

        Domainname wildcard = apex;
        wildcard.addSubdomain( "*" );
        addNSECAndRRSIG( response, wildcard );
        addSOAToAuthoritySection( response );

        return response;
    }


    Zone::RRSetPtr Zone::findRRSet( const Domainname &name, Type type ) const
    {
        auto node = findNode( name );
        if ( node )
            return node->find( type );
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

        ResourceRecord r;
        r.r_domainname  = soa->getOwner();
        r.r_type        = soa->getType();
        r.r_class       = soa->getClass();
        r.r_ttl         = soa->getTTL();
        for ( auto data_itr = soa->begin() ; data_itr != soa->end() ; data_itr++ ) {
            r.r_resource_data = *data_itr;
        }
        response.authority_section.push_back( r );

        if ( response.isDNSSECOK() ) {
            auto apex_node = findNode( apex );
            if ( auto rrsigs = apex_node->find( TYPE_RRSIG ) ) {
                addRRSIG( response.authority_section, *rrsigs, TYPE_SOA );
            }
        }

    }

    void Zone::addRRSet( std::vector<ResourceRecord> &section, const RRSet &rrset ) const
    {
	for ( auto data_itr = rrset.begin() ; data_itr != rrset.end() ; data_itr++ ) {
	    ResourceRecord r;
	    r.r_domainname  = rrset.getOwner();
	    r.r_type        = rrset.getType();
	    r.r_class       = rrset.getClass();
	    r.r_ttl         = rrset.getTTL();
	    r.r_resource_data = *data_itr;
	    section.push_back( r );
	}
    }

    void Zone::addRRSetToAnswerSection( PacketInfo &response, const RRSet &rrset ) const
    {
        addRRSet( response.answer_section, rrset );
    }

    void Zone::verify() const
    {
        if ( soa.get() == nullptr )
            throw ZoneError( "No SOA record" );

        if ( name_servers.get() == nullptr )
            throw ZoneError( "No NS records" );
    }


    void Zone::addRRSIG( std::vector<ResourceRecord> &section,
                         const RRSet &rrsigs,
                         Type type_covered ) const
    {
        for( auto rrsig : rrsigs ) {
            if ( std::dynamic_pointer_cast<RecordRRSIG>( rrsig )->getTypeCovered() == type_covered ) {
                ResourceRecord r;
                r.r_domainname  = rrsigs.getOwner();
                r.r_type        = rrsigs.getType();
                r.r_class       = rrsigs.getClass();
                r.r_ttl         = rrsigs.getTTL();
                r.r_resource_data = rrsig;
                section.push_back( r );
            }
        }
    }

    void Zone::addNSECAndRRSIG( PacketInfo &response, const Domainname &name ) const
    {
        if ( ! response.isDNSSECOK() )
            return;
        if ( owner_to_node.empty() )
            throw std::logic_error( "zone is emptry" );

        for ( auto node = owner_to_node.begin() ; node != owner_to_node.end() ; node++ ) {
	    auto nsec  = node->second->find( TYPE_NSEC );
	    auto rrsig = node->second->find( TYPE_RRSIG );
	    if ( nsec ) {
		if ( ! rrsig ) {
		    throw std::runtime_error( "not found RRSIG for NSEC RR" );
		}
		
		if ( nsec->count() > 0 &&
		     nsec->getOwner() < name &&
		     name < std::dynamic_pointer_cast<const RecordNSEC>( (*nsec)[0] )->getNextDomainname() ) {
                    if( nsec && rrsig ) {
                        addRRSet( response.authority_section, *nsec );
                        addRRSIG( response.authority_section, *rrsig, TYPE_NSEC );
                    }
                }
            }
        }
    }

}

