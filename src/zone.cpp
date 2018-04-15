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
           << typeCodeToString( getType() ) << std::endl;

        for ( auto rr : mResourceData )
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
        auto rrset_itr = mRRSets.find( t );
        if ( rrset_itr == mRRSets.end() )
            return RRSetPtr();
        return rrset_itr->second;
    }

    Zone::Zone( const Domainname &zone_name )
	: mApex( zone_name )
    {
	mOwnerToNode.insert( OwnerToNodePair( mApex, NodePtr( new Node ) ) );
    }

    void Zone::addEmptyNode( const Domainname &domainname )
    {
	mOwnerToNode.insert( OwnerToNodePair( domainname, NodePtr( new Node ) ) );
    }

    void Zone::add( RRSetPtr rrset )
    {
	Domainname owner = rrset->getOwner();
	if ( ! mApex.isSubDomain( owner ) ) {
	    throw std::runtime_error( "owner " + owner.toString() + "is not contained in " + mApex.toString() );
	}

	Domainname relative_name = mApex.getRelativeDomainname( owner );
	Domainname node_name     = mApex;
	for ( auto r = relative_name.getCanonicalLabels().rbegin() ; r != relative_name.getCanonicalLabels().rend() ; ++r ) {
	    node_name.addSubdomain( *r );
	    if ( ! findNode( node_name ) )
		addEmptyNode( node_name );
	}
	auto node = findNode( owner );
	if ( node.get() == nullptr )
	    throw std::logic_error( "node must be exist" );
	node->add( rrset );

	if ( rrset->getType() == TYPE_SOA && rrset->getOwner() == mApex ) {
	    mSOA = rrset;
	}
	if ( rrset->getType() == TYPE_NS && rrset->getOwner() == mApex ) {
	    mNameServers = rrset;
	}
	
    }

    PacketInfo Zone::getAnswer( const PacketInfo &query ) const
    {
	if ( query.getQuestionSection().size() != 1 ) {
	    throw std::logic_error( "one qname must be exist" );
	}
	
	Domainname qname  = query.getQuestionSection()[0].mDomainname;
	Type       qtype  = query.getQuestionSection()[0].mType;
	Class      qclass = query.getQuestionSection()[0].mClass;

	PacketInfo response;

	response.mID                  = query.mID;
	response.mOpcode              = query.mOpcode;
	response.mQueryResponse       = 1;
	response.mAuthoritativeAnswer = 1;
	response.mTruncation          = 0;
	response.mRecursionDesired    = query.mRecursionDesired;
	response.mRecursionAvailable  = 0;
	response.mZeroField           = 0;
	response.mAuthenticData       = 1;
	response.mCheckingDisabled    = query.mCheckingDisabled;

	if ( query.isEDNS0() ) {
	    OptPseudoRecord opt;
	    opt.mPayloadSize = std::min<uint16_t>( 1280, query.mOptPseudoRR.mPayloadSize );
	    opt.mDOBit = query.mOptPseudoRR.mDOBit;
	    response.mIsEDNS0 = true;
	    response.mOptPseudoRR = opt;
	}

	QuestionSectionEntry q;
	q.mDomainname = qname;
	q.mType       = qtype;
	q.mClass      = qclass;
	response.pushQuestionSection( q );

	if ( ! mApex.isSubDomain( qname ) ) {
	    response.mResponseCode = REFUSED;
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
		    response.mResponseCode = NO_ERROR;
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
			addRRSIG( response.mAnswerSection, *rrsigs, qtype );
		    }
		}
		return response;
	    }
	    else {
		// NoData ( found empty non-terminal or other type )
		response.mResponseCode = NO_ERROR;
		if ( response.isDNSSECOK() ) {
		    auto nsec  = node->find( TYPE_NSEC );
		    auto rrsig = node->find( TYPE_RRSIG );
		    if ( nsec && rrsig ) {
			addRRSet( response.mAuthoritySection, *nsec );
			addRRSIG( response.mAuthoritySection, *rrsig, TYPE_NSEC );
		    }
		}
		addSOAToAuthoritySection( response );
		return response;
	    }
	}
        
	// NXDOMAIN
	response.mResponseCode = NXDOMAIN;
	addNSECAndRRSIG( response, qname );

	Domainname wildcard = mApex;
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
	auto node = mOwnerToNode.find( name );
	if ( node != mOwnerToNode.end() ) {
	    return node->second;
	}
	return NodePtr();
    }

    void Zone::addSOAToAuthoritySection( PacketInfo &response ) const
    {
	if ( ! mSOA || mSOA->count() != 1 )
	    throw std::logic_error( "SOA record must be exist in zone" );

	ResourceRecord r;
	r.mDomainname = mSOA->getOwner();
	r.mType       = mSOA->getType();
	r.mClass      = mSOA->getClass();
	r.mTTL        = mSOA->getTTL();
	for ( auto data_itr = mSOA->begin() ; data_itr != mSOA->end() ; data_itr++ ) {
	    r.mRData = *data_itr;
	}
	response.pushAuthoritySection( r );

	if ( response.isDNSSECOK() ) {
	    auto apex_node = findNode( mApex );
	    if ( auto rrsigs = apex_node->find( TYPE_RRSIG ) ) {
		addRRSIG( response.mAuthoritySection, *rrsigs, TYPE_SOA );
	    }
	}

    }

    void Zone::addRRSet( std::vector<ResourceRecord> &section, const RRSet &rrset ) const
    {
	for ( auto data_itr = rrset.begin() ; data_itr != rrset.end() ; data_itr++ ) {
	    ResourceRecord r;
	    r.mDomainname = rrset.getOwner();
	    r.mType       = rrset.getType();
	    r.mClass      = rrset.getClass();
	    r.mTTL        = rrset.getTTL();
	    r.mRData      = *data_itr;
	    section.push_back( r );
	}
    }

    void Zone::addRRSetToAnswerSection( PacketInfo &response, const RRSet &rrset ) const
    {
	addRRSet( response.mAnswerSection, rrset );
    }

    void Zone::verify() const
    {
	if ( mSOA.get() == nullptr )
	    throw ZoneError( "No SOA record" );

	if ( mNameServers.get() == nullptr )
	    throw ZoneError( "No NS records" );
    }


    void Zone::addRRSIG( std::vector<ResourceRecord> &section,
			 const RRSet &rrsigs,
			 Type type_covered ) const
    {
	for( auto rrsig : rrsigs ) {
	    if ( std::dynamic_pointer_cast<RecordRRSIG>( rrsig )->getTypeCovered() == type_covered ) {
		ResourceRecord r;
		r.mDomainname = rrsigs.getOwner();
		r.mType       = rrsigs.getType();
		r.mClass      = rrsigs.getClass();
		r.mTTL        = rrsigs.getTTL();
		r.mRData      = rrsig;
		section.push_back( r );
	    }
	}
    }

    void Zone::addNSECAndRRSIG( PacketInfo &response, const Domainname &name ) const
    {
	if ( ! response.isDNSSECOK() )
	    return;
	if ( mOwnerToNode.empty() )
	    throw std::logic_error( "zone is emptry" );

	for ( auto node = mOwnerToNode.begin() ; node != mOwnerToNode.end() ; node++ ) {
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
			addRRSet( response.mAuthoritySection, *nsec );
			addRRSIG( response.mAuthoritySection, *rrsig, TYPE_NSEC );
		    }
		}
	    }
	}
    }

}
