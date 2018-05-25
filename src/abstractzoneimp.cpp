#include "abstractzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    AbstractZoneImp::AbstractZoneImp( const Domainname &zone_name )
        : mApex( zone_name )
    {
	mOwnerToNode.insert( OwnerToNodePair( mApex, NodePtr( new Node ) ) );
    }

    void AbstractZoneImp::addEmptyNode( const Domainname &domainname )
    {
        mOwnerToNode.insert( OwnerToNodePair( domainname, NodePtr( new Node ) ) );
    }

    void AbstractZoneImp::add( RRSetPtr rrset )
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

    PacketInfo AbstractZoneImp::getAnswer( const PacketInfo &query ) const
    {
        if ( query.mQuestionSection.size() != 1 ) {
            throw std::logic_error( "one qname must be exist" );
        }
	
        Domainname qname  = query.mQuestionSection[0].mDomainname;
        Type       qtype  = query.mQuestionSection[0].mType;
        Class      qclass = query.mQuestionSection[0].mClass;

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
        response.mQuestionSection.push_back( q );

        if ( ! mApex.isSubDomain( qname ) ) {
            response.mResponseCode = REFUSED;
            return response;
        }

        if ( qtype == TYPE_RRSIG ) {
	    responseRRSIG( qname, response );
	    return response;
        }

        if ( qtype == TYPE_NSEC ) {
	    responseNSEC( qname, response );
	    return response;
        }

        // find DNAME
        for ( auto parent_name = qname ; parent_name != mApex ; parent_name.popSubdomain() ) {
            auto dname_rrset = findRRSet( parent_name, TYPE_DNAME );
            if ( dname_rrset ) {
                if ( dname_rrset->count() != 1 )
                    throw std::logic_error( "multiple DNAME records exist " + parent_name.toString() );
                response.mResponseCode = NO_ERROR;
                addRRSet( response.mAnswerSection, *dname_rrset );
		addRRSIG( response, response.mAnswerSection, *dname_rrset );

                auto dname_rdata    = std::dynamic_pointer_cast<RecordDNAME>( (*dname_rrset)[0] );
                auto relative_name  = parent_name.getRelativeDomainname( qname );
                auto canonical_name = relative_name + dname_rdata->getCanonicalName();
                std::shared_ptr<RecordCNAME> cname_rdata( new RecordCNAME( canonical_name ) );
                RRSet cname_rrset( canonical_name, dname_rrset->getClass(), TYPE_CNAME, dname_rrset->getTTL() );
                cname_rrset.add( cname_rdata );

                addRRSet( response.mAnswerSection, cname_rrset );
		addRRSIG( response, response.mAnswerSection, cname_rrset );

                auto canonical_node  = findNode( canonical_name );
                if ( canonical_node ) {
                    auto canonical_rrset = canonical_node->find( qtype );
                    if ( canonical_rrset ) {
                        addRRSet( response.mAnswerSection, *canonical_rrset );
			addRRSIG( response, response.mAnswerSection, *canonical_rrset );
                    }
                }
                return response;
            }   
        }

        // find NS record for delegation.
        if ( qname != mApex ) {
            for ( auto parent = qname ; parent != mApex ; parent.popSubdomain() ) {
                auto rrset = findRRSet( parent, TYPE_NS );
                if ( rrset ) {
                    responseDelegation( qname, response, *rrset );
                    return response;
                }
            }
        }
        
	// find qname
        auto node = findNode( qname );
        if ( node ) {
	    if ( qtype == TYPE_ANY ) {
		if ( node->exist() ) {
		    for ( auto rrset_itr = node->begin() ; rrset_itr != node->end() ; rrset_itr++ ) {
                        auto rrset = *(rrset_itr->second);
                        addRRSet( response.mAnswerSection, rrset );
			addRRSIG( response, response.mAnswerSection, rrset );
                    }
                    RRSetPtr nsec = generateNSECRRSet( qname );
                    if ( nsec ) {
                        addRRSet( response.mAnswerSection, *nsec );
                        addRRSIG( response, response.mAnswerSection, *nsec );
                    }
		}
		else {
		    // NoData ( found empty non-terminal )
		    responseNoData( qname, response, false );
		}
		return response;
	    }
            auto cname_rrset = node->find( TYPE_CNAME );
            if ( cname_rrset ) {
                if ( cname_rrset->count() != 1 ) {
                    throw std::logic_error( "muliple cname records exist in " + qname.toString() );
                }
                
                // found 
                response.mResponseCode = NO_ERROR;
                addRRSet( response.mAnswerSection, *cname_rrset );
		addRRSIG( response, response.mAnswerSection, *cname_rrset );

                std::shared_ptr<RecordCNAME> cname = std::dynamic_pointer_cast<RecordCNAME>( (*cname_rrset)[0] );
                auto canonical_name = cname->getCanonicalName();
                if (mApex.isSubDomain( canonical_name ) ) {
                    auto canonical_node  = findNode( canonical_name );
                    auto canonical_rrset = canonical_node->find( qtype );
                    if ( canonical_rrset ) {
                        addRRSet( response.mAnswerSection, *canonical_rrset );
			addRRSIG( response, response.mAnswerSection, *canonical_rrset );
                    }
                }
                return response;
            }

            auto rrset = node->find( qtype );
            if ( rrset ) {
                // found 
                response.mResponseCode = NO_ERROR;
                addRRSet( response.mAnswerSection, *rrset );
		addRRSIG( response, response.mAnswerSection, *rrset );
                return response;
            }
            else {
                // NoData ( found empty non-terminal or other type )
		responseNoData( qname, response, node->exist() );
		return response;
            }
        }

        // NXDOMAIN
	responseNXDomain( qname, response );
        return response;
    }

    std::vector<std::shared_ptr<RecordDS>> AbstractZoneImp::getDSRecords() const
    {
	return std::vector<std::shared_ptr<RecordDS>>();
    }

    AbstractZoneImp::RRSetPtr AbstractZoneImp::findRRSet( const Domainname &domainname, Type type ) const
    {
        auto node = findNode( domainname );
        if ( node )
            return node->find( type );
        return RRSetPtr();
    }

    AbstractZoneImp::NodePtr AbstractZoneImp::findNode( const Domainname &name ) const
    {
        auto node = mOwnerToNode.find( name );
        if ( node != mOwnerToNode.end() ) {
            return node->second;
        }
        return NodePtr();
    }

    void AbstractZoneImp::addSOAToAuthoritySection( PacketInfo &response ) const
    {
        if ( ! mSOA || mSOA->count() != 1 )
            throw std::logic_error( "SOA record must be exist in zone" );

        addRRSet( response.mAuthoritySection, *mSOA );
        if ( response.isDNSSECOK() ) {
	    addRRSIG( response, response.mAuthoritySection, *mSOA );
        }

    }

    void AbstractZoneImp::responseDelegation( const Domainname &qname, PacketInfo &response, const RRSet &ns_rrset ) const
    {
        response.mResponseCode        = NO_ERROR;
        response.mAuthoritativeAnswer = 0;

        for ( auto ns : ns_rrset ) {
            ResourceRecord rr;
            rr.mDomainname = ns_rrset.getOwner();
            rr.mClass      = ns_rrset.getClass();
            rr.mType       = ns_rrset.getType();
            rr.mTTL        = ns_rrset.getTTL();
            rr.mRData      = ns;

            response.pushAuthoritySection( rr );

            Domainname nameserver = dynamic_cast<const RecordNS &>( *ns ).getNameServer();
            auto glue_node = findNode( nameserver );
            if ( glue_node ) {
                auto a_rrset = glue_node->find( TYPE_A );
                if ( a_rrset ) {
                    addRRSet( response.mAdditionalSection, *a_rrset );
                }
                auto aaaa_rrset = glue_node->find( TYPE_AAAA );
                if ( aaaa_rrset ) {
                    addRRSet( response.mAdditionalSection, *aaaa_rrset );
                }
            }   
        }
        auto ds_rrset = findRRSet( ns_rrset.getOwner(), TYPE_DS );
        if ( ds_rrset ) {
            addRRSet( response.mAuthoritySection, *ds_rrset );
            addRRSIG( response, response.mAuthoritySection, *ds_rrset );            
        }
    }

    void AbstractZoneImp::addRRSet( std::vector<ResourceRecord> &section, const RRSet &rrset ) const
    {
        rrset.addResourceRecords( section );
    }

    void AbstractZoneImp::verify() const
    {
        if ( mSOA.get() == nullptr )
            throw ZoneError( "No SOA record" );

        if ( mNameServers.get() == nullptr )
            throw ZoneError( "No NS records" );
    }    
}

