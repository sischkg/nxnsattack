#include "unsignedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    UnsignedZoneImp::UnsignedZoneImp( const Domainname &zone_name )
        : mApex( zone_name )
    {
	mOwnerToNode.insert( OwnerToNodePair( mApex, NodePtr( new Node ) ) );
    }

    void UnsignedZoneImp::addEmptyNode( const Domainname &domainname )
    {
        mOwnerToNode.insert( OwnerToNodePair( domainname, NodePtr( new Node ) ) );
    }

    void UnsignedZoneImp::add( RRSetPtr rrset )
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

    PacketInfo UnsignedZoneImp::getAnswer( const PacketInfo &query ) const
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

	// QTYPE == DNSKEY, return NODATAr
	if ( qtype == TYPE_DNSKEY && qname == mApex ) {
	    response.mResponseCode = NO_ERROR;
	    addSOAToAuthoritySection( response );
	    return response;
	}

        if ( qtype == TYPE_RRSIG ) {
            auto node = findNode( qname );
            if ( node ) {
		response.mResponseCode = NO_ERROR;
		addSOAToAuthoritySection( response );
		return response;
            }
            else {
                // NXDOMAIN
                response.mResponseCode = NXDOMAIN;
                addSOAToAuthoritySection( response );
                return response;
            }
        }

        // find DNAME
        for ( auto parent_name = qname ; parent_name != mApex ; parent_name.popSubdomain() ) {
            auto dname_rrset = findRRSet( parent_name, TYPE_DNAME );
            if ( dname_rrset ) {
                if ( dname_rrset->count() != 1 )
                    throw std::logic_error( "multiple DNAME records exist " + parent_name.toString() );
                response.mResponseCode = NO_ERROR;
                addRRSet( response.mAnswerSection, *dname_rrset );

                auto dname_rdata    = std::dynamic_pointer_cast<RecordDNAME>( (*dname_rrset)[0] );
                auto relative_name  = parent_name.getRelativeDomainname( qname );
                auto canonical_name = relative_name + dname_rdata->getCanonicalName();
                std::shared_ptr<RecordCNAME> cname_rdata( new RecordCNAME( canonical_name ) );
                RRSet cname_rrset( canonical_name, dname_rrset->getClass(), TYPE_CNAME, dname_rrset->getTTL() );
                cname_rrset.add( cname_rdata );

                addRRSet( response.mAnswerSection, cname_rrset );

                auto canonical_node  = findNode( canonical_name );
                if ( canonical_node ) {
                    auto canonical_rrset = canonical_node->find( qtype );
                    if ( canonical_rrset ) {
                        addRRSet( response.mAnswerSection, *canonical_rrset );
                    }
                }
                return response;
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
		    }
		}
		else {
		    // NoData ( found empty non-terminal )
		    response.mResponseCode = NO_ERROR;
		    addSOAToAuthoritySection( response );
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
                std::shared_ptr<RecordCNAME> cname = std::dynamic_pointer_cast<RecordCNAME>( (*cname_rrset)[0] );
                auto canonical_name = cname->getCanonicalName();
                if (mApex.isSubDomain( canonical_name ) ) {
                    auto canonical_node  = findNode( canonical_name );
                    auto canonical_rrset = canonical_node->find( qtype );
                    if ( canonical_rrset ) {
                        addRRSet( response.mAnswerSection, *canonical_rrset );
                    }
                }
                return response;
            }

            auto rrset = node->find( qtype );
            if ( rrset ) {
                // found 
                response.mResponseCode = NO_ERROR;
                addRRSet( response.mAnswerSection, *rrset );
                return response;
            }
            else {
                // NoData ( found empty non-terminal or other type )
                response.mResponseCode = NO_ERROR;
                addSOAToAuthoritySection( response );
		return response;
            }
        }

        for ( auto parent = qname ; parent != mApex ; parent.popSubdomain() ) {
            auto node = findNode( parent );
            if ( node ) {
                auto ns_rrset = node->find( TYPE_NS );
                if ( ns_rrset ) {
                    response.mResponseCode = NO_ERROR;
                    addRRSet( response.mAuthoritySection, *ns_rrset );
                    for ( auto ns : *ns_rrset ) {
                        auto glue_node = findNode( dynamic_cast<const RecordNS &>( *ns ).getNameServer() );
                        if ( glue_node ) {
                            if ( auto glue_a_rrset = glue_node->find( TYPE_A ) )
                                addRRSet( response.mAdditionalSection, *glue_a_rrset );
                            if ( auto glue_aaaa_rrset = glue_node->find( TYPE_AAAA ) )
                                addRRSet( response.mAdditionalSection, *glue_aaaa_rrset );
                        }
                    } 
                    return response;
                }
            }
        }
        
        // NXDOMAIN
        response.mResponseCode = NXDOMAIN;
        addSOAToAuthoritySection( response );

        return response;
    }

    std::vector<std::shared_ptr<RecordDS>> UnsignedZoneImp::getDSRecords() const
    {
	return std::vector<std::shared_ptr<RecordDS>>();
    }

    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::findRRSet( const Domainname &domainname, Type type ) const
    {
        auto node = findNode( domainname );
        if ( node ) {
            return node->find( type );
	}
        return RRSetPtr();
    }

    UnsignedZoneImp::NodePtr UnsignedZoneImp::findNode( const Domainname &name ) const
    {
        auto node = mOwnerToNode.find( name );
        if ( node != mOwnerToNode.end() ) {
            return node->second;
        }
        return NodePtr();
    }

    void UnsignedZoneImp::addSOAToAuthoritySection( PacketInfo &response ) const
    {
        if ( ! mSOA || mSOA->count() != 1 )
            throw std::logic_error( "SOA record must be exist in zone" );

        addRRSet( response.mAuthoritySection, *mSOA );
    }

    void UnsignedZoneImp::addRRSet( std::vector<ResourceRecord> &section, const RRSet &rrset ) const
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

    void UnsignedZoneImp::verify() const
    {
        if ( mSOA.get() == nullptr )
            throw ZoneError( "No SOA record" );

        if ( mNameServers.get() == nullptr )
            throw ZoneError( "No NS records" );
    }

    std::shared_ptr<RRSet> UnsignedZoneImp::signRRSet( const RRSet &rrset ) const
    {
        return std::shared_ptr<RRSet>();
    }

    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::getSOA() const
    {
	return mSOA;
    }

    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::getNameServer() const
    {
	return mNameServers;
    }
    
    void UnsignedZoneImp::initialize()
    {
    }
}

