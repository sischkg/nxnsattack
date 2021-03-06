#include "signedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    SignedZoneImp::SignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config,
                                  const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo,
                                  bool enable_nsec, bool enable_nsec3 )
        : AbstractZoneImp( zone_name ), mSigner( zone_name, ksk_config, zsk_config ),
          mNSECDB( new NSECDB( zone_name ) ),
          mNSEC3DB( new NSEC3DB( zone_name, salt, iterate, algo ) ),
          mEnableNSEC( enable_nsec ), mEnableNSEC3( enable_nsec3 )
    {}


    void SignedZoneImp::responseNoData( const Domainname &qname, MessageInfo &response, bool need_wildcard ) const
    {
	response.mResponseCode = NO_ERROR;
	addSOAToAuthoritySection( response );
	if ( response.isDNSSECOK() ) {
	    RRSetPtr nsec3 = generateNSEC3RRSet( qname );
            if ( nsec3 ) {
                addRRSet( response.mAuthoritySection, *nsec3 );
                addRRSIG( response, response.mAuthoritySection, *nsec3 );
            }
	    RRSetPtr nsec = generateNSECRRSet( qname );
            if ( nsec ) {
                addRRSet( response.mAuthoritySection, *nsec );
                addRRSIG( response, response.mAuthoritySection, *nsec );
            }

	    if ( need_wildcard ) {
		Domainname wildcard = getApex();
		wildcard.addSubdomain( "*" );
		RRSetPtr wildcard_nsec3 = generateNSEC3RRSet( wildcard );
                if ( wildcard_nsec3 ) {
                    addRRSet( response.mAuthoritySection, *wildcard_nsec3 );
                    addRRSIG( response, response.mAuthoritySection, *wildcard_nsec3 );
                }
		RRSetPtr wildcard_nsec = generateNSECRRSet( wildcard );
                if ( wildcard_nsec ) {
                    addRRSet( response.mAuthoritySection, *wildcard_nsec );
                    addRRSIG( response, response.mAuthoritySection, *wildcard_nsec );
                }
	    }
	}
    }


    void SignedZoneImp::responseNXDomain( const Domainname &qname, MessageInfo &response ) const
    {
	response.mResponseCode = NXDOMAIN;
	addSOAToAuthoritySection( response );
	if ( response.isDNSSECOK() ) {
	    RRSetPtr nsec3 = generateNSEC3RRSet( qname );
            if ( nsec3 ) {
                addRRSet( response.mAuthoritySection, *nsec3 );
                addRRSIG( response, response.mAuthoritySection, *nsec3 );
            }
	    RRSetPtr nsec = generateNSECRRSet( qname );
            if ( nsec ) {
                addRRSet( response.mAuthoritySection, *nsec );
                addRRSIG( response, response.mAuthoritySection, *nsec );
            }

	    Domainname wildcard = getApex();
	    wildcard.addSubdomain( "*" );
	    RRSetPtr wildcard_nsec3 = generateNSEC3RRSet( wildcard );
            if ( wildcard_nsec3 ) {
                addRRSet( response.mAuthoritySection, *wildcard_nsec3 );
                addRRSIG( response, response.mAuthoritySection, *wildcard_nsec3 );
            }
	    RRSetPtr wildcard_nsec = generateNSECRRSet( wildcard );
            if ( wildcard_nsec ) {
                addRRSet( response.mAuthoritySection, *wildcard_nsec );
                addRRSIG( response, response.mAuthoritySection, *wildcard_nsec );
            }
	}
    }

    void SignedZoneImp::responseDNSKEY( const Domainname &qname, MessageInfo &response ) const
    {
	std::vector<std::shared_ptr<RecordDNSKEY>> keys = mSigner.getDNSKEYRecords();
	std::shared_ptr<RRSet> dnskey_rrset( new RRSet( getSOA().getOwner(), getSOA().getClass(), TYPE_DNSKEY, getSOA().getTTL() ) );
	for ( auto k : keys ) {
	    dnskey_rrset->add( k );
	}
	addRRSet( response.mAnswerSection, *dnskey_rrset );
	if ( response.isDNSSECOK() ) {
	    std::shared_ptr<RRSet> rrsig_rrset = mSigner.signDNSKEY( getSOA().getTTL() );
	    addRRSet( response.mAnswerSection, *rrsig_rrset );
	}
    }

    void SignedZoneImp::responseRRSIG( const Domainname &qname, MessageInfo &response ) const
    {
	auto node = findNode( qname );
	if ( node ) {
	    if ( node->exist() ) {
		for ( auto rrset_itr = node->begin() ; rrset_itr != node->end() ; rrset_itr++ ) {
		    auto rrset = *(rrset_itr->second);
		    std::shared_ptr<RRSet> rrsig = mSigner.signRRSet( rrset );
		    addRRSet( response.mAnswerSection, *rrsig );
		}
	    }
	    else {
		responseNoData( qname, response, true );
	    }
	}
	else {
	    // NXDOMAIN
	    responseNXDomain( qname, response );
	}
    }

    void SignedZoneImp::responseNSEC( const Domainname &qname, MessageInfo &response ) const
    {
	auto node = findNode( qname );
	if ( node ) {
	    if ( node->exist() ) {
                ResourceRecord nsec_rr = mNSECDB->find( qname, getSOA().getTTL() );
                RRSetPtr rrset( new RRSet( nsec_rr.mDomainname, nsec_rr.mClass, nsec_rr.mType, nsec_rr.mTTL ) );
                rrset->add( nsec_rr.mRData );

                addRRSet( response.mAnswerSection, *rrset );
                addRRSIG( response, response.mAnswerSection, *rrset );
	    }
	    else {
		responseNoData( qname, response, true );
	    }
	}
	else {
	    // NXDOMAIN
	    responseNXDomain( qname, response );
	}
    }
    

    std::vector<std::shared_ptr<RecordDS>> SignedZoneImp::getDSRecords() const
    {
	return mSigner.getDSRecords();
    }

    void SignedZoneImp::setup()
    {
	add( getDNSKEYRRSet() ); 
	for ( auto node = begin() ; node != end() ; node++ ) {
	    mNSECDB->addNode( node->first, *(node->second) );
	    mNSEC3DB->addNode( node->first, *(node->second) );
	}
    }

    SignedZoneImp::RRSetPtr SignedZoneImp::getDNSKEYRRSet() const
    {
	std::vector<std::shared_ptr<RecordDNSKEY>> keys = mSigner.getDNSKEYRecords();
	RRSetPtr dnskey_rrset( new RRSet( getSOA().getOwner(), getSOA().getClass(), TYPE_DNSKEY, getSOA().getTTL() ) );
	for ( auto k : keys ) {
	    dnskey_rrset->add( k );
	}
	return dnskey_rrset;
    }

    void SignedZoneImp::addRRSIG( MessageInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset ) const
    {
        addRRSIG( response, section, original_rrset, original_rrset.getOwner() );
    }

    void SignedZoneImp::addRRSIG( MessageInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset, const Domainname &owner ) const
    {
	if ( ! response.isDNSSECOK() )
	    return;

	std::shared_ptr<RRSet> rrsigs = mSigner.signRRSet( original_rrset );
	
	for( auto rrsig : rrsigs->getRRSet() ) {
	    ResourceRecord r;
	    r.mDomainname = owner;
	    r.mType       = rrsigs->getType();
	    r.mClass      = rrsigs->getClass();
	    r.mTTL        = rrsigs->getTTL();
	    r.mRData      = rrsig;
	    section.push_back( r );
        }
    }

    
    SignedZoneImp::RRSetPtr SignedZoneImp::generateNSECRRSet( const Domainname &domainname ) const
    {
        if ( mEnableNSEC ) {
            ResourceRecord nsec_rr = mNSECDB->find( domainname, getSOA().getTTL() );
            RRSetPtr rrset( new RRSet( nsec_rr.mDomainname, nsec_rr.mClass, nsec_rr.mType, nsec_rr.mTTL ) );
            rrset->add( nsec_rr.mRData );

            return rrset;
        }
        else {
            return RRSetPtr();
        }
    }

    SignedZoneImp::RRSetPtr SignedZoneImp::generateNSEC3RRSet( const Domainname &domainname ) const
    {
        if ( mEnableNSEC3 ) {
            ResourceRecord nsec_rr = mNSEC3DB->find( domainname, getSOA().getTTL() );
            RRSetPtr rrset( new RRSet( nsec_rr.mDomainname, nsec_rr.mClass, nsec_rr.mType, nsec_rr.mTTL ) );
            rrset->add( nsec_rr.mRData );
            return rrset;
        }
        else {
            return RRSetPtr();
        }
    }

    std::shared_ptr<RRSet> SignedZoneImp::signRRSet( const RRSet &rrset ) const
    {
        if ( rrset.getType() == TYPE_DNSKEY )
            return mSigner.signDNSKEY( rrset.getTTL() );
        else
            return mSigner.signRRSet( rrset );
    }

    void SignedZoneImp::initialize()
    {
        ZoneSigner::initialize();
    }
}

