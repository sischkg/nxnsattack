#include "signedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    SignedZoneImp::SignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config )
        : AbstractZoneImp( zone_name ), mSigner( zone_name, ksk_config, zsk_config ), mNSECDB( new NSECDB( zone_name ) )
    {}

    void SignedZoneImp::responseDNSKEY( PacketInfo &response ) const
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

    void SignedZoneImp::responseRRSIG( const Domainname &qname, PacketInfo &response ) const
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

    void SignedZoneImp::responseNSEC( const Domainname &qname, PacketInfo &response ) const
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

    void SignedZoneImp::addRRSIG( PacketInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset ) const
    {
	if ( ! response.isDNSSECOK() )
	    return;

	std::shared_ptr<RRSet> rrsigs = mSigner.signRRSet( original_rrset );
	
	for( auto rrsig : rrsigs->getRRSet() ) {
	    ResourceRecord r;
	    r.mDomainname = rrsigs->getOwner();
	    r.mType       = rrsigs->getType();
	    r.mClass      = rrsigs->getClass();
	    r.mTTL        = rrsigs->getTTL();
	    r.mRData      = rrsig;
	    section.push_back( r );
        }
    }

    
    SignedZoneImp::RRSetPtr SignedZoneImp::generateNSECRRSet( const Domainname &domainname ) const
    {
	ResourceRecord nsec_rr = mNSECDB->find( domainname, getSOA().getTTL() );
	RRSetPtr rrset( new RRSet( nsec_rr.mDomainname, nsec_rr.mClass, nsec_rr.mType, nsec_rr.mTTL ) );
	rrset->add( nsec_rr.mRData );

	return rrset;
    }

    std::shared_ptr<RRSet> SignedZoneImp::signRRSet( const RRSet &rrset ) const
    {
        return mSigner.signRRSet( rrset );
    }

    void SignedZoneImp::initialize()
    {
        ZoneSigner::initialize();
    }
}

