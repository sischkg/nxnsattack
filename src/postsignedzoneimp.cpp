#include "postsignedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    PostSignedZoneImp::PostSignedZoneImp( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config,
                                          const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo )
        : AbstractZoneImp( zone_name ),
          mSigner( zone_name, ksk_config, zsk_config ),
          mNSECDB( new NSECDB( zone_name ) ),
          mNSEC3DB( zone_name, salt, iterate, algo )
    {}

    void PostSignedZoneImp::responseDNSKEY( PacketInfo &response ) const
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

    void PostSignedZoneImp::responseRRSIG( const Domainname &qname, PacketInfo &response ) const
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

    void PostSignedZoneImp::responseNSEC( const Domainname &qname, PacketInfo &response ) const
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
    

    std::vector<std::shared_ptr<RecordDS>> PostSignedZoneImp::getDSRecords() const
    {
	return mSigner.getDSRecords();
    }

    void PostSignedZoneImp::setup()
    {
	add( getDNSKEYRRSet() ); 
	for ( auto node = begin() ; node != end() ; node++ ) {
	    mNSECDB->addNode( node->first, *(node->second) );
	}
    }

    PostSignedZoneImp::RRSetPtr PostSignedZoneImp::getDNSKEYRRSet() const
    {
	std::vector<std::shared_ptr<RecordDNSKEY>> keys = mSigner.getDNSKEYRecords();
	RRSetPtr dnskey_rrset( new RRSet( getSOA().getOwner(), getSOA().getClass(), TYPE_DNSKEY, getSOA().getTTL() ) );
	for ( auto k : keys ) {
	    dnskey_rrset->add( k );
	}
	return dnskey_rrset;
    }

    void PostSignedZoneImp::addRRSIG( PacketInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset ) const
    {}

    
    PostSignedZoneImp::RRSetPtr PostSignedZoneImp::generateNSECRRSet( const Domainname &domainname ) const
    {
	ResourceRecord nsec_rr = mNSECDB->find( domainname, getSOA().getTTL() );
	RRSetPtr rrset( new RRSet( nsec_rr.mDomainname, nsec_rr.mClass, nsec_rr.mType, nsec_rr.mTTL ) );
	rrset->add( nsec_rr.mRData );

	return rrset;
    }

    std::shared_ptr<RRSet> PostSignedZoneImp::signRRSet( const RRSet &rrset ) const
    {
        return mSigner.signRRSet( rrset );
    }

    void PostSignedZoneImp::initialize()
    {
        ZoneSigner::initialize();
    }
}

