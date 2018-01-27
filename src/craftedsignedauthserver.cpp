#include "craftedsignedauthserver.hpp"
#include <fstream>
#include <iostream>

namespace dns
{
    void CraftedSignedAuthServer::signSection( std::vector<ResourceRecord> &section ) const
    {
	std::vector<ResourceRecord> rrsigs;
	std::vector< std::shared_ptr<RRSet> > signed_targets = cumulate( section );
	for ( auto signed_target : signed_targets ) {
	    std::shared_ptr<RRSet> rrsig_rrset = signRRSet( *signed_target );
	    for ( auto rrsig = rrsig_rrset->begin() ; rrsig != rrsig_rrset->end() ; rrsig++ ) {
		ResourceRecord rr;
		rr.r_domainname    = rrsig_rrset->getOwner();
		rr.r_class         = rrsig_rrset->getClass();
		rr.r_type          = rrsig_rrset->getType();
		rr.r_resource_data = *rrsig;
		rrsigs.push_back( rr );
	    }
	}
	section.insert( section.end(), rrsigs.begin(), rrsigs.end() );	
    }
    
    std::shared_ptr<RRSet> CraftedSignedAuthServer::signRRSet( const RRSet &rrset ) const
    {
	return mSigner.signRRSet( rrset );
    }


    std::vector<std::shared_ptr<RRSet>> CraftedSignedAuthServer::cumulate( const std::vector<ResourceRecord> &rrs ) const
    {
	std::vector<std::shared_ptr<RRSet> > rrsets;

	for ( auto rr : rrs ) {
	    bool is_found = false;
	    for ( auto rrset : rrsets ) {
		if ( rr.r_domainname == rrset->getOwner() &&
		     rr.r_class      == rrset->getClass() && 
		     rr.r_type       == rrset->getType()  ) {
		    rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
		    is_found = true;
		    break;
		}
	    }
	    if ( ! is_found ) {
		std::shared_ptr<RRSet> new_rrset( std::shared_ptr<RRSet>( new RRSet( rr.r_domainname, rr.r_class, rr.r_type, rr.r_ttl ) ) );
		new_rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
		rrsets.push_back( new_rrset );
	    }
	}

	return rrsets;
    }

}
