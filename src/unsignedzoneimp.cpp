#include "unsignedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    UnsignedZoneImp::UnsignedZoneImp( const Domainname &zone_name )
        : AbstractZoneImp( zone_name )
    {}

    void UnsignedZoneImp::responseDNSKEY( PacketInfo &response ) const
    {
        responseNoData( getSOA().getOwner(), response, true );
    }

    void UnsignedZoneImp::responseRRSIG( const Domainname &qname, PacketInfo &response ) const
    {
	auto node = findNode( qname );
	if ( node ) {
            responseNoData( qname, response, true );
	}
	else {
	    // NXDOMAIN
	    responseNXDomain( qname, response );
	}
    }

    void UnsignedZoneImp::responseNSEC( const Domainname &qname, PacketInfo &response ) const
    {
	auto node = findNode( qname );
	if ( node ) {
            responseNoData( qname, response, true );
	}
	else {
	    responseNXDomain( qname, response );
	}
    }
    

    std::vector<std::shared_ptr<RecordDS>> UnsignedZoneImp::getDSRecords() const
    {
        return std::vector<std::shared_ptr<RecordDS>>();
    }

    void UnsignedZoneImp::setup()
    {}

    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::getDNSKEYRRSet() const
    {
        return RRSetPtr();
    }

    void UnsignedZoneImp::addRRSIG( PacketInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset ) const
    {}

    
    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::generateNSECRRSet( const Domainname &domainname ) const
    {
	return RRSetPtr();
    }

    std::shared_ptr<RRSet> UnsignedZoneImp::signRRSet( const RRSet &rrset ) const
    {}

    void UnsignedZoneImp::initialize()
    {}
}

