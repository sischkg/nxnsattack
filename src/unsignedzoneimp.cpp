#include "unsignedzoneimp.hpp"
#include <algorithm>
#include <sstream>
#include <iterator>

namespace dns
{

    UnsignedZoneImp::UnsignedZoneImp( const Domainname &zone_name )
        : AbstractZoneImp( zone_name )
    {}

    void UnsignedZoneImp::responseNoData( const Domainname &qname, PacketInfo &response, bool need_wildcard ) const
    {
	response.mResponseCode = NO_ERROR;
	addSOAToAuthoritySection( response );
    }

    void UnsignedZoneImp::responseNXDomain( const Domainname &qname, PacketInfo &response ) const
    {
	response.mResponseCode = NXDOMAIN;
	addSOAToAuthoritySection( response );
    }

    void UnsignedZoneImp::responseDNSKEY( const Domainname &qname, PacketInfo &response ) const
    {
        responseNoData( qname, response, true );
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

    void UnsignedZoneImp::addRRSIG( PacketInfo &response, std::vector<ResourceRecord> &section, const RRSet &original_rrset, const Domainname & ) const
    {}

    
    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::generateNSECRRSet( const Domainname &domainname ) const
    {
	return RRSetPtr();
    }

    UnsignedZoneImp::RRSetPtr UnsignedZoneImp::signRRSet( const RRSet &rrset ) const
    {
        return RRSetPtr();
    }

    void UnsignedZoneImp::initialize()
    {}
}

