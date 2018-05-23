#include "signedauthserver.hpp"
#include <fstream>
#include <iostream>

namespace dns
{
    void SignedAuthServer::load( const std::string &apex, const std::string &filename,
                                 const std::string &ksk_config, const std::string &zsk_config )
    {
	std::ifstream fin( filename );
	std::string config;
	while ( ! fin.eof() ) {
	    std::string line;
	    std::getline( fin, line );
	    config += line;
	    config += "\n";
	}
	std::cerr << config << std::endl;

        SignedZone::initialize();
        zone.reset( new SignedZone( apex, ksk_config, zsk_config ) );
	dns::full::load( *zone, apex, config );
        zone->setup();
	zone->verify();
    }

    std::vector<std::shared_ptr<RecordDS>> SignedAuthServer::getDSRecords() const
    {
        return zone->getDSRecords();
    }

    PacketInfo SignedAuthServer::generateResponse( const dns::PacketInfo &query, bool via_tcp ) const
    {
	dns::PacketInfo response = zone->getAnswer( query );
	return modifyResponse( query, response, via_tcp );
    }

    PacketInfo SignedAuthServer::modifyResponse( const dns::PacketInfo &query,
                                                 const dns::PacketInfo &original_response,
                                                 bool via_tcp ) const
    {
	return original_response;
    }

    std::shared_ptr<RRSet> SignedAuthServer::signRRSet( const RRSet &rrset ) const
    {
	return zone->signRRSet( rrset );
    }


}
