#include "unsignedauthserver.hpp"
#include <fstream>
#include <iostream>

namespace dns
{
    void PostSignedAuthServer::load( const std::string &apex, const std::string &filename,
                                     const std::string &ksk_config, const std::string &zsk_config,
                                     const std::vector<uint8_t> &salt, uint16_t iterate, HashAlgorithm algo,
                                     bool enable_nsec, bool enable_nsec3 )
    {
	std::ifstream fin( filename );
	std::string config;
	while ( ! fin.eof() ) {
	    std::string line;
	    std::getline( fin, line );
	    config += line;
	    config += "\n";
	}

        PostSignedZone::initialize();
        zone.reset( new PostSignedZone( Domainname( apex ),
                                        ksk_config, zsk_config,
                                        salt, iterate, algo,
                                        enable_nsec, enable_nsec3 ) );
	dns::full::load( *zone, Domainname( apex ), config );
        zone->setup();
	zone->verify();
    }

    std::vector<std::shared_ptr<RecordDS>> PostSignedAuthServer::getDSRecords() const
    {
        return zone->getDSRecords();
    }

    MessageInfo PostSignedAuthServer::generateResponse( const dns::MessageInfo &query, bool via_tcp ) const
    {
	dns::MessageInfo response = zone->getAnswer( query );
	return modifyResponse( query, response, via_tcp );
    }

    MessageInfo PostSignedAuthServer::modifyResponse( const dns::MessageInfo &query,
						      const dns::MessageInfo &original_response,
                                                     bool via_tcp ) const
    {
	return original_response;
    }


    std::shared_ptr<RRSet> PostSignedAuthServer::signRRSet( const RRSet &rrset ) const
    {
	return zone->signRRSet( rrset );
    }


}
