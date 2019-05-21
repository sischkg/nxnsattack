#include "auth_server.hpp"
#include "unsignedzone.hpp"
#include <fstream>
#include <iostream>

namespace dns
{
    void AuthServer::load( const std::string &apex, const std::string &filename )
    {
	std::ifstream fin( filename );
	std::string config;
	while ( ! fin.eof() ) {
	    std::string line;
	    std::getline( fin, line );
	    config += line;
	    config += "\n";
	}
        zone.reset( new UnsignedZone( Domainname( apex ) ) );
	dns::full::load( *zone, Domainname( apex ), config );
    }


    MessageInfo AuthServer::generateResponse( const dns::MessageInfo &query, bool via_tcp ) const
    {
	dns::MessageInfo response = zone->getAnswer( query );
	return modifyResponse( query, response, via_tcp );
    }

    MessageInfo AuthServer::modifyResponse( const dns::MessageInfo &query,
					    const dns::MessageInfo &original_response,
					    bool via_tcp ) const
    {
	return original_response;
    }

}
