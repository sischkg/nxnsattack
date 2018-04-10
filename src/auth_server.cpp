#include "auth_server.hpp"
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
        zone.reset( new Zone( apex ) );
	dns::full::load( *zone, apex, config );
    }


    PacketInfo AuthServer::generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
	dns::PacketInfo response = zone->getAnswer( query );
	return modifyResponse( query, response, via_tcp );
    }

    PacketInfo AuthServer::modifyResponse( const dns::PacketInfo &query,
					   const dns::PacketInfo &original_response,
					   bool via_tcp ) const
    {
	return original_response;
    }

}
