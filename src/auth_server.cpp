#include "auth_server.hpp"
#include <fstream>

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
    std::cerr << config << std::endl;
    zone = dns::full::load( apex, config );
}


dns::PacketInfo AuthServer::generateResponse( const dns::PacketInfo &query, bool via_tcp )
{
    dns::PacketInfo response = zone->getAnswer( query );
    return response;
}
