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
	std::cerr << config << std::endl;
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

    bool AuthServer::replace( std::vector<ResourceRecord> &section,
                              const Condition &condition,
                              const Replacement &replace ) const
    {
        bool is_replace = false;
        for ( auto &entry : section ) {
            if ( ( ( ! ( condition.flags & MATCH_OWNER ) ) || entry.r_domainname == condition.owner ) &&
                 ( ( ! ( condition.flags & MATCH_TYPE  ) ) || entry.r_type       == condition.type  ) &&
                 ( ( ! ( condition.flags & MATCH_CLASS ) ) || entry.r_class      == condition.klass ) &&
                 ( ( ! ( condition.flags & MATCH_TTL   ) ) || entry.r_ttl        == condition.ttl   ) ) {
                is_replace = true;
                if ( replace.flags & MATCH_OWNER )
                    entry.r_domainname = replace.owner;
                if ( replace.flags & MATCH_TYPE )
                    entry.r_type = replace.type;
                if ( replace.flags & MATCH_CLASS )
                    entry.r_class = replace.klass;
                if ( replace.flags & MATCH_TTL )
                    entry.r_ttl = replace.ttl;
                if ( replace.flags & MATCH_DATA )
                    entry.r_resource_data = RDATAPtr( replace.resource_data->clone() );
            }
        }
        return is_replace;
    }

    bool AuthServer::erase( std::vector<ResourceRecord> &section,
                            const Condition &condition ) const
    {
        bool is_erase = false;
        for ( auto entry = section.begin() ; entry != section.end() ; ) {
            if ( ( ( ! ( condition.flags & MATCH_OWNER ) ) || entry->r_domainname == condition.owner ) &&
                 ( ( ! ( condition.flags & MATCH_TYPE  ) ) || entry->r_type       == condition.type  ) &&
                 ( ( ! ( condition.flags & MATCH_CLASS ) ) || entry->r_class      == condition.klass ) &&
                 ( ( ! ( condition.flags & MATCH_TTL   ) ) || entry->r_ttl        == condition.ttl   ) ) {
                is_erase = true;
                entry = section.erase( entry );
            }
            else {
                entry++;
            }
        }
        return is_erase;
    }
}
