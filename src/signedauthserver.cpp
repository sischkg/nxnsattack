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

        zone.reset( new SignedZone( apex, ksk_config, zsk_config ) );
	dns::full::load( *zone, apex, config );
    }

    std::vector<std::shared_ptr<RecordDS>> SignedAuthServer::getDSRecords() const
    {
        return zone->getDSRecords();
    }

    PacketInfo SignedAuthServer::generateResponse( const dns::PacketInfo &query, bool via_tcp )
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

    bool SignedAuthServer::replace( std::vector<ResponseSectionEntry> &section,
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
                    entry.r_resource_data = ResourceDataPtr( replace.resource_data->clone() );
            }
        }
        return is_replace;
    }

    bool SignedAuthServer::erase( std::vector<ResponseSectionEntry> &section,
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
