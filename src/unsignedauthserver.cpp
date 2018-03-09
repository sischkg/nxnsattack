#include "unsignedauthserver.hpp"
#include <fstream>
#include <iostream>

namespace dns
{
    void UnsignedAuthServer::load( const std::string &apex, const std::string &filename,
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

        UnsignedZone::initialize();
        zone.reset( new UnsignedZone( apex, ksk_config, zsk_config ) );
	dns::full::load( *zone, apex, config );
    }

    std::vector<std::shared_ptr<RecordDS>> UnsignedAuthServer::getDSRecords() const
    {
        return zone->getDSRecords();
    }

    PacketInfo UnsignedAuthServer::generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
	dns::PacketInfo response = zone->getAnswer( query );
	return modifyResponse( query, response, via_tcp );
    }

    PacketInfo UnsignedAuthServer::modifyResponse( const dns::PacketInfo &query,
                                                   const dns::PacketInfo &original_response,
                                                   bool via_tcp ) const
    {
	return original_response;
    }

    bool UnsignedAuthServer::replace( std::vector<ResourceRecord> &section,
                                      const Condition &condition,
                                      const Replacement &replace ) const
    {
        bool is_replace = false;
        for ( auto &entry : section ) {
            if ( ( ( ! ( condition.flags & MATCH_OWNER ) ) || entry.mDomainname == condition.owner ) &&
                 ( ( ! ( condition.flags & MATCH_TYPE  ) ) || entry.mType       == condition.type  ) &&
                 ( ( ! ( condition.flags & MATCH_CLASS ) ) || entry.mClass      == condition.klass ) &&
                 ( ( ! ( condition.flags & MATCH_TTL   ) ) || entry.mTTL        == condition.ttl   ) ) {
                is_replace = true;
                if ( replace.flags & MATCH_OWNER )
                    entry.mDomainname = replace.owner;
                if ( replace.flags & MATCH_TYPE )
                    entry.mType = replace.type;
                if ( replace.flags & MATCH_CLASS )
                    entry.mClass = replace.klass;
                if ( replace.flags & MATCH_TTL )
                    entry.mTTL = replace.ttl;
                if ( replace.flags & MATCH_DATA )
                    entry.mRData = RDATAPtr( replace.resource_data->clone() );
            }
        }
        return is_replace;
    }

    bool UnsignedAuthServer::erase( std::vector<ResourceRecord> &section,
                                    const Condition &condition ) const
    {
        bool is_erase = false;
        for ( auto entry = section.begin() ; entry != section.end() ; ) {
            if ( ( ( ! ( condition.flags & MATCH_OWNER ) ) || entry->mDomainname == condition.owner ) &&
                 ( ( ! ( condition.flags & MATCH_TYPE  ) ) || entry->mType       == condition.type  ) &&
                 ( ( ! ( condition.flags & MATCH_CLASS ) ) || entry->mClass      == condition.klass ) &&
                 ( ( ! ( condition.flags & MATCH_TTL   ) ) || entry->mTTL        == condition.ttl   ) ) {
                is_erase = true;
                entry = section.erase( entry );
            }
            else {
                entry++;
            }
        }
        return is_erase;
    }


    std::shared_ptr<RRSet> UnsignedAuthServer::signRRSet( const RRSet &rrset ) const
    {
	return zone->signRRSet( rrset );
    }


}
