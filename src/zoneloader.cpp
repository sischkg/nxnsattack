#include "zoneloader.hpp"

namespace dns
{
    std::shared_ptr<ResourceData> parseRecordA( const YAML::Node &node )
    {
        if ( node["address"] ) {
            return std::shared_ptr<ResourceData>( new RecordA( node["address"].as<std::string>() ) );
        }
        throw ZoneConfigError( "A record must have \"address\" attribute" );
    }

    std::shared_ptr<ResourceData> parseRecordNS( const YAML::Node &node )
    {
        if ( node["address"] ) {
            return std::shared_ptr<ResourceData>( new RecordAAAA( node["address"].as<std::string>() ) );
        }
        throw ZoneConfigError( "AAAA record must have \"address\" attribute" );
    }

    std::shared_ptr<ResourceData> parseRecordSOA( const YAML::Node &node )
    {
        std::string mname,  rname;

        if ( node["mname"] && node["rname"] &&
             node["serial"] && node["refresh"] && node["retry"] && node["expire"] && node["minimum"] ) {
            return std::shared_ptr<ResourceData>( new RecordSOA( node["mname"].as<std::string>(),
                                                                 node["rname"].as<std::string>(),
                                                                 node["serial"].as<uint32_t>(),
                                                                 node["refresh"].as<uint32_t>(),
                                                                 node["retry"].as<uint32_t>(),
                                                                 node["expire"].as<uint32_t>(),
                                                                 node["minimum"].as<uint32_t>() ) );
        }

        throw ZoneConfigError( "SOA record must have \"mname,rname,serial,refresh,retry,expire,minimum\" attributes" );
    }

    std::shared_ptr<RRSet> parseRRSet( const YAML::Node &node )
    {
        if ( ! ( node["owner"] || node["ttl"] || node["typpe"] || node["record"] ) ) {
            throw ZoneConfigError( "each record must have \"owner, ttl, type, record\" attributes" );
        }

        std::string owner = node["owner"].as<std::string>();
        TTL  ttl          = node["ttl"].as<uint32_t>();
        Type type         = string_to_type_code( node["type"].as<std::string>() );

        std::shared_ptr<RRSet> rrset( new RRSet( owner, CLASS_IN, type, ttl ) );
  
        const YAML::Node records = node["record"];
        for ( YAML::const_iterator record = records.begin() ; record != records.end() ; ++record ) { 
            switch( type ) {
            case TYPE_A:
                rrset->add( parseRecordA( *record ) );
                break;
            case TYPE_SOA:
                rrset->add( parseRecordSOA( *record ) );
                break;
            case TYPE_NS:
                rrset->add( parseRecordNS( *record ) );
                break;
            default:
                break;
            }
        }
        return rrset;
    }


    std::shared_ptr<Zone> load( const Domainname &apex, const char *config )
    {
        YAML::Node top = YAML::Load( config );

        std::shared_ptr<Zone> zone( new Zone( apex ) );
        for ( YAML::const_iterator rrset_it = top.begin() ; rrset_it != top.end() ; ++rrset_it ) {
            zone->add( parseRRSet( *rrset_it ) );
        }

        return zone;
    }

}
