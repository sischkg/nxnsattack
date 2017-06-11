#include "zoneloader.hpp"

namespace dns
{
    ResourceDataPtr parseRecordA( const YAML::Node &node )
    {
        if ( node["address"] ) {
            return std::shared_ptr<ResourceData>( new RecordA( node["address"].as<std::string>() ) );
        }
        throw ZoneConfigError( "A record must have \"address\" attribute" );
    }

    ResourceDataPtr parseRecordAAAA( const YAML::Node &node )
    {
        if ( node["address"] ) {
            return std::shared_ptr<ResourceData>( new RecordAAAA( node["address"].as<std::string>() ) );
        }
        throw ZoneConfigError( "AAAA record must have \"address\" attribute" );
    }


    ResourceDataPtr parseRecordNS( const YAML::Node &node )
    {
        if ( node["nameserver"] ) {
            return std::shared_ptr<ResourceData>( new RecordNS( node["nameserver"].as<std::string>() ) );
        }
        throw ZoneConfigError( "NS record must have \"nameserver\" attribute" );
    }

    ResourceDataPtr parseRecordSOA( const YAML::Node &node )
    {
        std::string mname,  rname;

        if ( node["mname"] && node["rname"] &&
             node["serial"] && node["refresh"] && node["retry"] && node["expire"] && node["minimum"] ) {
            return ResourceDataPtr( new RecordSOA( node["mname"].as<std::string>(),
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
  
	try {
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
	catch ( std::runtime_error &e ) {
	    std::cerr << "parse: " << e.what() << std::endl;
	    throw;
	}
    }


    std::shared_ptr<Zone> load( const Domainname &apex, const char *config )
    {
        YAML::Node top;
        try {
            top = YAML::Load( config );
        }
        catch( YAML::ParserException &e ) {
            std::cerr << "cannot load zone: " << e.what() << std::endl;
            throw ZoneConfigError( "cannot load zone " + apex.toString() + ": " + e.what() );
        }

        std::shared_ptr<Zone> zone( new Zone( apex ) );
        for ( YAML::const_iterator rrset_it = top.begin() ; rrset_it != top.end() ; ++rrset_it ) {
            try {
                auto rrset = parseRRSet( *rrset_it );
		zone->add( rrset );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << "cannot parse rrset: " << e.what() << std::endl;
                throw;
            }
        }

        return zone;
    }

}
