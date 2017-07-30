#include "zoneloader.hpp"
#include "tokenizer.hpp"
#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include <time.h>

namespace dns
{
      
    uint32_t timestamp_to_epoch( const std::string &timestamp )
    {
        if ( timestamp.size() != 14 ) {
            throw std::runtime_error( "timestamp " + timestamp + " is invalid" );
        }
        tm tm = { 0 };

        tm.tm_year  = boost::lexical_cast<int>( timestamp.substr(  0, 4 ) ) - 1900;
        tm.tm_mon   = boost::lexical_cast<int>( timestamp.substr(  4, 2 ) ) - 1;
        tm.tm_mday  = boost::lexical_cast<int>( timestamp.substr(  6, 2 ) );
        tm.tm_hour  = boost::lexical_cast<int>( timestamp.substr(  8, 2 ) );
        tm.tm_min   = boost::lexical_cast<int>( timestamp.substr( 10, 2 ) );
        tm.tm_sec   = boost::lexical_cast<int>( timestamp.substr( 12, 2 ) );
        tm.tm_isdst = 0;

        if ( tm.tm_year < 70 ||
             tm.tm_mon  > 11 ||
             tm.tm_mday < 1  ||
             tm.tm_mday > 31 ||
             tm.tm_hour > 23 ||
             tm.tm_min  > 59 ||
             tm.tm_sec  > 60 ) {
            throw std::runtime_error( "timestamp " + timestamp + " is invalid" );
        }
		
        return timegm( &tm );
    }

    std::vector<std::string> parse_txt( const std::string &s )
    {
	std::vector<std::string> txt;
	std::string t  = "";
	bool in_txt    = false;
	for ( auto c : s ) {
	    if ( c == '"' && ! in_txt ) {
		in_txt = true;
		continue;
	    }
	    if ( c == '"' && in_txt ) {
		in_txt = false;
		txt.push_back( t );
		t      = "";
		continue;
	    }
	    if ( in_txt )
		t.push_back( c );
	}
	return txt;
    }
    
    namespace yamlloader
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

        ResourceDataPtr parseRecordMX( const YAML::Node &node )
        {
            if ( node["priority"] && node["mailserver"] ) {
                return std::shared_ptr<ResourceData>( new RecordMX( node["priority"].as<uint16_t>(),
                                                                    node["mailserver"].as<std::string>() ) );
            }
            throw ZoneConfigError( "MX record must have \"priority and mailserver\" attribute" );
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

        ResourceDataPtr parseRecordCNAME( const YAML::Node &node )
        {
            if ( node["canonicalname"] ) {
                return std::shared_ptr<ResourceData>( new RecordCNAME( node["canonicalname"].as<std::string>() ) );
            }
            throw ZoneConfigError( "CNAME record must have \"canonical\" attribute" );
        }

        ResourceDataPtr parseRecordDNAME( const YAML::Node &node )
        {
            if ( node["canonicalname"] ) {
                return std::shared_ptr<ResourceData>( new RecordDNAME( node["canonicalname"].as<std::string>() ) );
            }
            throw ZoneConfigError( "DNAME record must have \"canonical\" attribute" );
        }

        ResourceDataPtr parseRecordRRSIG( const YAML::Node &node )
        {
            if ( node["type_covered"] &&
                 node["algorithm"] &&
                 node["label_count"]  &&
                 node["original_ttl"] &&
                 node["expiration"]  &&
                 node["inception"]  &&
                 node["key_tag"]  &&
                 node["signer"]  &&
                 node["signature"] ) {
                std::vector<uint8_t> signature;
                decode_from_base64( node["signature"].as<std::string>(), signature );

                return std::shared_ptr<ResourceData>( new RecordRRSIG( node["type_covered"].as<uint16_t>(),
                                                                       node["algorithm"].as<uint16_t>(),
                                                                       node["label_count"].as<uint16_t>(),
                                                                       node["original_ttl"].as<uint32_t>(),
                                                                       node["expiration"].as<uint32_t>(),
                                                                       node["inception"].as<uint32_t>(),
                                                                       node["key_tag"].as<uint16_t>(),
                                                                       node["signer"].as<std::string>(),
                                                                       signature ) );
            }
            const char *error_message = "RRSIG record must have "
                "\"type_covered\", \"algorithm\", \"label_count\", "
                "\"original_ttl\", \"expiration\", \"inception\", "
                "\"key_tag\", \"signer\" and \"signature\" attribute";
	    
            throw ZoneConfigError( error_message );
        }

        ResourceDataPtr parseRecordDNSKey( const YAML::Node &node )
        {
            if ( node["flag"] &&
                 node["algorithm"] &&
                 node["public_key"] ) {
                std::vector<uint8_t> public_key;
                decode_from_base64( node["public_key"].as<std::string>(), public_key );
                return std::shared_ptr<ResourceData>( new RecordDNSKey( node["flag"].as<uint16_t>(),
                                                                        node["algorithm"].as<uint16_t>(),
                                                                        public_key ) );
            }
            throw ZoneConfigError( "DNSKey record must have \"flag\", \"algorithm\" and \"public_key\" attribute" );
        }

        ResourceDataPtr parseRecordDS( const YAML::Node &node )
        {
            if ( node["key_tag"] &&
                 node["algorithm"] &&
                 node["digest_type"] &&
                 node["digest"] ) {
                std::vector<uint8_t> digest;
                decodeFromHex( node["digest"].as<std::string>(), digest );
                return std::shared_ptr<ResourceData>( new RecordDS( node["key_tag"].as<uint16_t>(),
                                                                    node["algorithm"].as<uint16_t>(),
                                                                    node["digest_type"].as<uint16_t>(),
                                                                    digest ) );
            }
            throw ZoneConfigError( "DS record must have \"key_tag\", \"algorithm\", \"digest_type\" and \"digest\" attribute" );
        }

        ResourceDataPtr parseRecordNSEC( const YAML::Node &node )
        {
            if ( node["next"] &&
                 node["types"] ) {
                YAML::Node node_types = node["types"];
                std::vector<Type> types;
                for ( unsigned int i = 0 ; i < node_types.size() ; i++ ) {
                    std::string type_string = node_types[i].as<std::string>();
                    types.push_back( string_to_type_code( type_string ) );
                }
                return std::shared_ptr<ResourceData>( new RecordNSEC( node["next"].as<std::string>(),
                                                                      types ) );
            }
            throw ZoneConfigError( "NSEC record must have \"next\", and \"types\" attribute" );
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
                    case TYPE_AAAA:
                        rrset->add( parseRecordAAAA( *record ) );
                        break;
                    case TYPE_SOA:
                        rrset->add( parseRecordSOA( *record ) );
                        break;
                    case TYPE_NS:
                        rrset->add( parseRecordNS( *record ) );
                        break;
                    case TYPE_MX:
                        rrset->add( parseRecordMX( *record ) );
                        break;
                    case TYPE_CNAME:
                        rrset->add( parseRecordCNAME( *record ) );
                        break;
                    case TYPE_DNAME:
                        rrset->add( parseRecordDNAME( *record ) );
                        break;
                    case TYPE_RRSIG:
                        rrset->add( parseRecordRRSIG( *record ) );
                        break;
                    case TYPE_DNSKEY:
                        rrset->add( parseRecordDNSKey( *record ) );
                        break;
                    case TYPE_DS:
                        rrset->add( parseRecordDS( *record ) );
                        break;
                    case TYPE_NSEC:
                        rrset->add( parseRecordNSEC( *record ) );
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


        std::shared_ptr<Zone> load( const Domainname &apex, const std::string &config )
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
                catch ( std::logic_error &e ) {
                    std::cerr << "cannot parse rrset: " << e.what() << std::endl;
                    throw;
                }
                catch ( ... ) {
                    std::cerr << "cannot parse rrset: other error" << std::endl;
                    throw;
                }
            }

            return zone;
        }

    }


    namespace full
    {
        std::string eraseComment( const std::string &line )
        {
            std::string::size_type pos = line.find( ';' );
            if ( pos == std::string::npos )
                return line;
            return std::string( line, 0, pos );
        }

	std::string eraseLastSpace( const std::string &line )
	{
	    std::string l = line;
	    while ( l.size() > 0 && l[l.size()-1] == ' ' )
		l.pop_back();
	    return l;
	}
	
        std::shared_ptr<RRSet> parseLine( const std::string &line )
        {
	    try {
		std::vector<std::string> tokens = tokenize( line );
		//            boost::char_separator<char> sep( " \t" );
		//            boost::tokenizer<boost::char_separator<char>> tokens( line, sep );
		auto pos = tokens.begin();
 
		if ( pos == tokens.end() )
		    throw std::runtime_error( "empty line or no owner field" );
		std::string owner = *pos; pos++;

		if ( pos == tokens.end() )
		    throw std::runtime_error( "no ttl field" );
		uint32_t ttl      = boost::lexical_cast<uint32_t>( *pos ); pos++;

		if ( pos == tokens.end() )
		    throw std::runtime_error( "no class field" );
		std::string klass = *pos; pos++;

		if ( pos == tokens.end() )
		    throw std::runtime_error( "no type field" );
		Type type         = string_to_type_code( *pos ); pos++;
 
		if ( pos == tokens.end() )
		    throw std::runtime_error( "no data field" );
		std::vector<std::string> data;
		for ( ; pos != tokens.end() ; pos++ )
		    data.push_back( *pos );

		ResourceDataPtr rr;
		switch ( type ) {
		case TYPE_A:
		    rr = parseRecordA( data );
		    break;
		case TYPE_AAAA:
		    rr = parseRecordAAAA( data );
		    break;
		case TYPE_NS:
		    rr = parseRecordNS( data );
		    break;
		case TYPE_MX:
		    rr = parseRecordMX( data );
		    break;
		case TYPE_SOA:
		    rr = parseRecordSOA( data );
		    break;
		case TYPE_CNAME:
		    rr = parseRecordCNAME( data );
		    break;
		case TYPE_DNAME:
		    rr = parseRecordDNAME( data );
		    break;
		case TYPE_TXT:
		    rr = parseRecordTXT( data );
		    break;
		case TYPE_SPF:
		    rr = parseRecordSPF( data );
		    break;
		case TYPE_RRSIG:
		    rr = parseRecordRRSIG( data );
		    break;
		case TYPE_DS:
		    rr = parseRecordDS( data );
		    break;
		case TYPE_DNSKEY:
		    rr = parseRecordDNSKey( data );
		    break;
		case TYPE_NSEC:
		    rr = parseRecordNSEC( data );
		    break;
		default:
		    throw std::runtime_error( "unknown supported type" );
		}

		std::shared_ptr<RRSet> rrset( new RRSet( owner, CLASS_IN, type, ttl ) );
		rrset->add( rr );
		return rrset;
	    }
	    catch ( std::runtime_error &e ) {
		std::cerr << "cannot load line \"" << line << "\" ( " << e.what() << ")." << std::endl;
		throw;
	    }		
        }

        std::vector<uint8_t> decode_from_base64_strings( std::vector<std::string>::const_iterator begin,
                                                         std::vector<std::string>::const_iterator end )
        {
            std::string base64_string;
            while ( begin != end ) {
                base64_string += *begin;
                begin++;
            }

            std::vector<uint8_t> decoded_data;
            decode_from_base64( base64_string, decoded_data );
            return decoded_data;
        }


	
        ResourceDataPtr parseRecordA( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordA( data[0] ) );
        }

        ResourceDataPtr parseRecordAAAA( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordAAAA( data[0] ) );
        }

        ResourceDataPtr parseRecordNS( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordNS( data[0] ) );
        }

        ResourceDataPtr parseRecordMX( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordMX( boost::lexical_cast<uint16_t>( data[0] ),
                                                  data[1] ) );
        }

        ResourceDataPtr parseRecordSOA( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordSOA( data[0],                                  // mname
                                                   data[1],                                  // rname
                                                   boost::lexical_cast<uint32_t>( data[2] ), // serial
                                                   boost::lexical_cast<uint32_t>( data[3] ), // refresh
                                                   boost::lexical_cast<uint32_t>( data[4] ), // retry
                                                   boost::lexical_cast<uint32_t>( data[5] ), // expire,
                                                   boost::lexical_cast<uint32_t>( data[6] )  // minimum
                                                   ) );
        }

        ResourceDataPtr parseRecordCNAME( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordCNAME( data[0] ) );
        }

        ResourceDataPtr parseRecordDNAME( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordCNAME( data[0] ) );
        }

	ResourceDataPtr parseRecordTXT( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordTXT( data ) );
        }

	ResourceDataPtr parseRecordSPF( const std::vector<std::string> &data )
        {
            return ResourceDataPtr( new RecordSPF( data ) );
        }


        ResourceDataPtr parseRecordRRSIG( const std::vector<std::string> &data )
        {
            auto signature_data = data.begin();
            for ( int i = 0 ; i < 8 ; i++ ) signature_data++;
            auto signature = decode_from_base64_strings( signature_data, data.end() );
            
            return ResourceDataPtr( new RecordRRSIG( string_to_type_code( data[0] ),           // type covered
                                                     boost::lexical_cast<uint16_t>( data[1] ),  // algorithm
                                                     boost::lexical_cast<uint16_t>( data[2] ),  // label count
                                                     boost::lexical_cast<uint32_t>( data[3] ),  // original ttl
                                                     timestamp_to_epoch( data[4] ),            // expiration
						     timestamp_to_epoch( data[5] ),            // inception
                                                     boost::lexical_cast<uint16_t>( data[6] ), // key tag
                                                     data[7],                                  // signer
                                                     signature ) );
        }

        ResourceDataPtr parseRecordDS( const std::vector<std::string> &data )
        {
            auto digest_data = data.begin();
            for ( int i = 0 ; i < 3 ; i++ ) digest_data++;
            auto digest = decode_from_base64_strings( digest_data, data.end() );

            return ResourceDataPtr( new RecordDS( boost::lexical_cast<uint16_t>( data[0] ), // key tag
                                                  boost::lexical_cast<uint16_t>( data[1] ),  // algorithm
                                                  boost::lexical_cast<uint16_t>( data[2] ),  // digest type
                                                  digest ) );
        }

        ResourceDataPtr parseRecordDNSKey( const std::vector<std::string> &data )
        {
            auto public_key_data = data.begin();
            for ( int i = 0 ; i < 3 ; i++ ) public_key_data++;
            auto public_key = decode_from_base64_strings( public_key_data, data.end() );

            return ResourceDataPtr( new RecordDNSKey( boost::lexical_cast<uint16_t>( data[0] ), // FLAG
                                                      boost::lexical_cast<uint16_t>( data[2] ),  // algorithm
                                                      public_key ) );                           // Public Key
        }

        ResourceDataPtr parseRecordNSEC( const std::vector<std::string> &data )
        {
            std::vector<Type> types;
            for ( unsigned int i = 1 ; i < data.size() ; i++ ) {
                types.push_back( string_to_type_code( data[i] ) );
            }
            return ResourceDataPtr( new RecordNSEC( data[0], types ) );
        }

        std::shared_ptr<Zone> load( const Domainname &apex, const std::string &config )
        {
            std::shared_ptr<Zone> zone( new Zone( apex ) );

	    boost::char_separator<char> sep( "\r\n" );
            boost::tokenizer<boost::char_separator<char>> tokens( config, sep );

            for ( auto line_pos = tokens.begin(); line_pos != tokens.end() ; line_pos++ ) {
                std::string line = eraseLastSpace( eraseComment( *line_pos ) );
                if ( line == "" )
                    continue;

                auto new_rrset = parseLine( line );
                auto rrset = zone->findRRSet( new_rrset->getOwner(), new_rrset->getType() );
                if ( rrset.get() == nullptr ) {
                    zone->add( new_rrset );
                }
                else {
                    rrset->add( (*new_rrset)[0] );
                }
            }
            return zone;
        }

        std::string dump( const Zone &zone )
        {
            std::ostringstream zonefile;
            for ( auto node_itr = zone.begin() ; node_itr != zone.end() ; node_itr++ ) {
                for ( auto rrset_itr = node_itr->second->begin() ;
                      rrset_itr != node_itr->second->end() ;
                      rrset_itr++ ) {
                    Domainname owner = rrset_itr->second->getOwner();
                    Type       type  = rrset_itr->second->getType();
                    TTL        ttl   = rrset_itr->second->getTTL();

                    for ( auto data_ptr = rrset_itr->second->begin() ;
                          data_ptr != rrset_itr->second->end() ;
                          data_ptr++ ) {

                        zonefile << owner.toString()            << "\t"
                                 << ttl                         << "\t"
                                 << "IN"                        << "\t"
                                 << type_code_to_string( type ) << "\t"
                                 << (*data_ptr)->toZone()       << std::endl;
                        
                        }
                }
            }
            return zonefile.str();
        }
    }
}
