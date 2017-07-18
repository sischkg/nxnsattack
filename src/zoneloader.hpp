#ifndef ZONELOADER_HPP
#define ZONELOADER_HPP

#include "zone.hpp"
#include <yaml-cpp/yaml.h>

/**********************************
      
- owner:example.com:
  type: SOA
  ttl: 3600
  record:
  - mname: ns01.example.com
    rname: hostmaster.example.com
    serial: 2017050101
    refresh: 3600
    retry: 1800
    expire: 8640000
    minimum: 3600
- owner: example.com:
  ttl: 86400
  type: NS
  record:
  - nameserver: ns01.example.com
  - nameserver: ns02.example.com
- owner: ns01.example.com:
  ttl: 86400
  type: A
  record:
  - address: 192.168.0.11
- owner: ns02.example.com:
  ttl: 86400
  type: A
  record:
  - address: 192.168.0.12
- owner: www.example.com:
  ttl: 3600
  type: A
  record:
  - address: 192.168.0.101
  - address: 192.168.0.102

************************************/

namespace dns
{

    class ZoneConfigError : std::runtime_error
    {
    public:
        ZoneConfigError( const std::string &msg )
            : std::runtime_error( msg )
        {}
    };

    namespace yamlloader
    {
        ResourceDataPtr parseRecordA( const YAML::Node & );
        ResourceDataPtr parseRecordAAAA( const YAML::Node & );
        ResourceDataPtr parseRecordNS( const YAML::Node & );
        ResourceDataPtr parseRecordMX( const YAML::Node & );
        ResourceDataPtr parseRecordSOA( const YAML::Node & );
        ResourceDataPtr parseRecordCNAME( const YAML::Node & );
        ResourceDataPtr parseRecordDNAME( const YAML::Node & );
        ResourceDataPtr parseRecordRRSIG( const YAML::Node & );
        ResourceDataPtr parseRecordDS( const YAML::Node & );
        ResourceDataPtr parseRecordDNSKey( const YAML::Node & );
        ResourceDataPtr parseRecordNSEC( const YAML::Node & );
    
        std::shared_ptr<RRSet> parseRRSet( const YAML::Node &node );

        std::shared_ptr<Zone> load( const Domainname &apex, const std::string &config );
    }

    namespace full
    {
        ResourceDataPtr parseRecordA( const std::vector<std::string> & );
        ResourceDataPtr parseRecordAAAA( const std::vector<std::string> & );
        ResourceDataPtr parseRecordNS( const std::vector<std::string> & );
        ResourceDataPtr parseRecordMX( const std::vector<std::string> & );
        ResourceDataPtr parseRecordSOA( const std::vector<std::string> & );
        ResourceDataPtr parseRecordCNAME( const std::vector<std::string> & );
        ResourceDataPtr parseRecordDNAME( const std::vector<std::string> & );
        ResourceDataPtr parseRecordTXT( const std::vector<std::string> & );
        ResourceDataPtr parseRecordSPF( const std::vector<std::string> & );
        ResourceDataPtr parseRecordRRSIG( const std::vector<std::string> & );
        ResourceDataPtr parseRecordDS( const std::vector<std::string> & );
        ResourceDataPtr parseRecordDNSKey( const std::vector<std::string> & );
        ResourceDataPtr parseRecordNSEC( const std::vector<std::string> & );
    
        std::shared_ptr<RRSet> parseRRSet( const std::vector<std::string> & );

        std::shared_ptr<Zone> load( const Domainname &apex, const std::string &config );
    }

    uint32_t timestamp_to_epoch( const std::string &timestamp );
    std::vector<std::string> parse_txt( const std::string &s );
}

#endif

