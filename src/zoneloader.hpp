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
  - address: 192.168.11
- owner: ns02.example.com:
  ttl: 86400
  type: A
  record:
  - address: 192.168.12
- owner: www.example.com:
  ttl: 3600
  type: A
  record:
  - address: 192.168.101
  - address: 192.168.102

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

    ResourceDataPtr parseRecordA( const YAML::Node & );
    ResourceDataPtr parseRecordNS( const YAML::Node & );
    ResourceDataPtr parseRecordSOA( const YAML::Node & );
    
    std::shared_ptr<RRSet> parseRRSet( const YAML::Node &node );

    std::shared_ptr<Zone> load( const Domainname &apex, const char *config );

}

#endif

