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
        RDATAPtr parseRecordA( const YAML::Node & );
        RDATAPtr parseRecordAAAA( const YAML::Node & );
        RDATAPtr parseRecordNS( const YAML::Node & );
        RDATAPtr parseRecordMX( const YAML::Node & );
        RDATAPtr parseRecordSOA( const YAML::Node & );
        RDATAPtr parseRecordCNAME( const YAML::Node & );
        RDATAPtr parseRecordDNAME( const YAML::Node & );
        RDATAPtr parseRecordTXT( const YAML::Node & );
        RDATAPtr parseRecordSPF( const YAML::Node & );
        RDATAPtr parseRecordCAA( const YAML::Node & );
        RDATAPtr parseRecordRRSIG( const YAML::Node & );
        RDATAPtr parseRecordDS( const YAML::Node & );
        RDATAPtr parseRecordDNSKEY( const YAML::Node & );
        RDATAPtr parseRecordNSEC( const YAML::Node & );
    
        std::shared_ptr<RRSet> parseRRSet( const YAML::Node &node );

        void load( Zone &zone, const Domainname &apex, const std::string &config );
    }

    namespace full
    {
        RDATAPtr parseRecordA( const std::vector<std::string> & );
        RDATAPtr parseRecordAAAA( const std::vector<std::string> & );
        RDATAPtr parseRecordNS( const std::vector<std::string> & );
        RDATAPtr parseRecordMX( const std::vector<std::string> & );
        RDATAPtr parseRecordSOA( const std::vector<std::string> & );
        RDATAPtr parseRecordCNAME( const std::vector<std::string> & );
        RDATAPtr parseRecordDNAME( const std::vector<std::string> & );
        RDATAPtr parseRecordTXT( const std::vector<std::string> & );
        RDATAPtr parseRecordSPF( const std::vector<std::string> & );
        RDATAPtr parseRecordCAA( const std::vector<std::string> & );
        RDATAPtr parseRecordSRV( const std::vector<std::string> & );
        RDATAPtr parseRecordRRSIG( const std::vector<std::string> & );
        RDATAPtr parseRecordDS( const std::vector<std::string> & );
        RDATAPtr parseRecordDNSKEY( const std::vector<std::string> & );
        RDATAPtr parseRecordNSEC( const std::vector<std::string> & );
    
        std::shared_ptr<RRSet> parseRRSet( const std::vector<std::string> & );

        void load( Zone &zone, const Domainname &apex, const std::string &config );
    }

    uint32_t convertTimestampToEpoch( const std::string &timestamp );
    std::vector<std::string> parseTXT( const std::string &s );
}

#endif

