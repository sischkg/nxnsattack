#ifndef SIGNED_ZONE_HPP
#define SIGNED_ZONE_HPP

#include "zone.hpp"
#include "zonesigner.hpp"

namespace dns
{
    class SignedZoneImp;
    
    class SignedZone : public Zone
    {
    public:
        SignedZone( const Domainname &zone_name, const std::string &ksk_config, const std::string &zsk_config,
                    const std::vector<uint8_t> &salt = std::vector<uint8_t>(), uint16_t iterate = 1, HashAlgorithm alog = DNSSEC_SHA1,
                    bool enable_nsec = true, bool enable_nsec3 = false );

        void add( std::shared_ptr<RRSet> rrset );
        MessageInfo getAnswer( const MessageInfo &query ) const;
        NodePtr  findNode( const Domainname &domainname ) const;
        RRSetPtr findRRSet( const Domainname &domainname, Type type ) const;
	std::vector<std::shared_ptr<RecordDS>> getDSRecords() const; 
        void verify() const;
        void setup();
        std::shared_ptr<RRSet> signRRSet( const RRSet &rrset );

        static void initialize();
    private:
	std::shared_ptr<SignedZoneImp> mImp;
    };

}

#endif

