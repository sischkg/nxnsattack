#ifndef AUTH_SERVER_HPP
#define AUTH_SERVEE_HPP

#include "dns_server.hpp"
#include "zone.hpp"
#include "zoneloader.hpp"

class AuthServer : public dns::DNSServer
{
public:
    AuthServer( const std::string &addr, uint16_t port, bool debug )
        : dns::DNSServer( addr, port, debug )
    {}

    void load( const std::string &apex, const std::string &filename );
    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp );
private:
    std::shared_ptr<dns::Zone> zone;
};


#endif
