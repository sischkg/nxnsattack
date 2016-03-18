#ifndef DNS_SERVER_HPP
#define DNS_SERVER_HPP

#include "dns.hpp"
#include "tcpv4server.hpp"
#include "udpv4server.hpp"
#include "wireformat.hpp"
#include <map>
#include <string>
#include <boost/thread.hpp>

namespace dns
{
    struct ResponseInfo {
        PacketHeaderField                 header;
        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResponseSectionEntry> answer_section;
        std::vector<ResponseSectionEntry> authority_section;
        std::vector<ResponseSectionEntry> additional_infomation_section;
    };

    struct TSIGKey {
        std::string algorithm;
        PacketData  key;

        TSIGKey( const std::string &a, const PacketData &k ) : algorithm( a ), key( k )
        {
        }
    };

    class DNSServer
    {
    private:
        std::string mBindAddress;
        uint16_t    mBindPort;
        std::map<std::string, TSIGKey> mNameToKey;

        void startUDPServer();
        void startTCPServer();

        ResponseCode verifyTSIGQuery( const PacketInfo &query, const uint8_t *begin, const uint8_t *end );
        PacketInfo generateTSIGErrorResponse( const PacketInfo &query, ResponseCode rcode );

	void sendZone( const PacketInfo &info, tcpv4::ConnectionPtr connection );
    public:
        DNSServer( const std::string &address = "0.0.0.0", uint16_t port = 53 )
            : mBindAddress( address ), mBindPort( port )
        {
        }

        ~DNSServer()
        {
        }

        virtual PacketInfo generateResponse( const PacketInfo &query, bool via_tcp ) = 0;
        virtual void generateAXFRResponse( const PacketInfo &query, tcpv4::ConnectionPtr &conn )
        {
        }

        void start();

        void addTSIGKey( const std::string &name, const TSIGKey &key );
    };
}

#endif
