#ifndef DNS_SERVER_HPP
#define DNS_SERVER_HPP

#include "dns.hpp"
#include "tcpv4server.hpp"
#include "udpv4server.hpp"
#include "wireformat.hpp"
#include "threadpool.hpp"
#include <boost/thread.hpp>
#include <map>
#include <string>

namespace dns
{
    struct ResponseInfo {
        PacketHeaderField                 header;
        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResourceRecord> answer_section;
        std::vector<ResourceRecord> authority_section;
        std::vector<ResourceRecord> additional_infomation_section;
    };

    struct TSIGKey {
        std::string algorithm;
        PacketData  key;

        TSIGKey( const std::string &a, const PacketData &k ) : algorithm( a ), key( k )
        {}
    };

    class DNSServer
    {
    private:
        std::string  mBindAddress;
        uint16_t     mBindPort;
        bool         mDebug;
        unsigned int mThreadCount;
        std::map<std::string, TSIGKey> mNameToKey;

        void startUDPServer();
        void replyOverUDP( udpv4::Server &server, udpv4::PacketInfo );
        void startTCPServer();
        void replyOverTCP( tcpv4::ConnectionPtr connection );

        ResponseCode verifyTSIGQuery( const PacketInfo &query, const uint8_t *begin, const uint8_t *end ) const;
        PacketInfo generateTSIGErrorResponse( const PacketInfo &query, ResponseCode rcode ) const;

        void sendZone( const PacketInfo &info, tcpv4::ConnectionPtr connection );
        bool isDebug() const { return mDebug; }
    public:
        DNSServer( const std::string &address = "0.0.0.0", uint16_t port = 53, bool debug = false, unsigned int thread_count = 1 )
            : mBindAddress( address ), mBindPort( port ), mDebug( debug ), mThreadCount( thread_count )
        {}

        ~DNSServer()
        {}

        virtual PacketInfo generateResponse( const PacketInfo &query, bool via_tcp ) const = 0;
        virtual void generateAXFRResponse( const PacketInfo &query, tcpv4::ConnectionPtr &conn ) const {}
	virtual void modifyMessage( const PacketInfo &query, WireFormat &messge ) const {} 
        void start();

        void addTSIGKey( const std::string &name, const TSIGKey &key );
    };
}

#endif
