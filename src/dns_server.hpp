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
        Domainname algorithm;
        PacketData key;

        TSIGKey( const Domainname &a, const PacketData &k ) : algorithm( a ), key( k )
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

        ResponseCode verifyTSIGQuery( const MessageInfo &query, const uint8_t *begin, const uint8_t *end ) const;
        MessageInfo generateTSIGErrorResponse( const MessageInfo &query, ResponseCode rcode ) const;
	MessageInfo generateErrorResponse( const MessageInfo &query, ResponseCode rcode ) const;
        void sendZone( const MessageInfo &info, tcpv4::ConnectionPtr &connection );
        bool isDebug() const { return mDebug; }
    public:
        DNSServer( const std::string &address = "0.0.0.0", uint16_t port = 53, unsigned int thread_count = 1 )
            : mBindAddress( address ), mBindPort( port ), mThreadCount( thread_count )
        {}

        ~DNSServer()
        {}

        virtual MessageInfo generateResponse( const MessageInfo &query, bool via_tcp ) const = 0;
        virtual void generateAXFRResponse( const MessageInfo &query, tcpv4::ConnectionPtr &conn ) const {}
	virtual void modifyMessage( const MessageInfo &query, WireFormat &messge ) const {} 
        void start();

        void addTSIGKey( const std::string &name, const TSIGKey &key );
    };
}

#endif
