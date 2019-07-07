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

    struct DNSServerParameters {
	std::string  mBindAddress;
	uint16_t     mBindPort;
	bool         mMulticast;
	bool         mDebug;
	unsigned int mThreadCount;

	DNSServerParameters()
	    : mBindAddress( "0.0.0.0" ),
	      mBindPort( 53 ),
	      mMulticast( false ),
	      mDebug( false ),
	      mThreadCount( 1 )
	{}
    };

    class DNSServer
    {
    private:
	DNSServerParameters            mServerParameters;
        bool                           mDebug;
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
        DNSServer( const DNSServerParameters &params )
            : mServerParameters( params ),
	      mDebug( params.mDebug )
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
