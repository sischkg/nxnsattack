#ifndef DNS_SERVER_HPP
#define DNS_SERVER_HPP

#include "udpv4server.hpp"
#include "tcpv4server.hpp"
#include "dns.hpp"
#include <string>

namespace dns
{
    struct ResponseInfo {
	PacketHeaderField                 header;    
	std::vector<QuestionSectionEntry> question_section;
	std::vector<ResponseSectionEntry> answer_section;
	std::vector<ResponseSectionEntry> authority_section;
	std::vector<ResponseSectionEntry> additional_infomation_section;
    };

    class DNSServer
    {
    private:
	std::string bind_address;
	uint16_t    bind_port;

	void startUDPServer();
	void startTCPServer();

    public:
	DNSServer( const std::string &address = "0.0.0.0",
		   uint16_t           port = 53 )
	    : bind_address( address ), bind_port( port )
	{}

	~DNSServer(){}

	virtual PacketInfo generateResponse( const PacketInfo &query, bool via_tcp ) = 0;

	void start();
    };
    
}

#endif
