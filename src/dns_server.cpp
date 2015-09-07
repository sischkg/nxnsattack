#include "dns_server.hpp"
#include <stdexcept>
#include <iostream>
#include <time.h>
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/thread.hpp>

namespace dns
{

    void DNSServer::startUDPServer()
    {
	try {
	    udpv4::ServerParameters params;
	    params.bind_address = bind_address;
	    params.bind_port    = bind_port;
	    udpv4::Server dns_receiver( params );

	    while( true ) {
		try {
		    udpv4::PacketInfo recv_data     = dns_receiver.receivePacket();
		    QueryPacketInfo   query         = parse_dns_query_packet( recv_data.begin(), recv_data.end() );
		    ResponseInfo      response_info = generateResponse( query );

		    PacketData response_packet = generate_dns_packet( response_info.header,
								      response_info.question_section, 
								      response_info.answer_section,
								      response_info.authority_section,
								      response_info.additional_infomation_section );
		
		    udpv4::ClientParameters client;
		    client.destination_address = recv_data.source_address;
		    client.destination_port    = recv_data.source_port;
		    dns_receiver.sendPacket( client, response_packet );
		}
		catch( std::runtime_error &e ) {
		    std::cerr << "send response failed," << std::endl;
		    std::exit(1 );
		}
	    }
	}
	catch ( std::runtime_error &e ) {
	    std::cerr << "caught " << e.what() << std::endl;
	}
    }


    void DNSServer::startTCPServer()
    {
	try {
	    tcpv4::ServerParameters params;
	    params.bind_address = bind_address;
	    params.bind_port    = bind_port;

	    tcpv4::Server dns_receiver( params );

	    while( true ) {

		try {
		    tcpv4::ConnectionPtr connection = dns_receiver.acceptConnection();
		    PacketData size_data = connection->receive( 2 );
		    uint16_t size = ntohs( *( reinterpret_cast<const uint16_t *>( &size_data[0] ) ) );

		    PacketData      recv_data     = connection->receive( size );
		    QueryPacketInfo query         = parse_dns_query_packet( &recv_data[0], &recv_data[0] + recv_data.size() );
		    ResponseInfo    response_info = generateResponse( query );

		    PacketData response_packet = generate_dns_packet( response_info.header,
								      response_info.question_section, 
								      response_info.answer_section,
								      response_info.authority_section,
								      response_info.additional_infomation_section );
		
		    uint16_t send_size = htons( response_packet.size() );
		    connection->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof(send_size) );
		    connection->send( response_packet );
		}
		catch( std::runtime_error &e ) {
		    std::cerr << "send response failed(" << e.what() << ")." << std::endl;
		    std::exit(1 );
		}
	    }
	}
	catch ( std::runtime_error &e ) {
	    std::cerr << "caught " << e.what() << std::endl;
	}
    }


    void DNSServer::start()
    {
	boost::thread udp_server_thread( &DNSServer::startUDPServer, this );
	boost::thread tcp_server_thread( &DNSServer::startTCPServer, this );

	udp_server_thread.join();
	tcp_server_thread.join();
    }
}
