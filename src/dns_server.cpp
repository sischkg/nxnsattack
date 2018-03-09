#include "dns_server.hpp"
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/shared_ptr.hpp>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <time.h>

namespace dns
{
    void ignore_sigpipe( int )
    {
    }

    void DNSServer::addTSIGKey( const std::string &name, const TSIGKey &key )
    {
        mNameToKey.insert( std::pair<std::string, TSIGKey>( name, key ) );
    }

    ResponseCode DNSServer::verifyTSIGQuery( const PacketInfo &query, const uint8_t *begin, const uint8_t *end )
    {
        auto tsig_key = mNameToKey.find( query.tsig_rr.mKeyName.toString() );
        if ( tsig_key == mNameToKey.end() )
            return BADKEY;

        TSIGInfo tsig_info;
        tsig_info.mName       = query.tsig_rr.mKeyName.toString();
        tsig_info.mKey        = tsig_key->second.key;
        tsig_info.mAlgorithm  = tsig_key->second.algorithm;
        tsig_info.mSignedTime = query.tsig_rr.mSignedTime;
        tsig_info.mFudge      = query.tsig_rr.mFudge;
        tsig_info.mMAC        = query.tsig_rr.mMAC;
        tsig_info.mOriginalID = query.tsig_rr.mOriginalID;
        tsig_info.mError      = query.tsig_rr.mError;
        tsig_info.mOther      = query.tsig_rr.mOther;

        time_t now = time( NULL );
        if ( query.tsig_rr.mSignedTime > now - query.tsig_rr.mFudge &&
             query.tsig_rr.mSignedTime < now + query.tsig_rr.mFudge ) {
            return BADTIME;
        }

        if ( verifyTSIGResourceRecord( tsig_info, query, WireFormat( begin, end ) ) ) {
            return NO_ERROR;
        }

        return BADSIG;
    }

    PacketInfo DNSServer::generateTSIGErrorResponse( const PacketInfo &query, ResponseCode rcode )
    {
        PacketInfo response;

        return response;
    }


    void DNSServer::startUDPServer()
    {
        try {
            udpv4::ServerParameters params;
            params.bind_address = mBindAddress;
            params.bind_port    = mBindPort;
            udpv4::Server dns_receiver( params );

            while ( true ) {
                try {
                    udpv4::PacketInfo recv_data = dns_receiver.receivePacket();
                    PacketInfo        query     = parseDNSMessage( recv_data.begin(), recv_data.end() );

                    if ( isDebug() )
                        std::cerr << "Query:" << query << std::endl; 

                    if ( query.tsig ) {
                        ResponseCode rcode = verifyTSIGQuery( query, recv_data.begin(), recv_data.end() );
                        if ( rcode != NO_ERROR ) {
                            PacketInfo response_info = generateTSIGErrorResponse( query, rcode );
                        }
                    }

                    PacketInfo response_info = generateResponse( query, false );

                    if ( isDebug() )
                        std::cerr << "Response:" << response_info << std::endl; 

		    if ( mTruncation ) {
			uint32_t requested_max_payload_size = 512;
			if ( query.isEDNS0() &&
			     query.opt_pseudo_rr.mPayloadSize > 512 ) {
			    requested_max_payload_size = query.opt_pseudo_rr.mPayloadSize;
			    if ( query.opt_pseudo_rr.mPayloadSize > 4096 )
				query.opt_pseudo_rr.mPayloadSize = 4096;
			}

                        if ( isDebug() )
                            std::cerr << "response size(UDP): " << response_info.getMessageSize() << std::endl;
			if ( response_info.getMessageSize() > requested_max_payload_size ) {
                            if ( isDebug() )
                                std::cerr << "response TC=1: " << response_info.getMessageSize() << std::endl;
			    response_info.truncation = 1;
                            
			    response_info.clearAnswerSection();
			    response_info.clearAuthoritySection();
			    response_info.clearAdditionalInfomationSection();
			}
		    }
		    
                    WireFormat response_packet;
                    response_info.generateMessage( response_packet );

		    modifyMessage( response_packet );
		    
                    udpv4::ClientParameters client;
                    client.destination_address = recv_data.source_address;
                    client.destination_port    = recv_data.source_port;
                    dns_receiver.sendPacket( client, response_packet );
                } catch ( std::runtime_error &e ) {
                    std::cerr << "recv/send response failed(" << e.what() << ")." << std::endl;
                }
            }
        } catch ( std::runtime_error &e ) {
            std::cerr << "caught " << e.what() << std::endl;
        }
    }

    void DNSServer::sendZone( const PacketInfo &query, tcpv4::ConnectionPtr connection )
    {
        generateAXFRResponse( query, connection );
    }

    void DNSServer::startTCPServer()
    {
        try {
            tcpv4::ServerParameters params;
            params.bind_address = mBindAddress;
            params.bind_port    = mBindPort;

            tcpv4::Server dns_receiver( params );

            while ( true ) {

                try {
                    tcpv4::ConnectionPtr connection = dns_receiver.acceptConnection();
                    PacketData           size_data  = connection->receive( 2 );
                    if ( size_data.size() < 2 ) {
                        throw std::runtime_error( "cannot get message of dns message" );
                    }
                    uint16_t size = ntohs( *( reinterpret_cast<const uint16_t *>( &size_data[ 0 ] ) ) );
                    if ( isDebug() )
                        std::cerr << "DNS message size: " << size << std::endl;

                    PacketData recv_data = connection->receive( size );
                    PacketInfo query     = parseDNSMessage( &recv_data[ 0 ], &recv_data[ 0 ] + recv_data.size() );
                    if ( query.question_section[ 0 ].mType == dns::TYPE_AXFR ||
                         query.question_section[ 0 ].mType == dns::TYPE_IXFR ) {
                        boost::thread axfr_thread( &DNSServer::sendZone, this, query, connection );
                        axfr_thread.detach();
                    } else {
                        PacketInfo response_info = generateResponse( query, true );
                        WireFormat response_stream;

                        if ( isDebug() )
                            std::cerr << "response size(TCP): " << response_info.getMessageSize() << std::endl;

                        if ( response_info.getMessageSize() > 0xffff ) {
                            std::cerr << "too large size: " << response_info.getMessageSize() << std::endl;
                            response_info.response_code = SERVER_ERROR;
                            response_info.clearAnswerSection();
                            response_info.clearAuthoritySection();
                            response_info.clearAdditionalInfomationSection();
                        }

			response_info.generateMessage( response_stream );
			modifyMessage( response_stream );
			
                        uint16_t send_size = htons( response_stream.size() );
                        connection->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
                        connection->send( response_stream );
                    }
                } catch ( std::runtime_error &e ) {
                    std::cerr << "recv/send response failed(" << e.what() << ")." << std::endl;
                }
            }
        } catch ( std::runtime_error &e ) {
            std::cerr << "caught " << e.what() << std::endl;
        }
    }

    void DNSServer::start()
    {
        signal( SIGPIPE, ignore_sigpipe );

        boost::thread udp_server_thread( &DNSServer::startUDPServer, this );
        boost::thread tcp_server_thread( &DNSServer::startTCPServer, this );

        udp_server_thread.join();
        tcp_server_thread.join();
    }
}
