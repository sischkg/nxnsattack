#include "dns_server.hpp"
#include "threadpool.hpp"
#include "logger.hpp"
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/numeric/conversion/cast.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <iostream>
#include <signal.h>
#include <stdexcept>
#include <time.h>

namespace dns
{
    void DNSServer::addTSIGKey( const std::string &name, const TSIGKey &key )
    {
        mNameToKey.insert( std::pair<std::string, TSIGKey>( name, key ) );
    }

    ResponseCode DNSServer::verifyTSIGQuery( const MessageInfo &query, const uint8_t *begin, const uint8_t *end ) const
    {
        auto tsig_key = mNameToKey.find( query.mTSIGRR.mKeyName.toString() );
        if ( tsig_key == mNameToKey.end() )
            return BADKEY;

        TSIGInfo tsig_info;
        tsig_info.mName       = query.mTSIGRR.mKeyName.toString();
        tsig_info.mKey        = tsig_key->second.key;
        tsig_info.mAlgorithm  = tsig_key->second.algorithm;
        tsig_info.mSignedTime = query.mTSIGRR.mSignedTime;
        tsig_info.mFudge      = query.mTSIGRR.mFudge;
        tsig_info.mMAC        = query.mTSIGRR.mMAC;
        tsig_info.mOriginalID = query.mTSIGRR.mOriginalID;
        tsig_info.mError      = query.mTSIGRR.mError;
        tsig_info.mOther      = query.mTSIGRR.mOther;

        time_t now = time( NULL );
        if ( query.mTSIGRR.mSignedTime > now - query.mTSIGRR.mFudge &&
             query.mTSIGRR.mSignedTime < now + query.mTSIGRR.mFudge ) {
            return BADTIME;
        }

        if ( verifyTSIGResourceRecord( tsig_info, query, WireFormat( begin, end ) ) ) {
            return NO_ERROR;
        }

        return BADSIG;
    }

    MessageInfo DNSServer::generateTSIGErrorResponse( const MessageInfo &query, ResponseCode rcode ) const
    {
        MessageInfo response;

        return response;
    }


    void DNSServer::startUDPServer()
    {
        try {
            udpv4::ServerParameters params;
            params.mAddress = mBindAddress;
            params.mPort    = mBindPort;
            udpv4::Server dns_receiver( params );

            utils::ThreadPool pool( mThreadCount );
            pool.start();

            while ( true ) {
                udpv4::PacketInfo request = dns_receiver.receivePacket();
                pool.submit( boost::bind( &DNSServer::replyOverUDP, this, boost::ref( dns_receiver ), request ) );
            }

            pool.join();

        } catch ( std::runtime_error &e ) {
	    BOOST_LOG_TRIVIAL(debug) << "dns.server.udp: exception: " << e.what();
        }
    }

    void DNSServer::replyOverUDP( udpv4::Server &dns_receiver, udpv4::PacketInfo recv_data )
    {
        try {
	    BOOST_LOG_TRIVIAL(debug) << "dns.server.udp: received DNS message from "
				     << recv_data.mSourceAddress << ":" << recv_data.mSourcePort << ".";
	    
            MessageInfo query = parseDNSMessage( recv_data.begin(), recv_data.end() );

	    BOOST_LOG_TRIVIAL(trace) << "dns.server.udp: " << "Query: " << query; 

            if ( query.mIsTSIG ) {
                ResponseCode rcode = verifyTSIGQuery( query, recv_data.begin(), recv_data.end() );
                if ( rcode != NO_ERROR ) {
                    MessageInfo response_info = generateTSIGErrorResponse( query, rcode );
                }
            }

            MessageInfo response_info = generateResponse( query, false );

            if ( isDebug() )
		BOOST_LOG_TRIVIAL(trace) << "dns.server.udp: Response: " << response_info;

            uint32_t requested_max_payload_size = 512;
            if ( query.isEDNS0() &&
                 query.mOptPseudoRR.mPayloadSize > 512 ) {
                requested_max_payload_size = query.mOptPseudoRR.mPayloadSize;
                if ( query.mOptPseudoRR.mPayloadSize > 4096 )
                    query.mOptPseudoRR.mPayloadSize = 4096;
            }

            if ( isDebug() )
		BOOST_LOG_TRIVIAL(debug) << "dns.server.udp: response size(UDP): " << response_info.getMessageSize();
            if ( response_info.getMessageSize() > requested_max_payload_size ) {
                if ( isDebug() )
                    BOOST_LOG_TRIVIAL(debug) << "dns.server.udp: response TC=1: " << response_info.getMessageSize();
                response_info.mTruncation = 1;
                            
                response_info.clearAnswerSection();
                response_info.clearAuthoritySection();
                response_info.clearAdditionalSection();
            }
		    
            WireFormat response_packet;
            response_info.generateMessage( response_packet );

            modifyMessage( query, response_packet );
		    
            udpv4::ClientParameters client;
            client.mAddress = recv_data.mSourceAddress;
            client.mPort    = recv_data.mSourcePort;
            dns_receiver.sendPacket( client, response_packet );

	    BOOST_LOG_TRIVIAL(debug) << "dns.server.udp: sent DNS message to "
				     << client.mAddress << ":" << client.mPort << ".";
        }
        catch ( std::runtime_error &e ) {
	    BOOST_LOG_TRIVIAL(error) << "dns.server.udp: recv/send response failed(" << e.what() << ") from "
				     << recv_data.mSourceAddress << ":" << recv_data.mSourcePort << ".";
        }

    }

    void DNSServer::sendZone( const MessageInfo &query, tcpv4::ConnectionPtr &connection )
    {
        generateAXFRResponse( query, connection );
    }

    void DNSServer::startTCPServer()
    {
        try {
            tcpv4::ServerParameters params;
            params.mAddress = mBindAddress;
            params.mPort    = mBindPort;
            tcpv4::Server dns_receiver( params );

            while ( true ) {

                try {
                    tcpv4::ConnectionPtr connection = dns_receiver.acceptConnection();
                    boost::thread tcp_thread( &DNSServer::replyOverTCP, this, connection );
                    tcp_thread.detach();
                }
                catch ( std::runtime_error &e ) {
                    BOOST_LOG_TRIVIAL(error) << "dns,server.tcp: recv/send response failed(" << e.what() << ").";
                }
            }
        }
        catch ( std::runtime_error &e ) {
	    BOOST_LOG_TRIVIAL(error) << "dns.server.tcp: exception: " << e.what() << std::endl;
        }
    }


    void DNSServer::replyOverTCP( tcpv4::ConnectionPtr connection )
    {
        try {
	    BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: connected.";

            PacketData size_data = connection->receive( 2 );
            if ( size_data.size() < 2 ) {
                throw std::runtime_error( "cannot get size of dns message" );
            }
            uint16_t size = ntohs( *( reinterpret_cast<const uint16_t *>( &size_data[ 0 ] ) ) );
	    BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: message size: " << size;

            PacketData recv_data = connection->receive( size );
            MessageInfo query    = parseDNSMessage( &recv_data[ 0 ], &recv_data[ 0 ] + recv_data.size() );

	    BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: parsed query." << size;
	    BOOST_LOG_TRIVIAL(trace) << "dns.server.tcp: query: " << query;

            if ( query.mQuestionSection[ 0 ].mType == dns::TYPE_AXFR ||
                 query.mQuestionSection[ 0 ].mType == dns::TYPE_IXFR ) {
		BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: sending zone";
                sendZone( query, connection );
            }
            else {
                MessageInfo response_info = generateResponse( query, true );
                WireFormat  response_stream;

		BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: response size(TCP): " << response_info.getMessageSize();

                if ( response_info.getMessageSize() > 0xffff ) {
		    BOOST_LOG_TRIVIAL(info) << "dns.server.tcp: too large size: " << response_info.getMessageSize();
		    BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: sending SREVFAIL." << response_info.getMessageSize();
		    
                    response_info.mResponseCode = SERVER_ERROR;
                    response_info.clearAnswerSection();
                    response_info.clearAuthoritySection();
                    response_info.clearAdditionalSection();
                }

                response_info.generateMessage( response_stream );
		BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: generated DNS Message.";
                modifyMessage( query, response_stream );
			
                uint16_t send_size = htons( response_stream.size() );
                connection->send( reinterpret_cast<const uint8_t *>( &send_size ), sizeof( send_size ) );
                connection->send( response_stream );
            }
	    BOOST_LOG_TRIVIAL(debug) << "dns.server.tcp: sent response.";
        } 
        catch ( std::runtime_error &e ) {
	    BOOST_LOG_TRIVIAL(error) << "dns.server.tcp: recv/send response failed(" << e.what() << ").";
        }
    }

    void DNSServer::start()
    {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGQUIT);
        sigaddset(&set, SIGUSR1);
        sigaddset(&set, SIGPIPE);
        int s = pthread_sigmask(SIG_BLOCK, &set, NULL);
        if ( s != 0 ) {
            throw std::runtime_error( "cannot set sigmask" );
        }

        boost::thread udp_server_thread( &DNSServer::startUDPServer, this );
        boost::thread tcp_server_thread( &DNSServer::startTCPServer, this );

        udp_server_thread.join();
        tcp_server_thread.join();
    }
}
