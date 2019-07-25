#include "dns.hpp"
#include "udpv4client.hpp"
#include "tcpv4client.hpp"
#include "rrgenerator.hpp"
#include "shufflebytes.hpp"
#include "logger.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>
#include <fstream>
#include <time.h>
#include <signal.h>

const char *DNS_SERVER_ADDRESS       = "127.0.0.1";
const uint32_t DEFAULT_INTERVAL_MSEC = 500;

namespace po = boost::program_options;

std::vector<dns::ResourceRecord> newRRs( const dns::RRSet &rrset )
{
    std::vector<dns::ResourceRecord> rrs;

    for( auto rr : rrset.getRRSet() ) {
        dns::ResourceRecord r;
        r.mDomainname = rrset.getOwner();
        r.mType       = rrset.getType();
        r.mClass      = rrset.getClass();
        r.mTTL        = rrset.getTTL();
        r.mRData      = rr;
        rrs.push_back( r );
    }
    return rrs;
}


std::string now_string();

std::string now_string()
{
    time_t t = time(NULL);
    tm *tmp = localtime(&t);
    if ( tmp == nullptr) {
        exit(EXIT_FAILURE);
    }

    char outstr[256];
    if (strftime(outstr, sizeof(outstr), "%Y-%m-%d %H:%M:%S", tmp) == 0) {
        std::cerr << "strftime returned 0" << std::endl;
        exit(EXIT_FAILURE);
    }

    return outstr;
}


void ignore_signal( int sig )
{}

void generate_query( const dns::Domainname &basename,
                     const dns::Domainname &another_basename,
                     dns::DomainnameGenerator &label_generator,
                     dns::ResourceRecordGenerator &rr_generator,
                     dns::OptionGenerator &option_generator,
                     bool is_randomize,
                     WireFormat &ref_query )
{
    dns::MessageInfo packet_info;

    if ( dns::getRandom( 5 ) ) {
        packet_info.mOptPseudoRR.mDomainname  = ".";
        packet_info.mOptPseudoRR.mPayloadSize = dns::getRandom( 0xffff );
        packet_info.mOptPseudoRR.mRCode       = dns::getRandom( 0xff );
        packet_info.mOptPseudoRR.mVersion     = 0;
        packet_info.mOptPseudoRR.mDOBit       = 1;
        packet_info.mIsEDNS0 = true;

        unsigned int count = dns::getRandom( 8 );
        for ( unsigned int i = 0 ; i < count ; i++ ) {
            option_generator.generate( packet_info );
        }

        if ( ! dns::getRandom( 7 ) ) {
            packet_info.mOptPseudoRR.mPayloadSize = dns::getRandom( 11000 );
        }
        if ( ! dns::getRandom( 7 ) ) {
            packet_info.mOptPseudoRR.mRCode = dns::getRandom( 16);
        }
        if ( ! dns::getRandom( 7 ) ) {
            packet_info.mOptPseudoRR.mDOBit = dns::getRandom( 1 );
        }
    }

    dns::Domainname qname;
    if ( dns::getRandom( 2 ) )
        qname = (dns::Domainname)basename;
    else
        qname = (dns::Domainname)another_basename;
            
    switch ( dns::getRandom( 12 ) ) {
    case 0:
        qname.addSubdomain( "www" );
        break;
    case 1:
        qname.addSubdomain( "vvv" );
        break;
    case 2:
        qname.addSubdomain( "yyy" );
        break;
    case 3:
        switch ( dns::getRandom( 3 ) ) {
        case 0:
            qname.addSubdomain( "yyy" );
            break;
        case 1:
            qname.addSubdomain( "vvv" );
            break;
        case 2:
            qname.addSubdomain( "zzz" );
            break;
        }

        switch ( dns::getRandom( 6 ) ) {
        case 0:
            qname.addSubdomain( "www" );
            break;
        case 1:
            qname.addSubdomain( "zzz" );
            break;
        case 2:
            qname.addSubdomain( "yyy" );
            break;
        case 3:
            qname.addSubdomain( "ns01" );
            break;
        case 4:
            qname.addSubdomain( "child" );
            break;
        case 5:
            qname.addSubdomain( label_generator.generateLabel() );
            break;
        }
        break;
    case 4:
        qname.addSubdomain( "yyyy" );
        switch ( dns::getRandom( 4 ) ) {
        case 0:
            qname.addSubdomain( "www" );
            break;
        case 1:
            qname.addSubdomain( "ns01" );
            break;
        case 2:
            qname.addSubdomain( label_generator.generateLabel() );
            break;
        }
        break;
    case 5:
        qname.addSubdomain( "*" );
        switch ( dns::getRandom( 4 ) ) {
        case 0:
            qname.addSubdomain( "www" );
            break;
        case 1:
            qname.addSubdomain( "ns01" );
            break;
        case 2:
            qname.addSubdomain( "child" );
            break;
        case 3:
            qname.addSubdomain( label_generator.generateLabel() );
            break;
        }
        break;
    case 6:
        qname.addSubdomain( "xxxxxxxxxx" );
        break;
    case 7:
        qname.addSubdomain( label_generator.generateLabel() );
        break;
    case 8:
        qname.addSubdomain( label_generator.generateLabel() );
        switch ( dns::getRandom( 4 ) ) {
        case 0:
            qname.addSubdomain( "www" );
            break;
        case 1:
            qname.addSubdomain( "ns01" );
            break;
        case 2:
            qname.addSubdomain( "child" );
            break;
        case 3:
            qname.addSubdomain( label_generator.generateLabel() );
            break;
        }
        break;
    default:
        qname.addSubdomain( "child" );
        switch ( dns::getRandom( 6 ) ) {
        case 0:
            qname.addSubdomain( "vvv" );
            break;
        case 1:
            qname.addSubdomain( "www" );
            break;
        case 2:
            qname.addSubdomain( "zzz" );
            break;
        case 3:
            qname.addSubdomain( "ns01" );
            break;
        case 4:
            qname.addSubdomain( "child" );
            break;
        case 5:
            qname.addSubdomain( label_generator.generateLabel() );
            break;
        }
        break;
    }

    dns::Type  qtype  = dns::getRandom( 63 );
    dns::Class qclass = dns::CLASS_IN;
    if ( dns::getRandom( 16 ) == 0 )
        qclass = dns::CLASS_ANY;
    if ( dns::getRandom( 16 ) == 0 )
        qclass = dns::CLASS_NONE;

    dns::QuestionSectionEntry q;
    q.mDomainname = qname;
    q.mType       = qtype;
    q.mClass      = qclass;
    packet_info.mQuestionSection.push_back( q );

    // append new rrsets
    unsigned int rrsets_count = dns::getRandom( 4 );
    for ( unsigned int i = 0 ; i < rrsets_count ; i++ ) {
        dns::RRSet rrset = rr_generator.generate( packet_info, (dns::Domainname)another_basename );

        switch ( dns::getRandom( 5 ) ) {
        case 0:
            {
                auto new_rrs = newRRs( rrset );
                for ( auto rr : new_rrs )
                    packet_info.pushAnswerSection( rr );
            }
            break;
        case 1:
            {
                auto new_rrs = newRRs( rrset );
                for ( auto rr : new_rrs )
                    packet_info.pushAuthoritySection( rr );
            }
            break;
        case 2:
            {
                auto new_rrs = newRRs( rrset );
                for ( auto rr : new_rrs )
                    packet_info.pushAdditionalSection( rr );
            }
            break;
        default:
            break;
        }
    }

    packet_info.mIsEDNS0 = true;
    packet_info.mOptPseudoRR.mDOBit = true;

    unsigned int option_count = dns::getRandom( 4 );
    for ( unsigned int i = 0 ; i < option_count ; i++ )
        option_generator.generate( packet_info );

    if ( ! dns::getRandom( 7 ) ) {
        packet_info.mOptPseudoRR.mPayloadSize = dns::getRandom( 0xffff );
    }
    if ( ! dns::getRandom( 7 ) ) {
        packet_info.mOptPseudoRR.mRCode = dns::getRandom( 15 );
    }
    if ( ! dns::getRandom( 7 ) ) {
        packet_info.mOptPseudoRR.mDOBit = dns::getRandom( 1 );
    }

    packet_info.mID                  = dns::getRandom( 0xffff );
    packet_info.mOpcode              = dns::getRandom( 0x02 );
    packet_info.mQueryResponse       = dns::getRandom( 0x02 );
    packet_info.mAuthoritativeAnswer = dns::getRandom( 0x02 );
    packet_info.mTruncation          = dns::getRandom( 0x02 );
    packet_info.mRecursionDesired    = dns::getRandom( 0x02 );
    packet_info.mRecursionAvailable  = dns::getRandom( 0x02 );
    packet_info.mZeroField           = dns::getRandom( 0x0f );
    packet_info.mAuthenticData       = dns::getRandom( 0x02 );
    packet_info.mCheckingDisabled    = dns::getRandom( 0x02 );
    packet_info.mResponseCode        = dns::getRandom( 0x0f );
	
    packet_info.generateMessage( ref_query );

    if ( is_randomize ) {
        unsigned int shuffle_count = dns::getRandom( 3 );
        for ( unsigned int i = 0 ; i < shuffle_count ; i++ ) {
            if ( dns::getRandom( 8 ) == 0 ) {
                WireFormat src = ref_query;
                dns::shuffle( src, ref_query );
            }
        }
    }
}


int main( int argc, char **argv )
{
    std::string target_server;
    uint16_t    target_port;
    std::string basename, another_basename;
    uint32_t    interval = 0;
    bool        is_randomize = true;
    bool        is_pipelining = false;
    std::string sent_queries_file = "";
    std::string log_level;
    
    po::options_description desc( "query generator" );
    desc.add_options()( "help,h", "print this message" )

        ( "server,s",
          po::value<std::string>( &target_server )->default_value( DNS_SERVER_ADDRESS ),
          "target server address" )
        ( "port,p",
          po::value<uint16_t>( &target_port )->default_value( 53 ),
          "target server port" )
        ( "base,b",
          po::value<std::string>( &basename ),
          "basename" )
        ( "pipelining",
          "enable TCP pipelining" )
        ( "randomize,r",
          po::value<bool>( &is_randomize )->default_value( true ),
          "randomize message" )
        ( "sent-queries,q",
          po::value<std::string>( &sent_queries_file )->default_value( "" ),
          "recording query messages" )
        ( "another,y",
          po::value<std::string>( &another_basename ),
          "yet another base name for cache poisoning" )
	( "interval,i",
          po::value<uint32_t>( &interval )->default_value( DEFAULT_INTERVAL_MSEC ),
	  "interval(msec) of each queries")
	( "log-level,l",
	  po::value<std::string>( &log_level )->default_value( "info" ),
	  "trace|debug|info|warning|error|fatal" );

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }
    if ( vm.count( "pipelining" ) )
        is_pipelining = true;

    dns::logger::initialize( log_level );

    bool record_queries = false;
    std::fstream fs_record_queries;
    if ( sent_queries_file != "" ) {
        record_queries = true;
        fs_record_queries.open( sent_queries_file,  std::fstream::out | std::fstream::app );
    }

    dns::DomainnameGenerator label_generator;
    dns::ResourceRecordGenerator rr_generator;
    dns::OptionGenerator option_generator;

    BOOST_LOG_TRIVIAL(info) << "Sending fuzzing queries to " << target_server << ":" << target_port << ".";
    
    signal( SIGPIPE, ignore_signal );

    if ( is_pipelining ) {
        BOOST_LOG_TRIVIAL(info) << "enable pipelining.";
        while ( true ) {
            BOOST_LOG_TRIVIAL(info) << "new connection";
            try {
                tcpv4::ClientParameters tcp_param;
                tcp_param.mAddress = target_server;
                tcp_param.mPort    = target_port;
                tcp_param.mBlock   = false;

                tcpv4::Client tcp( tcp_param );
                tcp.openSocket();
                BOOST_LOG_TRIVIAL(info) << "connected";
                
                while ( true ) {
                    FD::Event tcp_event = tcp.wait();
                    if ( tcp_event & FD::ERROR ) {
                        throw std::runtime_error( "closed or other error" );
                    }
                    if ( tcp_event & FD::READABLE ) {
                        BOOST_LOG_TRIVIAL(info) << "reading response";
                        PacketData response_data;
                        tcpv4::ConnectionInfo response_size_data = tcp.receive_data( 2 );
                        if ( response_size_data.getLength() < 2 )
                            continue;
                        uint16_t response_size = ntohs( *( reinterpret_cast<const uint16_t *>( response_size_data.getData() ) ) );
                        while ( response_data.size() < response_size ) {
                            tcpv4::ConnectionInfo received_data = tcp.receive_data( response_size - response_data.size() );
                            response_data.insert( response_data.end(), received_data.begin(), received_data.end() );
                        }
                        BOOST_LOG_TRIVIAL(info) << "read response";
                    }
                    if ( tcp_event & FD::WRITABLE ) {
                        WireFormat message;
                        generate_query( (dns::Domainname)basename,
                                        (dns::Domainname)another_basename,
                                        label_generator,
                                        rr_generator,
                                        option_generator,
                                        is_randomize,
                                        message );

                        if ( record_queries ) {
                            std::string message_base64;
                            std::vector<uint8_t> m;
                            m = message.get();
                            encodeToBase64( m, message_base64 );
                            fs_record_queries << now_string() << "," << message_base64 << std::endl;
                        }

                        BOOST_LOG_TRIVIAL(info) << "writing query";
                        uint16_t query_size_data2 = htons( message.size() );
                        tcp.send( reinterpret_cast<const uint8_t *>( &query_size_data2 ), 2 );
                        tcp.send( message );
                        BOOST_LOG_TRIVIAL(info) << "wrote query";
                    }
                }
            }
            catch ( std::runtime_error &e )  {
                BOOST_LOG_TRIVIAL(error) << e.what();
            }
            catch ( ... ) {
                BOOST_LOG_TRIVIAL(error) << "other error";
            }
            BOOST_LOG_TRIVIAL(info) << "connection closed";
        }
    }
    else {
        while ( true ) {
            try {
                WireFormat message;
                generate_query( (dns::Domainname)basename,
                                (dns::Domainname)another_basename,
                                label_generator,
                                rr_generator,
                                option_generator,
                                is_randomize,
                                message );

                if ( record_queries ) {
                    std::string message_base64;
                    std::vector<uint8_t> m;
                    m = message.get();
                    encodeToBase64( m, message_base64 );

                    fs_record_queries << now_string() << "," << message_base64 << std::endl;
                }

                if ( message.size() < 1500 ) {
                    udpv4::ClientParameters udp_param;
                    udp_param.mAddress = target_server;
                    udp_param.mPort    = target_port;
                    udpv4::Client udp( udp_param );
                    udp.sendPacket( message );
                }
                else {
                    tcpv4::ClientParameters tcp_param;
                    tcp_param.mAddress = target_server;
                    tcp_param.mPort    = target_port;
                    tcpv4::Client tcp( tcp_param );
                    tcp.openSocket();

                    uint16_t query_size_data2 = htons( message.size() );
                    tcp.send( reinterpret_cast<const uint8_t *>( &query_size_data2 ), 2 );
                    tcp.send( message );

                    tcpv4::ConnectionInfo response_size_data = tcp.receive_data( 2 );
                    if ( response_size_data.getLength() < 2 )
                        continue;
                    uint16_t response_size = ntohs( *( reinterpret_cast<const uint16_t *>( response_size_data.getData() ) ) );

                    PacketData response_data;
                    while ( response_data.size() < response_size ) {
                        tcpv4::ConnectionInfo received_data = tcp.receive_data( response_size - response_data.size() );

                        response_data.insert( response_data.end(), received_data.begin(), received_data.end() );
                    }
                }

                wait_msec( interval );
            }
            catch ( std::runtime_error &e )  {
                BOOST_LOG_TRIVIAL(error) << e.what();
            }
            catch ( ... ) {
                BOOST_LOG_TRIVIAL(error) << "other error";
            }

        }
    }

    return 0;
}
