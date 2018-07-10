#include "signedauthserver.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>


int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    uint16_t    bind_port;
    uint16_t    thread_count; 
    std::string zone_filename;
    std::string apex;
    bool        debug;
    std::string ksk_filename, zsk_filename;
    bool        enable_nsec;
    bool        enable_nsec3;
    std::vector<uint8_t> nsec3_salt;
    std::string nsec3_salt_str;
    uint16_t    nsec3_iterate;
    uint16_t    nsec3_hash_algo;

    po::options_description desc( "dnssec server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b",    po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
        ( "port,p",    po::value<uint16_t>( &bind_port )->default_value( 53 ),              "bind port" )
        ( "thread,n",  po::value<uint16_t>( &thread_count )->default_value( 1 ),            "thread count" )
	( "file,f",    po::value<std::string>( &zone_filename ),                            "zone filename" )
	( "zone,z",    po::value<std::string>( &apex),                                      "zone apex" )
        ( "ksk,K",     po::value<std::string>( &ksk_filename),                              "KSK filename" )
        ( "zsk,Z",     po::value<std::string>( &zsk_filename),                               "ZSK filename" )       
        ( "nsec",      po::value<bool>( &enable_nsec )->default_value( true ),              "enable NSEC" )
        ( "nsec3,3",   po::value<bool>( &enable_nsec3 )->default_value( false ),            "enable NSEC3" )
        ( "salt,s",    po::value<std::string>( &nsec3_salt_str )->default_value( "00" ),    "NSEC3 salt" )
        ( "iterate,i", po::value<uint16_t>( &nsec3_iterate )->default_value( 1 ),           "NSEC3 iterate" )
        ( "hash",      po::value<uint16_t>( &nsec3_hash_algo )->default_value( 1 ),         "NSEC3 hash algorithm" )
        ( "debug,d",   po::bool_switch( &debug )->default_value( false ),                   "debug mode" );
    
    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    decodeFromHex( nsec3_salt_str, nsec3_salt );

    try {
	dns::SignedAuthServer server( bind_address, bind_port, debug, thread_count );
	server.load( apex, zone_filename,
                     ksk_filename, zsk_filename,
                     nsec3_salt, nsec3_iterate, dns::DNSSEC_SHA1,
                     enable_nsec, enable_nsec3 );
        std::vector<std::shared_ptr<dns::RecordDS>> rrset_ds = server.getDSRecords();
        for ( auto ds : rrset_ds ){
            std::cout << ds->toZone() << std::endl;
        }
	server.start();
    }
    catch ( std::runtime_error &e ) {
	std::cerr << e.what() << std::endl;
    }
    catch ( std::logic_error &e ) {
	std::cerr << e.what() << std::endl;
    }
    return 0;
}
