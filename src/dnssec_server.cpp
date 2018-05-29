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

    po::options_description desc( "dnssec server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b",  po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
        ( "port,p",  po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )
        ( "thread,n",  po::value<uint16_t>( &thread_count )->default_value( 1 ),            "thread count" )
	( "file,f",  po::value<std::string>( &zone_filename ),           "zone filename" )
	( "zone,z",  po::value<std::string>( &apex),                     "zone apex" )
        ( "ksk,K",   po::value<std::string>( &ksk_filename),  "KSK filename" )
        ( "zsk,Z",   po::value<std::string>( &zsk_filename),  "ZSK filename" )       
        ( "debug,d", po::bool_switch( &debug )->default_value( false ), "debug mode" );
    
    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    try {
	dns::SignedAuthServer server( bind_address, bind_port, debug, thread_count );
	server.load( apex, zone_filename,
                     ksk_filename, zsk_filename );
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
