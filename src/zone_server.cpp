#include "dns_server.hpp"
#include "zone.hpp"
#include "zoneloader.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>

class ZoneServer : public dns::DNSServer
{
public:
    ZoneServer( const std::string &addr, uint16_t port, bool debug )
        : dns::DNSServer( addr, port, debug )
    {}

    void load( const std::string &apex, const std::string &filename )
    {
        std::ifstream fin( filename );
        std::string config;
        while ( ! fin.eof() ) {
            std::string line;
            std::getline( fin, line );
            config += line;
	    config += "\n";
        }
	std::cerr << config << std::endl;
        zone = dns::full::load( apex, config );
    }


    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
        dns::PacketInfo response = zone->getAnswer( query );
        return response;
    }

private:
    std::shared_ptr<dns::Zone> zone;
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    std::string zone_filename;
    std::string apex;
    bool        debug;

    po::options_description desc( "unbound" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b", po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
	( "file,f", po::value<std::string>( &zone_filename ),           "bind address" )
	( "zone,z", po::value<std::string>( &apex),                     "zone apex" )
        ( "debug,d", po::bool_switch( &debug )->default_value( false ), "debug mode" );
    
    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    try {
	ZoneServer server( bind_address, 53, debug );
	server.load( apex, zone_filename );
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
