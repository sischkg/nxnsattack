#include "signedauthserver.hpp"
#include "rrgenerator.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>


namespace dns
{
    class FuzzServer : public SignedAuthServer
    {
    public:
	FuzzServer( const std::string &addr, uint16_t port, bool debug )
	    : dns::SignedAuthServer( addr, port, debug )
	{}

        std::vector<ResponseSectionEntry> newRRs( const RRSet &rrset ) const
        {
            std::vector<ResponseSectionEntry> rrs;
            std::shared_ptr<RRSet> rrsigs = signRRSet( rrset );

            for( auto rr : rrset.getRRSet() ) {
                ResponseSectionEntry r;
                r.r_domainname    = rrset.getOwner();
                r.r_type          = rrset.getType();
                r.r_class         = rrset.getClass();
                r.r_ttl           = rrset.getTTL();
                r.r_resource_data = rr;
                rrs.push_back( r );
            }
            for( auto rrsig : rrsigs->getRRSet() ) {
                ResponseSectionEntry r;
                r.r_domainname    = rrsigs->getOwner();
                r.r_type          = rrsigs->getType();
                r.r_class         = rrsigs->getClass();
                r.r_ttl           = rrsigs->getTTL();
                r.r_resource_data = rrsig;
                rrs.push_back( r );
            }

            return rrs;
        }

        PacketInfo modifyResponse( const PacketInfo &query,
                                   const PacketInfo &original_response,
                                   bool vir_tcp ) const
        {
            PacketInfo modified_response = original_response;

            ResourceRecordGenerator rr_generator;
            // appand new rrsets
            unsigned int rrsets_count = getRandom( 16 );
            for ( unsigned int i = 0 ; i < rrsets_count ; i++ ) {
                RRSet rrset = rr_generator.generate( original_response );

                switch ( getRandom( 16 ) ) {
                case 0:
                    {
                        auto new_rrs = newRRs( rrset );
                        for ( auto rr : new_rrs )
                            modified_response.pushAnswerSection( rr );
                    }
                    break;
                case 1:
                    {
                        auto new_rrs = newRRs( rrset );
                        for ( auto rr : new_rrs )
                            modified_response.pushAuthoritySection( rr );
                    }
                    break;
                case 2:
                    {
                        auto new_rrs = newRRs( rrset );
                        for ( auto rr : new_rrs )
                            modified_response.pushAdditionalInfomationSection( rr );
                    }
                    break;
                default:
                    break;
                }
            }
            return modified_response;
        }
    };
 
}

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    uint16_t    bind_port;
    std::string zone_filename;
    std::string apex;
    bool        debug;
    std::string ksk_filename, zsk_filename;

    po::options_description desc( "fuzz server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b",  po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
        ( "port,p",  po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )
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
	dns::FuzzServer server( bind_address, bind_port, debug );
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
