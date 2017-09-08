#include "unsignedauthserver.hpp"
#include "rrgenerator.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>


namespace dns
{
    class FuzzServer : public UnsignedAuthServer
    {
    public:
	FuzzServer( const std::string &addr, uint16_t port, bool debug )
	    : dns::UnsignedAuthServer( addr, port, debug )
	{}

        std::vector<ResourceRecord> newRRs( const RRSet &rrset ) const
        {
            std::vector<ResourceRecord> rrs;
            std::shared_ptr<RRSet> rrsigs = signRRSet( rrset );

            for( auto rr : rrset.getRRSet() ) {
                ResourceRecord r;
                r.r_domainname    = rrset.getOwner();
                r.r_type          = rrset.getType();
                r.r_class         = rrset.getClass();
                r.r_ttl           = rrset.getTTL();
                r.r_resource_data = rr;
                rrs.push_back( r );
            }
            for( auto rrsig : rrsigs->getRRSet() ) {
                ResourceRecord r;
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

            // clear rr
            if ( ! getRandom( 16 ) )
                modified_response.clearAnswerSection();
            if ( ! getRandom( 16 ) )
                modified_response.clearAuthoritySection();
            if ( ! getRandom( 16 ) )
                modified_response.clearAdditionalInfomationSection();

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

            replaceClass( modified_response.answer_section );
            replaceClass( modified_response.authority_section );
            replaceClass( modified_response.additional_infomation_section );

            if ( query.question_section[0].q_type != TYPE_RRSIG &&
                 modified_response.getAnswerSection().size() != 0 &&
                 modified_response.response_code != NO_ERROR ) {
                signSection( modified_response.answer_section );
            }
            signSection( modified_response.authority_section );
            signSection( modified_response.additional_infomation_section );

            if ( ! getRandom( 5 ) ) {
                ResourceRecord opt_pseudo_rr = generate_opt_pseudo_record( modified_response.opt_pseudo_rr );
                RRSet rrset( opt_pseudo_rr.r_domainname,
                             opt_pseudo_rr.r_class,
                             opt_pseudo_rr.r_type,
                             opt_pseudo_rr.r_ttl );

                std::shared_ptr<RRSet> rrsig = signRRSet( rrset );
                ResourceRecord rrsig_rr;
                rrsig_rr.r_domainname = rrsig->getOwner();
                rrsig_rr.r_class      = rrsig->getClass();
                rrsig_rr.r_type       = rrsig->getType();
                rrsig_rr.r_resource_data = (*rrsig)[0];
                modified_response.pushAdditionalInfomationSection( rrsig_rr );
            }

            return modified_response;
        }

        void replaceClass( std::vector<ResourceRecord> &section ) const
        {
            if ( getRandom( 5 ) )
                return;

            Class class_table[] = { CLASS_IN, CLASS_CH, CLASS_HS, CLASS_NONE, CLASS_ANY };
            for ( ResourceRecord &rr : section ) {
                rr.r_class = class_table[ getRandom( sizeof(class_table)/sizeof(Class) ) ];
            }
        }

        void signSection( std::vector<ResourceRecord> &section ) const
        {
            std::vector<ResourceRecord> rrsigs;
            std::vector< std::shared_ptr<RRSet> > signed_targets = cumulate( section );
            for ( auto signed_target : signed_targets ) {
                std::shared_ptr<RRSet> rrsig = signRRSet( *signed_target );
                ResourceRecord rr;
                rr.r_domainname = rrsig->getOwner();
                rr.r_class      = rrsig->getClass();
                rr.r_type       = rrsig->getType();
                rr.r_resource_data = (*rrsig)[0];
                rrsigs.push_back( rr );
            }
            section.insert( section.end(), rrsigs.begin(), rrsigs.end() );
        }

        std::vector<std::shared_ptr<RRSet> > cumulate( const std::vector<ResourceRecord> &rrs ) const
        {
            std::vector<std::shared_ptr<RRSet> > rrsets;

            for ( auto rr : rrs ) {
                for ( auto rrset : rrsets ) {
                    if ( rr.r_domainname == rrset->getOwner() &&
                         rr.r_class      == rrset->getClass() && 
                         rr.r_type       == rrset->getType()  ) {
                        rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
                    }
                    else {
                        std::shared_ptr<RRSet> new_rrset( std::shared_ptr<RRSet>( new RRSet( rr.r_domainname, rr.r_class, rr.r_type, rr.r_ttl ) ) );
                        new_rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
                        rrsets.push_back( new_rrset );
                    }
                }
            }

            return rrsets;
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
