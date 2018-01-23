#include "unsignedauthserver.hpp"
#include "rrgenerator.hpp"
#include "shufflebytes.hpp"
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

            modified_response.clearAnswerSection();
            modified_response.clearAuthoritySection();
            modified_response.clearAdditionalInfomationSection();

            for ( int i = 0 ; i < 8 ; i++ ) {
                Domainname owner = query.question_section[0].q_domainname;
                std::string hash;
                encodeToBase32Hex( getRandomStream( 20 ), hash ); 
                owner.addSubdomain( hash );

                std::vector<Type> types;
                unsigned int type_count = getRandom( 0x04 );
                for ( unsigned int i = 0 ; i < type_count ; i++ ) {
                    types.push_back( getRandom( 0xffff ) );
                }

                std::shared_ptr<RDATA> resource_data( new RecordNSEC3( 0x01,
                                                                       0,
                                                                       getRandom( 0x00ff ),
                                                                       getRandomSizeStream( 0xff ),
                                                                       getRandomStream( 20 ),
                                                                       types ) );
            
                RRSet rrset( owner, CLASS_NONE, TYPE_NSEC3, getRandom( 1 ) );
                rrset.add( resource_data );

                auto rrs = newRRs( rrset );
                for ( auto rr : rrs )
                    modified_response.pushAnswerSection( rr );
            }

            RRSet rrset_ns( "", CLASS_NONE, TYPE_NS, 1 );
            for ( unsigned int i = 0 ; i < (unsigned int)('d' - 'a') ; i++ ) {
                Domainname nsname = query.question_section[0].q_domainname;
                std::string subdomain;
                subdomain.push_back( 'a' + i );
                nsname.addSubdomain( subdomain );

                std::shared_ptr<RDATA> resource_data_ns( new RecordNS( nsname ) );
                rrset_ns.add( resource_data_ns );
            }
            auto rrs_ns = newRRs( rrset_ns );
            for ( auto rr : rrs_ns )
                modified_response.pushAuthoritySection( rr );

            for ( unsigned int i = 0 ; i < (unsigned int)('d' - 'a') ; i++ ) {

                Domainname nsname = query.question_section[0].q_domainname;
                std::string subdomain;
                subdomain.push_back( 'a' + i );
                nsname.addSubdomain( subdomain );

                RRSet rrset_a( nsname, CLASS_NONE, TYPE_A, 1 );
                std::shared_ptr<RDATA> resource_data_a( new RecordA( "218.251.248.110" ) );
                rrset_a.add( resource_data_a );

                auto rrs_a = newRRs( rrset_a );
                for ( auto rr : rrs_a )
                    modified_response.pushAdditionalInfomationSection( rr );
            }

            //            signSection( modified_response.answer_section );
            //            signSection( modified_response.authority_section );
            //            signSection( modified_response.additional_infomation_section );

            modified_response.response_code = NXDOMAIN;
            return modified_response;
        }

	void modifyMessage( WireFormat &message )
	{
	    // WireFormat src = message;
            //	    shuffle( src, message );
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
                std::shared_ptr<RRSet> rrsig_rrset = signRRSet( *signed_target );
                for ( auto rrsig = rrsig_rrset->begin() ; rrsig != rrsig_rrset->end() ; rrsig++ ) {
                    ResourceRecord rr;
                    rr.r_domainname    = rrsig_rrset->getOwner();
                    rr.r_class         = rrsig_rrset->getClass();
                    rr.r_type          = rrsig_rrset->getType();
                    rr.r_resource_data = *rrsig;
                    rrsigs.push_back( rr );
                }
            }
            section.insert( section.end(), rrsigs.begin(), rrsigs.end() );
        }

        std::vector<std::shared_ptr<RRSet> > cumulate( const std::vector<ResourceRecord> &rrs ) const
        {
            std::vector<std::shared_ptr<RRSet> > rrsets;

            for ( auto rr : rrs ) {
                bool is_found = false;
                for ( auto rrset : rrsets ) {
                    if ( rr.r_domainname == rrset->getOwner() &&
                         rr.r_class      == rrset->getClass() && 
                         rr.r_type       == rrset->getType()  ) {
                        rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
                        is_found = true;
                        break;
                    }
                }
                if ( ! is_found ) {
                    std::shared_ptr<RRSet> new_rrset( std::shared_ptr<RRSet>( new RRSet( rr.r_domainname, rr.r_class, rr.r_type, rr.r_ttl ) ) );
                    new_rrset->add( std::shared_ptr<RDATA>( rr.r_resource_data->clone() ) );
                    rrsets.push_back( new_rrset );
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
