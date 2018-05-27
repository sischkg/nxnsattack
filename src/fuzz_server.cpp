#include "unsignedauthserver.hpp"
#include "rrgenerator.hpp"
#include "shufflebytes.hpp"
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>

namespace dns
{
    class FuzzServer : public PostSignedAuthServer
    {
    public:
	FuzzServer( const std::string &addr, uint16_t port, bool debug, unsigned int thread_count = 1 )
	    : dns::PostSignedAuthServer( addr, port, debug, thread_count ), mSeedGenerator(), mRandomEngine( mSeedGenerator() )
	{
        }

        std::vector<ResourceRecord> newRRs( const RRSet &rrset ) const
        {
            std::vector<ResourceRecord> rrs;
            std::shared_ptr<RRSet> rrsigs = signRRSet( rrset );

            rrsigs->addResourceRecords( rrs );
            return rrs;
        }

        PacketInfo modifyResponse( const PacketInfo &query,
                                   const PacketInfo &original_response,
                                   bool vir_tcp ) const
        {
            PacketInfo modified_response = original_response;

            ResourceRecordGenerator rr_generator;

            // clear rr
            if ( ! getRandom( 32 ) )
                modified_response.clearAnswerSection();
            if ( ! getRandom( 32 ) )
                modified_response.clearAuthoritySection();
            if ( ! getRandom( 32 ) )
                modified_response.clearAdditionalSection();

            // appand new rrsets
            unsigned int rrsets_count = getRandom( 8 );
            for ( unsigned int i = 0 ; i < rrsets_count ; i++ ) {
                RRSet rrset = rr_generator.generate( original_response );

                switch ( getRandom( 4 ) ) {
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
                            modified_response.pushAdditionalSection( rr );
                    }
                    break;
                default:
                    break;
                }
            }

            replaceClass( modified_response.mAnswerSection );
            replaceClass( modified_response.mAuthoritySection );
            replaceClass( modified_response.mAdditionalSection );

	    int sign_count;
	    sign_count= getRandom( 2 );
	    for ( int i = 0 ; i < sign_count ; i++ )
		signSection( modified_response.mAnswerSection );
	    sign_count= getRandom( 2 );
	    for ( int i = 0 ; i < sign_count ; i++ )
		signSection( modified_response.mAuthoritySection );
	    sign_count= getRandom( 2 );
	    for ( int i = 0 ; i < sign_count ; i++ )
		signSection( modified_response.mAdditionalSection );

	    OptionGenerator option_generator;
	    unsigned int option_count = getRandom( 8 );
	    for ( unsigned int i = 0 ; i < option_count ; i++ )
		option_generator.generate( modified_response );

            if ( ! getRandom( 7 ) ) {
                modified_response.mOptPseudoRR.mPayloadSize = getRandom( 0xffff  );
            }
            if ( ! getRandom( 7 ) ) {
                modified_response.mOptPseudoRR.mRCode = getRandom( 16 );
            }
            if ( ! getRandom( 7 ) ) {
                modified_response.mOptPseudoRR.mDOBit = getRandom( 1 );
            }
	    
            if ( ! getRandom( 5 ) ) {
                ResourceRecord opt_pseudo_rr = generateOptPseudoRecord( modified_response.mOptPseudoRR );
                RRSet rrset( opt_pseudo_rr.mDomainname,
                             opt_pseudo_rr.mClass,
                             opt_pseudo_rr.mType,
                             opt_pseudo_rr.mTTL );

                std::shared_ptr<RRSet> rrsig = signRRSet( rrset );
                rrsig->addResourceRecords( modified_response.mAdditionalSection );
            }

            if ( ! getRandom( 16 ) ) {
                modified_response.mResponseCode = getRandom( 16 );
            }

            if ( ! getRandom( 5 ) )
                shuffle_rr( modified_response.mAnswerSection );

            if ( ! getRandom( 5 ) )
                shuffle_rr( modified_response.mAuthoritySection );

            if ( ! getRandom( 5 ) )
                shuffle_rr( modified_response.mAdditionalSection );

            return modified_response;
        }

	void modifyMessage( const PacketInfo &query, WireFormat &message )
	{
	    WireFormat src = message;
            dns::shuffle( src, message );
	}
	
        void shuffle_rr( std::vector<ResourceRecord> &rrs ) const
        {
	  std::shuffle( rrs.begin(), rrs.end(), mRandomEngine );
        }

        void replaceClass( std::vector<ResourceRecord> &section ) const
        {
            if ( getRandom( 5 ) )
                return;

            Class class_table[] = { CLASS_IN, CLASS_CH, CLASS_HS, CLASS_NONE, CLASS_ANY };
            for ( ResourceRecord &rr : section ) {
                unsigned int index = getRandom( sizeof(class_table)/sizeof(Class) - 1 );
                if ( index >= sizeof(class_table)/sizeof(Class) ) {
                    std::cerr << "invalid replace class index " << index << "." << std::endl;
                    throw std::logic_error( "invalid replace class index" );
                }
                rr.mClass = class_table[ index ];
            }
        }

        void signSection( std::vector<ResourceRecord> &section ) const
        {
            std::vector<ResourceRecord> rrsigs;
            std::vector< std::shared_ptr<RRSet> > signed_targets = cumulate( section );
            for ( auto signed_target : signed_targets ) {
                std::shared_ptr<RRSet> rrsig_rrset = signRRSet( *signed_target );
                rrsig_rrset->addResourceRecords( section );
            }
            section.insert( section.end(), rrsigs.begin(), rrsigs.end() );
        }

        std::vector<std::shared_ptr<RRSet> > cumulate( const std::vector<ResourceRecord> &rrs ) const
        {
            std::vector<std::shared_ptr<RRSet> > rrsets;

            for ( auto rr : rrs ) {
                bool is_found = false;
                for ( auto rrset : rrsets ) {
                    if ( rr.mDomainname == rrset->getOwner() &&
                         rr.mClass      == rrset->getClass() && 
                         rr.mType       == rrset->getType()  ) {
                        rrset->add( std::shared_ptr<RDATA>( rr.mRData->clone() ) );
                        is_found = true;
                        break;
                    }
                }
                if ( ! is_found ) {
                    std::shared_ptr<RRSet> new_rrset( std::shared_ptr<RRSet>( new RRSet( rr.mDomainname, rr.mClass, rr.mType, rr.mTTL ) ) );
                    new_rrset->add( std::shared_ptr<RDATA>( rr.mRData->clone() ) );
                    rrsets.push_back( new_rrset );
                }
            }

            return rrsets;
        }

    private:
        mutable std::random_device mSeedGenerator;
        mutable std::mt19937 mRandomEngine;
    };


}

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
    bool                 is_nsec3;
    std::vector<uint8_t> nsec3_salt;
    std::string          nsec3_salt_str;
    uint16_t             nsec3_iterate;
    uint16_t             nsec3_hash_algo;

    po::options_description desc( "fuzz server" );
    desc.add_options()( "help,h", "print this message" )

        ( "bind,b",    po::value<std::string>( &bind_address )->default_value( "0.0.0.0" ), "bind address" )
        ( "port,p",    po::value<uint16_t>( &bind_port )->default_value( 53 ),              "bind port" )
        ( "thread,n",  po::value<uint16_t>( &thread_count )->default_value( 1 ),            "thread count" )
	( "file,f",    po::value<std::string>( &zone_filename ),                            "zone filename" )
	( "zone,z",    po::value<std::string>( &apex),                                      "zone apex" )
        ( "ksk,K",     po::value<std::string>( &ksk_filename),                              "KSK filename" )
        ( "zsk,Z",     po::value<std::string>( &zsk_filename),                              "ZSK filename" )
        ( "3",         po::value<bool>( &is_nsec3 )->default_value( false ),                "enable NSEC3" )
        ( "salt,s",    po::value<std::string>( &nsec3_salt_str )->default_value( "00" ),    "NSEC3 salt" )
        ( "iterate,i", po::value<uint16_t>( &nsec3_iterate )->default_value( 1 ),           "NSEC3 iterate" )
        ( "hash,h",    po::value<uint16_t>( &nsec3_hash_algo )->default_value( 1 ),         "NSEC3 hash algorithm" )
        ( "debug,d",   po::bool_switch( &debug )->default_value( false ),                   "debug mode" );
    
    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    if ( apex.back() != '.' )
	apex.push_back( '.' );

    decodeFromHex( nsec3_salt_str, nsec3_salt );
    
    try {
	dns::FuzzServer server( bind_address, bind_port, debug, thread_count );
	server.load( apex, zone_filename,
                     ksk_filename, zsk_filename,
                     nsec3_salt, nsec3_iterate, dns::DNSSEC_SHA1);
        std::vector<std::shared_ptr<dns::RecordDS>> rrset_ds = server.getDSRecords();
	std::cout << "DS records" << std::endl;
        for ( auto ds : rrset_ds ){
            std::cout << apex << "   IN DS " << ds->toZone() << std::endl;
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
