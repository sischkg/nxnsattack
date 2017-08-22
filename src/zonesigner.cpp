#include "zonesigner.hpp"
#include "zonesignerimp.hpp"
#include <boost/program_options.hpp>
#include <iostream>

namespace dns
{

    
    /*******************************************************************************************
     * ZoneSinger
     *******************************************************************************************/

    ZoneSigner::ZoneSigner( const Domainname &d, const std::string &ksk, const std::string &zsk )
	: mImp( new ZoneSignerImp( d, ksk, zsk ) )
    {}

    std::shared_ptr<RRSet> ZoneSigner::signRRSet( const RRSet &rrset ) const
    {
	return mImp->signRRSet( rrset );
    }
    
    std::shared_ptr<RRSet> ZoneSigner::signDNSKEY( TTL ttl ) const
    {
	return mImp->signDNSKEY( ttl );
    }

    std::shared_ptr<PublicKey> ZoneSigner::getKSKPublicKey() const
    {
	return mImp->getKSKPublicKey();
    }

    std::shared_ptr<PublicKey> ZoneSigner::getZSKPublicKey() const
    {
	return mImp->getZSKPublicKey();
    }

    std::vector<std::shared_ptr<RecordDS>> ZoneSigner::getDSRecords() const
    {
	return mImp->getDSRecords();
    }

    std::vector<std::shared_ptr<RecordDNSKEY>> ZoneSigner::getDNSKEYRecords() const
    {
	return mImp->getDNSKEYRecords();
    }

    void ZoneSigner::initialize()
    {
	ZoneSignerImp::initialize();
    }


    /*******************************************************************************************
     * RSAPublicKey
     *******************************************************************************************/

    RSAPublicKey::RSAPublicKey( const std::vector<uint8_t> &exp, const std::vector<uint8_t> &mod )
	: mImp( new RSAPublicKeyImp( exp, mod ) )
    {}

    std::string RSAPublicKey::toString() const
    {
	return mImp->toString();
    }

    const std::vector<uint8_t> &RSAPublicKey::getExponent() const
    {
	return mImp->getExponent();
    }
    
    const std::vector<uint8_t> &RSAPublicKey::getModulus() const
    {
	return mImp->getModulus();
    }

    std::vector<uint8_t> RSAPublicKey::getDNSKEYFormat() const
    {
	return mImp->getDNSKEYFormat();
    }

}

#ifdef EXAMPLE_ZONE_SIGNER

namespace po = boost::program_options;

int main( int argc, char **argv )
{

    std::string apex, input_zone_filename, output_zone_filename, ksk_filename, zsk_filename;
    bool debug;

    po::options_description desc( "zonesigner" );
    desc.add_options()( "help,h", "print this message" )
        ( "zone,z",  po::value<std::string>( &apex )->default_value( "example.com" ), "zone apex" )
        ( "in,i",    po::value<std::string>( &input_zone_filename ),  "input pre-signed zone filename" )
        ( "out,o",   po::value<std::string>( &output_zone_filename ), "output signed zone filename" )	
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
    
    dns::ZoneSigner::initialize();
    dns::ZoneSigner signer( "example.com", ksk_filename, zsk_filename );

    auto ksk_public_key = signer.getKSKPublicKey();
    auto zsk_public_key = signer.getZSKPublicKey();

    std::cout << ksk_public_key->toString() << std::endl;
    std::cout << zsk_public_key->toString() << std::endl;

    std::shared_ptr<dns::RRSet> a( new dns::RRSet( "examle.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    a->add( std::shared_ptr<dns::RecordA>( new dns::RecordA( "127.0.0.1" ) ) );
    
    auto dss = signer.getDSRecords();
    auto dnskeys = signer.getDNSKEYRecords();
    auto rrsig  = signer.signDNSKEY( 3600 );
    for ( auto ds : dss )
        std::cout << ds->toString() << std::endl;
    for ( auto dnskey : dnskeys )
        std::cout << dnskey->toString() << std::endl;
    std::cout << rrsig->toString() << std::endl;

    auto rrsig_a = signer.signRRSet( *a );
    std::cout << rrsig_a->toString() << std::endl;
    
    return 0;
}

#endif
