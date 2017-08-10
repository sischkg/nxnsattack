#include "zonesigner.hpp"
#include <boost/program_options.hpp>
#include <boost/utility.hpp>
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iterator>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <yaml-cpp/yaml.h>

namespace dns
{
    /*******************************************************************************************
     * PrivateKeyImp
     *******************************************************************************************/
    /*
      type: KSK
      domain: example.com
      tag: 12345
      not_before: 1502238577
      not_after:  1502413242
      key_file:   /etc/nsd/keys/Kexample.com.+008.123456
    */
    class PrivateKeyImp : private boost::noncopyable
    {
    public:
        ~PrivateKeyImp();

        KeyType   getKeyType() const   { return mKeyType; }
        Algorithm getAlgorithm() const { return DNSSEC_RSA; }
        EVP_PKEY *getPrivateKey() const { return mPrivateKey; }
        uint16_t  getKeyTag() const    { return mKeyTag; }
        uint32_t  getNotBefore() const { return mNotBefore; }
        uint32_t  getNotAfter() const  { return mNotAfter; }
        const Domainname getDomainname() const { return mDomainname; }

        static std::shared_ptr<PrivateKeyImp> load( const std::string &config );
        static std::shared_ptr<PrivateKeyImp> loadConfig( const std::string &config_file );
    private:
        KeyType     mKeyType;
        EVP_PKEY   *mPrivateKey;
        uint16_t    mKeyTag;
        uint32_t    mNotBefore;
        uint32_t    mNotAfter;
        Domainname  mDomainname;

        PrivateKeyImp( KeyType key_type, EVP_PKEY *key, uint16_t tag, uint32_t not_before, uint32_t not_after, const Domainname &domain )
            : mKeyType( key_type ), mPrivateKey( key ), mKeyTag( tag ), mNotBefore( not_before ), mNotAfter( not_after ), mDomainname( domain )
        {}

        static EVP_PKEY *loadPrivateKey( const std::string &key_file );
        template<typename TYPE>
        static TYPE loadParameter( const YAML::Node &node, const std::string param_name )
        {
            if ( node[param_name] )
                return node[param_name].as<TYPE>();
            throw std::runtime_error( param_name + " must be specified" ); 
        }
    };

    PrivateKeyImp::~PrivateKeyImp()
    {
        EVP_PKEY_free( mPrivateKey );
    }

    EVP_PKEY *PrivateKeyImp::loadPrivateKey( const std::string &key_filename )
    {
        // Load Private / Public Key
        FILE *fp_private_key = std::fopen( key_filename.c_str(), "r" );
        if ( ! fp_private_key ) {
            throw std::runtime_error( "cannot open private key \"" + key_filename + "\"" );
        }
        BIO *bio_private_key = BIO_new_fp( fp_private_key, BIO_CLOSE );
        if ( ! bio_private_key ) {
            throw std::runtime_error( "cannot create bio for private key file" );
        }

        EVP_PKEY *private_key = PEM_read_bio_PrivateKey( bio_private_key, NULL, NULL, NULL );
        if ( ! private_key ) {
            throw std::runtime_error( "cannot read private key" );
        }
        BIO_free_all( bio_private_key );

	return private_key;
    }

    std::shared_ptr<PrivateKeyImp> PrivateKeyImp::loadConfig( const std::string &config_filename )
    {
        std::ifstream fs( config_filename );
        std::istreambuf_iterator<char> begin( fs );
        std::istreambuf_iterator<char> end;

        if ( !fs ) {
            throw std::runtime_error( "cannot load config file \"" + config_filename + "\"" );
        }
        std::string config( begin, end );
        return load( config );
    }


    std::shared_ptr<PrivateKeyImp> PrivateKeyImp::load( const std::string &config )
    {
        YAML::Node top;
        try {
            top = YAML::Load( config );
        }
        catch( YAML::ParserException &e ) {
            std::cerr << "cannot load private key: " << e.what() << std::endl;
            throw std::runtime_error( "cannot load private key " + config + ": " + e.what() );
        }

        KeyType     key_type    = ZSK;
        EVP_PKEY   *private_key = nullptr;
        uint16_t    tag         = 0;
        uint32_t    not_before  = 0;
        uint32_t    not_after   = 0;
        Domainname  domain;

        std::string key_type_name = loadParameter<std::string>( top, "type" );
        if ( key_type_name == "ksk" ) 
            key_type = KSK;
   
        private_key = loadPrivateKey( loadParameter<std::string>( top, "key_file" ) );

        tag        = loadParameter<uint16_t>( top, "tag" );
        not_before = loadParameter<uint32_t>( top, "not_before" );
        not_after  = loadParameter<uint32_t>( top, "not_after" );
        domain     = loadParameter<std::string>( top, "domain" );

        return std::shared_ptr<PrivateKeyImp>( new PrivateKeyImp( key_type, private_key, tag, not_before, not_after, domain ) );
    }

    /*******************************************************************************************
     * ZoneSingerImp
     *******************************************************************************************/

    /*!
     * ZoneSingerImp
     */
    class ZoneSignerImp
    {
    private:
        Domainname  mApex;
        EVP_MD_CTX *mMDContext;
        std::shared_ptr<PrivateKeyImp> mKSK;
        std::shared_ptr<PrivateKeyImp> mZSK;

        static void      throwException( const char *message, const char *other = nullptr );
	static std::shared_ptr<PublicKey> getPublicKey( EVP_PKEY *private_key );
        static const EVP_MD *enumToMD( HashAlgorithm );
    public:
        ZoneSignerImp( const Domainname &d, const std::string &ksk, const std::string &zsk );
        ~ZoneSignerImp();

        void sign( const uint8_t *message, size_t size,
                   std::vector<uint8_t> &signature, HashAlgorithm algo = DNSSEC_SHA256 ) const;

	std::shared_ptr<PublicKey> getKSKPublicKey() const;
	std::shared_ptr<PublicKey> getZSKPublicKey() const;

        std::shared_ptr<RecordDS>     getDSRecord( HashAlgorithm algo ) const;
        std::shared_ptr<RecordDNSKey> getDNSKeyRecord( const PrivateKeyImp &private_key ) const;
        std::vector<std::shared_ptr<RecordDS> >     getDSRecords() const;
        std::vector<std::shared_ptr<RecordDNSKey> > getDNSKeyRecords() const;

        static void initialize();
    };

    void ZoneSignerImp::throwException( const char *message, const char *other )
    {
        unsigned int code = ERR_get_error();
        char openssl_error[1024];
        std::memset( openssl_error, 0, sizeof(openssl_error) );
        ERR_error_string_n( code, openssl_error, sizeof(openssl_error) );
 
        std::ostringstream err;
        err << message;
        if ( other != nullptr )
            err << "\"" << other << "\"";
        err << "(" << openssl_error << ")";

        std::runtime_error( err.str() );
    }

    ZoneSignerImp::ZoneSignerImp( const Domainname &apex, const std::string &ksk_filename, const std::string &zsk_filename )
        : mApex( apex ), mMDContext( nullptr )
    {
	try {
            mKSK = PrivateKeyImp::loadConfig( ksk_filename );
            mZSK = PrivateKeyImp::loadConfig( zsk_filename );

	    mMDContext = EVP_MD_CTX_create();
	    if ( ! mMDContext ) {
		throwException( "cannot create MD_CTX" );
	    }
	}
	catch ( std::runtime_error &e ) {
	    if ( mMDContext != nullptr )
		EVP_MD_CTX_destroy( mMDContext );
	    throw;
	}	
    }

    ZoneSignerImp::~ZoneSignerImp()
    {
        EVP_MD_CTX_destroy( mMDContext );
    }


    void ZoneSignerImp::sign( const uint8_t *message, size_t size, std::vector<uint8_t> &signature, HashAlgorithm algo ) const
    {
        int result =  EVP_DigestSignInit( mMDContext, NULL, enumToMD( algo ), NULL, mZSK->getPrivateKey() );
        if ( result != 1 ) {
            throwException( "cannot initialize DigestSign" );
        }
 
        result = EVP_DigestSignUpdate( mMDContext, message, size );
        if ( result != 1 ) {
            throwException( "cannot update DigestSign" );
        }

        size_t sign_length;
        result = EVP_DigestSignFinal( mMDContext, NULL, &sign_length );
        if ( result != 1 ) {
            throwException( "cannot fetch result buffer length" );
        }

        std::vector<uint8_t> buffer;
        signature.resize( sign_length );

        result = EVP_DigestSignFinal( mMDContext, &signature[0], &sign_length );
        if ( result != 1 ) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error( "cannot create signature" );
        }
    }

    std::shared_ptr<RecordDNSKey> ZoneSignerImp::getDNSKeyRecord( const PrivateKeyImp &key ) const
    {
        std::shared_ptr<PublicKey> public_key = getPublicKey( key.getPrivateKey() );

        return std::shared_ptr<RecordDNSKey>( new RecordDNSKey( key.getKeyType(),
                                                                key.getAlgorithm(),
                                                                public_key->getDNSKeyFormat() ) );
    }

    std::vector<std::shared_ptr<RecordDNSKey>> ZoneSignerImp::getDNSKeyRecords() const
    {
        std::vector<std::shared_ptr<RecordDNSKey>> result;
        result.push_back( getDNSKeyRecord( *mKSK ) );
        result.push_back( getDNSKeyRecord( *mZSK ) );
        return result;
    }

    std::shared_ptr<RecordDS> ZoneSignerImp::getDSRecord( HashAlgorithm algo ) const
    {
        WireFormat hash_target;
        mKSK->getDomainname().outputCanonicalWireFormat( hash_target );
        std::shared_ptr<RecordDNSKey> dnskey = getDNSKeyRecord( *mKSK );
        dnskey->outputWireFormat( hash_target );
        std::vector<uint8_t> hash_target_data = hash_target.get();

        unsigned int digest_length = EVP_MAX_MD_SIZE;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex( mdctx, enumToMD( algo ), NULL);
        EVP_DigestUpdate( mdctx, &hash_target_data[0], hash_target_data.size() );
        std::vector<uint8_t> digest( EVP_MAX_MD_SIZE );
        EVP_DigestFinal_ex( mdctx, &digest[0], &digest_length );
        digest.resize( digest_length );
        EVP_MD_CTX_free( mdctx );

        return std::shared_ptr<RecordDS>( new RecordDS( mKSK->getKeyTag(),
                                                        mKSK->getAlgorithm(),
                                                        algo,
                                                        digest ) );
    }

    std::vector<std::shared_ptr<RecordDS>> ZoneSignerImp::getDSRecords() const
    {
        std::vector<std::shared_ptr<RecordDS>> result;
        result.push_back( getDSRecord( DNSSEC_SHA1 ) );
        result.push_back( getDSRecord( DNSSEC_SHA256 ) );
        return result;
    }

    void ZoneSignerImp::initialize()
    {
        SSL_library_init();
    }

    const EVP_MD *ZoneSignerImp::enumToMD( HashAlgorithm algo )
    {
        switch ( algo ) {
        case DNSSEC_SHA1:
            return EVP_sha1();
        case DNSSEC_SHA256:
            return EVP_sha256();
        default:
            throw std::runtime_error( "unknown hash algorighm for DS" );
        }
    }
    
    std::shared_ptr<PublicKey> ZoneSignerImp::getPublicKey( EVP_PKEY *private_key )
    {
        RSA* r = EVP_PKEY_get0_RSA( private_key );
	const BIGNUM *modulus, *public_exponent, *private_exponent;

	RSA_get0_key( r, &modulus, &public_exponent, &private_exponent );
	std::vector<uint8_t> public_exponent_buf( BN_num_bytes( public_exponent ) );
	std::vector<uint8_t> modulus_buf( BN_num_bytes( modulus ) );

	BN_bn2bin( public_exponent, &public_exponent_buf[0] );
	BN_bn2bin( modulus,         &modulus_buf[0] );

	return std::shared_ptr<RSAPublicKey>( new RSAPublicKey( public_exponent_buf, modulus_buf ) );
    }

    std::shared_ptr<PublicKey> ZoneSignerImp::getKSKPublicKey() const
    {
	return getPublicKey( mKSK->getPrivateKey() );
    }

    std::shared_ptr<PublicKey> ZoneSignerImp::getZSKPublicKey() const
    {
	return getPublicKey( mZSK->getPrivateKey() );
    }

    
    /*******************************************************************************************
     * ZoneSinger
     *******************************************************************************************/

    ZoneSigner::ZoneSigner( const Domainname &d, const std::string &ksk, const std::string &zsk )
	: mImp( new ZoneSignerImp( d, ksk, zsk ) )
    {}

    void ZoneSigner::sign( const uint8_t *message, size_t size,
			   std::vector<uint8_t> &signature, HashAlgorithm algo ) const
    {
	mImp->sign( message, size, signature, algo );
    }

    void ZoneSigner::sign( const std::vector<uint8_t> &message,
			   std::vector<uint8_t> &signature, HashAlgorithm algo ) const
    {
	mImp->sign( &message[0], message.size(), signature, algo );
	
    }
    
    void ZoneSigner::sign( const std::string &message,
			   std::vector<uint8_t> &signature, HashAlgorithm algo ) const
    {
	mImp->sign( reinterpret_cast<const uint8_t *>( message.c_str() ), message.size(), signature, algo );
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

    std::vector<std::shared_ptr<RecordDNSKey>> ZoneSigner::getDNSKeyRecords() const
    {
	return mImp->getDNSKeyRecords();
    }

    void ZoneSigner::initialize()
    {
	ZoneSignerImp::initialize();
    }

    /*******************************************************************************************
     * RSAPublicKeyImp
     *******************************************************************************************/
    /*!
     * RSAPublicKeyImp
     */
    class RSAPublicKeyImp
    {
    public:
        RSAPublicKeyImp( const std::vector<uint8_t> &exp, const std::vector<uint8_t> &mod );

        std::string toString() const;
        const std::vector<uint8_t> &getExponent() const { return exponent; } 
        const std::vector<uint8_t> &getModulus() const  { return modulus; }  
        std::vector<uint8_t> getDNSKeyFormat() const;
    private:
	std::vector<uint8_t> exponent;
	std::vector<uint8_t> modulus;
    };

    RSAPublicKeyImp::RSAPublicKeyImp( const std::vector<uint8_t> &exp, const std::vector<uint8_t> &mod )
	: exponent( exp ), modulus( mod )
    {}

    std::string RSAPublicKeyImp::toString() const
    {
	std::ostringstream os;
	std::string exponent_base64, modulus_base64;
	encode_to_base64( exponent, exponent_base64 );
	encode_to_base64( modulus,  modulus_base64 );

	os << "exponent: " << exponent_base64 << ", "
	   << "modulus: "  << modulus_base64;

	return os.str();
    }

    static void copyFactor( const std::vector<uint8_t> &src,
			    std::vector<uint8_t> &dst )
    {
	dst.clear();
	auto i = src.begin();
	for ( ; *i == 0 && i != src.end() ; i++ ); // skip front 0x00. see RFC3110 2
	for ( ; i != src.end() ; i++ )
	    dst.push_back( *i );
    }

    std::vector<uint8_t> RSAPublicKeyImp::getDNSKeyFormat() const
    {
	std::vector<uint8_t> result;
	std::vector<uint8_t> exponent_tmp, modulus_tmp;

	copyFactor( exponent, exponent_tmp );
	copyFactor( modulus,  modulus_tmp );
	
	uint32_t exponent_size = exponent_tmp.size();
	if ( exponent_size < 0x0100 ) {
	    result.push_back( exponent_size );
	}
	else {
	    result.push_back( 0 );
	    result.push_back( ( exponent_size & 0xff00 ) >>  8 );
	    result.push_back( ( exponent_size & 0x00ff ) >>  0 );
	}

	result.insert( result.end(), exponent_tmp.begin(), exponent_tmp.end() );
	result.insert( result.end(), modulus_tmp.begin(),  modulus_tmp.end() );
	return result;
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

    std::vector<uint8_t> RSAPublicKey::getDNSKeyFormat() const
    {
	return mImp->getDNSKeyFormat();
    }

}


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

    std::vector<uint8_t> signature;
    std::string message = "test message";

    signer.sign( message, signature );
    auto ksk_public_key = signer.getKSKPublicKey();
    auto zsk_public_key = signer.getZSKPublicKey();

    std::string signature_base64;
    encode_to_base64( signature, signature_base64 );

    std::cout << signature_base64 << std::endl;
    std::cout << ksk_public_key->toString() << std::endl;
    std::cout << zsk_public_key->toString() << std::endl;

    auto dss = signer.getDSRecords();
    auto dnskeys = signer.getDNSKeyRecords();
    for ( auto ds : dss )
        std::cout << ds->toString() << std::endl;
    for ( auto dnskey : dnskeys )
        std::cout << dnskey->toString() << std::endl;

    return 0;
}
