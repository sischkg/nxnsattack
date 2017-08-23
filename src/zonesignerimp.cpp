#include "zonesignerimp.hpp"
#include <string>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <iterator>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace dns
{

    /*******************************************************************************************
     * PrivateKeyImp
     *******************************************************************************************/
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

    void ZoneSignerImp::sign( const WireFormat &message,
			      std::vector<uint8_t> &signature,
			      const PrivateKeyImp &key,
			      SignAlgorithm algo ) const
    {
	

	unsigned int digest_length = EVP_MAX_MD_SIZE;
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex( mdctx, EVP_sha1(), NULL);

	std::vector<uint8_t> digest_target = message.get();
	int res = EVP_DigestUpdate( mdctx, &digest_target[0], digest_target.size() );
				    /*
				    message.foreachBuffers(
			       [mdctx]( const uint8_t *begin, const uint8_t *end ) {
				   int res = EVP_DigestUpdate( mdctx, begin, end - begin );
				   if ( res != 1 ) {
				       throwException( "cannot update DigestUpdate" );
				   }
			       } );
				    */

        std::vector<uint8_t> digest( EVP_MAX_MD_SIZE );
        EVP_DigestFinal_ex( mdctx, &digest[0], &digest_length );
        digest.resize( digest_length );
        EVP_MD_CTX_free( mdctx );

	RSA* rsa = EVP_PKEY_get0_RSA( key.getPrivateKey() );
	unsigned int signature_length = RSA_size( rsa );
 	signature.resize( signature_length );
	int result = RSA_sign( NID_sha1, &digest[0], digest_length, &signature[0], &signature_length, rsa );
        std::cerr << "sign:" << message.size() << std::endl;
        if ( result != 1 ) {
            throwException( "RSA_sign failed" );
        }
	signature.resize( signature_length );
	/*

        int result =  EVP_DigestSignInit( mMDContext, NULL, enumToSignMD( algo ), NULL, key.getPrivateKey() );
        if ( result != 1 ) {
            throwException( "cannot initialize DigestSign" );
        }

	message.foreachBuffers(
			       [this]( const uint8_t *begin, const uint8_t *end ) {
				   int res = EVP_DigestSignUpdate( this->mMDContext, begin, end - begin );
				   if ( res != 1 ) {
				       throwException( "cannot update DigestSign" );
				   }
			       } );

        size_t sign_length;
        result = EVP_DigestSignFinal( mMDContext, NULL, &sign_length );
        if ( result != 1 ) {
            throwException( "cannot fetch result buffer length" );
        }

        signature.resize( sign_length );

        result = EVP_DigestSignFinal( mMDContext, &signature[0], &sign_length );
        if ( result != 1 ) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error( "cannot create signature" );
        }
	*/
    }

    void ZoneSignerImp::generateSignData( const RRSet &rrset, const PrivateKeyImp &key, WireFormat &sign_target ) const
    {
	sign_target.clear();
 
	sign_target.pushUInt16HtoN( rrset.getType() );                 // type covered
	sign_target.pushUInt8( key.getAlgorithm() );                   // algorithm
	sign_target.pushUInt8( rrset.getOwner().getLabels().size() );  // label
	sign_target.pushUInt32HtoN( rrset.getTTL() );                  // original ttl
	sign_target.pushUInt32HtoN( key.getNotAfter() );               // expiration
	sign_target.pushUInt32HtoN( key.getNotBefore() );              // inception
	sign_target.pushUInt16HtoN( getKeyTag( key ) );                // key tag
	key.getDomainname().outputCanonicalWireFormat( sign_target );  // signer 
	
	std::vector<ResourceDataPtr> ordered_rrs = rrset.getRRSet();
	std::sort( ordered_rrs.begin(),
		   ordered_rrs.end(),
		   []( const ResourceDataPtr &lhs, const ResourceDataPtr &rhs )
		   {
		       WireFormat lhs_data, rhs_data;
		       lhs->outputCanonicalWireFormat( lhs_data );
		       rhs->outputCanonicalWireFormat( rhs_data );
		       return lhs < rhs;
		   } );

	for ( auto rr : ordered_rrs ) {
	    rrset.getOwner().outputCanonicalWireFormat( sign_target );
	    sign_target.pushUInt16HtoN( rrset.getType() );
	    sign_target.pushUInt16HtoN( rrset.getClass() );
	    sign_target.pushUInt32HtoN( rrset.getTTL() );
	    WireFormat tmp;
	    rr->outputCanonicalWireFormat( tmp );
	    sign_target.pushUInt16HtoN( tmp.size() );
	    sign_target.pushBuffer( tmp.get() );
	}
    }

    std::shared_ptr<RecordRRSIG> ZoneSignerImp::generateRRSIG( const RRSet &rrset, const PrivateKeyImp &key ) const
    {
	WireFormat sign_target;
	generateSignData( rrset, key, sign_target );
	std::vector<uint8_t> signature;
	sign( sign_target, signature, key, key.getAlgorithm() );

        return std::shared_ptr<RecordRRSIG>( new RecordRRSIG( rrset.getType(),
                                                              key.getAlgorithm(),
                                                              rrset.getOwner().getLabels().size(),
                                                              rrset.getTTL(),
                                                              key.getNotAfter(),
                                                              key.getNotBefore(),
                                                              getKeyTag( key ),
                                                              key.getDomainname(),
                                                              signature ) );
    }

    std::shared_ptr<RRSet> ZoneSignerImp::signRRSetByKeys( const RRSet &rrset, const std::vector<std::shared_ptr<PrivateKeyImp> > &keys ) const
    {
        std::shared_ptr<RRSet> rrsig_rrset( new RRSet( rrset.getOwner(),
                                                       rrset.getClass(),
                                                       TYPE_RRSIG,
                                                       rrset.getTTL() ) );
        for ( auto key : keys ) {
            rrsig_rrset->add( generateRRSIG( rrset, *key ) );
        }

	return rrsig_rrset;
    }


    std::shared_ptr<RRSet> ZoneSignerImp::signRRSet( const RRSet &rrset ) const
    {
        std::vector<std::shared_ptr<PrivateKeyImp> > keys;
        keys.push_back( mZSK );
	return signRRSetByKeys( rrset, keys );
    }

    std::shared_ptr<RRSet> ZoneSignerImp::signDNSKEY( TTL ttl ) const
    {
	std::vector<std::shared_ptr<RecordDNSKEY>> dnskeys = getDNSKEYRecords();
	RRSet rrset( mKSK->getDomainname(), CLASS_IN, TYPE_DNSKEY, ttl );
	for ( auto k : dnskeys )
	    rrset.add( k );

        std::vector<std::shared_ptr<PrivateKeyImp> > keys;
        keys.push_back( mKSK );
        keys.push_back( mZSK );
        std::cerr << "signDNSKEY:" << rrset.getOwner().toString() << std::endl;
	return signRRSetByKeys( rrset, keys );
    }

    uint16_t ZoneSignerImp::getKeyTag( const PrivateKeyImp &key ) const
    {
        std::shared_ptr<RecordDNSKEY> dnskey = getDNSKEYRecord( key );
        WireFormat message;
        dnskey->outputWireFormat( message );

        // From RFC4034
        uint32_t ac = 0;

        for ( int i = 0; i < message.size() ; ++i )
            ac += (i & 1) ? message[i] : message[i] << 8;
        ac += (ac >> 16) & 0xFFFF;
        return ac & 0xffff;
    }

    std::shared_ptr<RecordDNSKEY> ZoneSignerImp::getDNSKEYRecord( const PrivateKeyImp &key ) const
    {
        std::shared_ptr<PublicKey> public_key = getPublicKey( key.getPrivateKey() );

        return std::shared_ptr<RecordDNSKEY>( new RecordDNSKEY( key.getKeyType(),
                                                                key.getAlgorithm(),
                                                                public_key->getDNSKEYFormat() ) );
    }

    std::vector<std::shared_ptr<RecordDNSKEY>> ZoneSignerImp::getDNSKEYRecords() const
    {
        std::vector<std::shared_ptr<RecordDNSKEY>> result;
        result.push_back( getDNSKEYRecord( *mKSK ) );
        result.push_back( getDNSKEYRecord( *mZSK ) );
        return result;
    }

    std::shared_ptr<RecordDS> ZoneSignerImp::getDSRecord( HashAlgorithm algo ) const
    {
        WireFormat hash_target;
        mKSK->getDomainname().outputCanonicalWireFormat( hash_target );
        std::shared_ptr<RecordDNSKEY> dnskey = getDNSKEYRecord( *mKSK );
        dnskey->outputWireFormat( hash_target );
        std::vector<uint8_t> hash_target_data = hash_target.get();

        unsigned int digest_length = EVP_MAX_MD_SIZE;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex( mdctx, enumToDigestMD( algo ), NULL);
        EVP_DigestUpdate( mdctx, &hash_target_data[0], hash_target_data.size() );
        std::vector<uint8_t> digest( EVP_MAX_MD_SIZE );
        EVP_DigestFinal_ex( mdctx, &digest[0], &digest_length );
        digest.resize( digest_length );
        EVP_MD_CTX_free( mdctx );

        return std::shared_ptr<RecordDS>( new RecordDS( getKeyTag( *mKSK ),
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

    const EVP_MD *ZoneSignerImp::enumToDigestMD( HashAlgorithm algo )
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

    const EVP_MD *ZoneSignerImp::enumToSignMD( SignAlgorithm algo )
    {
        switch ( algo ) {
        case DNSSEC_RSASHA1:
            return EVP_sha1();
        default:
            throw std::runtime_error( "unknown hash algorighm for RRSIG" );
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
     * RSAPublicKeyImp
     *******************************************************************************************/

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

    std::vector<uint8_t> RSAPublicKeyImp::getDNSKEYFormat() const
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


}

