#ifndef ZONE_SIGNER_IMP_HPP
#define ZONE_SIGNER_IMP_HPP

#include "zonesigner.hpp"
#include <boost/utility.hpp>
#include <string>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <yaml-cpp/yaml.h>

namespace dns
{

    /*******************************************************************************************
     * PrivateKeyImp
     *******************************************************************************************/
    /*
      type: KSK
      domain: example.com
      algorithm: RSASHA1
      not_before: 1502238577
      not_after: 1502413242
      key_file: /etc/nsd/keys/example.com.ksk.key
    */
    class PrivateKeyImp : private boost::noncopyable
    {
    public:
        ~PrivateKeyImp();

        KeyType           getKeyType() const    { return mKeyType; }
        SignAlgorithm     getAlgorithm() const  { return mSignAlgorithm; }
        EVP_PKEY         *getPrivateKey() const { return mPrivateKey; }
        uint16_t          getKeyTag() const     { return mKeyTag; }
        uint32_t          getNotBefore() const  { return mNotBefore; }
        uint32_t          getNotAfter() const   { return mNotAfter; }
        const Domainname  getDomainname() const { return mDomainname; }

	std::shared_ptr<PublicKey> getPublicKey() const;
	
	static std::vector<std::shared_ptr<PrivateKeyImp> > load( const std::string &config );
        static std::vector<std::shared_ptr<PrivateKeyImp> > loadConfig( const std::string &config_file );
    private:
        KeyType        mKeyType;
	SignAlgorithm  mSignAlgorithm;
        EVP_PKEY      *mPrivateKey;
        uint16_t       mKeyTag;
        uint32_t       mNotBefore;
        uint32_t       mNotAfter;
        Domainname     mDomainname;

        PrivateKeyImp( KeyType key_type,
		       SignAlgorithm algo,
		       EVP_PKEY *key,
		       uint16_t tag,
		       uint32_t not_before,
		       uint32_t not_after,
		       const Domainname &domain )
            : mKeyType( key_type ),
	      mSignAlgorithm( algo ),
	      mPrivateKey( key ),
	      mKeyTag( tag ),
	      mNotBefore( not_before ),
	      mNotAfter( not_after ),
	      mDomainname( domain )
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
	std::vector< std::shared_ptr<PrivateKeyImp> > mKSKs;
        std::vector< std::shared_ptr<PrivateKeyImp> > mZSKs;

        uint16_t getKeyTag( const PrivateKeyImp &key ) const;
	std::shared_ptr<RecordRRSIG>  generateRRSIG( const RRSet &, const PrivateKeyImp &key ) const;
	std::shared_ptr<RRSet>        signRRSetByKeys( const RRSet &, const std::vector<std::shared_ptr<PrivateKeyImp> > &keys ) const;
        std::shared_ptr<RecordDS>     getDSRecord( const PrivateKeyImp &ksk, HashAlgorithm algo ) const;
        std::shared_ptr<RecordDNSKEY> getDNSKEYRecord( const PrivateKeyImp &private_key ) const;

        static void      throwException( const char *message, const char *other = nullptr );

       static const EVP_MD *enumToDigestMD( HashAlgorithm );
        static const EVP_MD *enumToSignMD( SignAlgorithm );

    public:
        ZoneSignerImp( const Domainname &d, const std::string &ksks, const std::string &zsks );
        ~ZoneSignerImp();

	void sign( const WireFormat &message,
		   std::vector<uint8_t> &signature,
		   const PrivateKeyImp &key,
		   SignAlgorithm algo ) const;

	std::vector<std::shared_ptr<PublicKey>> getKSKPublicKeys() const;
	std::vector<std::shared_ptr<PublicKey>> getZSKPublicKeys() const;

        std::vector<std::shared_ptr<RecordDS> >     getDSRecords() const;
        std::vector<std::shared_ptr<RecordDNSKEY> > getDNSKEYRecords() const;

	void generateSignData( const RRSet &rrset, const PrivateKeyImp &key, WireFormat &sign_target ) const;
	std::shared_ptr<RRSet> signRRSet( const RRSet & ) const;
	std::shared_ptr<RRSet> signDNSKEY( TTL ttl ) const;

        static void initialize();
    };

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
        std::vector<uint8_t> getDNSKEYFormat() const;
    private:
	std::vector<uint8_t> exponent;
	std::vector<uint8_t> modulus;
    };

    /*******************************************************************************************
     * ECDSAPublicKeyImp
     *******************************************************************************************/
    /*!
     * ECDSAPublicKeyImp
     */
    class ECDSAPublicKeyImp
    {
    public:
        ECDSAPublicKeyImp( const std::vector<uint8_t> &public_key );

        std::string toString() const;
        std::vector<uint8_t> getDNSKEYFormat() const;
    private:
	std::vector<uint8_t> mQ;
    };

}

#endif

