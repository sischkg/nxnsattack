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
        SignAlgorithm getAlgorithm() const { return DNSSEC_RSASHA1; }
        EVP_PKEY *getPrivateKey() const { return mPrivateKey; }
        uint16_t  getKeyTag() const { return mKeyTag; }
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

        uint16_t getKeyTag( const PrivateKeyImp &key ) const;
	std::shared_ptr<RecordRRSIG> generateRRSIG( const RRSet &, const PrivateKeyImp &key ) const;
	std::shared_ptr<RRSet> signRRSetByKeys( const RRSet &, const std::vector<std::shared_ptr<PrivateKeyImp> > &keys ) const;
        static void      throwException( const char *message, const char *other = nullptr );
	static std::shared_ptr<PublicKey> getPublicKey( EVP_PKEY *private_key );
        static const EVP_MD *enumToDigestMD( HashAlgorithm );
        static const EVP_MD *enumToSignMD( SignAlgorithm );

    public:
        ZoneSignerImp( const Domainname &d, const std::string &ksk, const std::string &zsk );
        ~ZoneSignerImp();

	void sign( const WireFormat &message,
		   std::vector<uint8_t> &signature,
		   const PrivateKeyImp &key,
		   SignAlgorithm algo ) const;

	std::shared_ptr<PublicKey> getKSKPublicKey() const;
	std::shared_ptr<PublicKey> getZSKPublicKey() const;

        std::shared_ptr<RecordDS>     getDSRecord( HashAlgorithm algo ) const;
        std::shared_ptr<RecordDNSKEY> getDNSKEYRecord( const PrivateKeyImp &private_key ) const;
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

}

#endif

