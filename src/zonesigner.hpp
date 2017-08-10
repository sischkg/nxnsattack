#ifndef ZONE_SIGNER_HPP
#define ZONE_SIGNER_HPP

#include "dns.hpp"

namespace dns
{
    class ZoneSignerImp;
    class PrivateKeyImp;
    class PublicKey;
    class RSAPublicKey;
    class RSAPublicKeyImp;

    enum KeyType {
        KSK = 257,
        ZSK = 256,
    };

    enum HashAlgorithm {
	DNSSEC_SHA1   = 1,
	DNSSEC_SHA256 = 2,
    };

    enum Algorithm {
	DNSSEC_RSA = 8,
    };
    
    class PublicKey {
    public:
        virtual ~PublicKey() {}
        virtual std::string toString() const = 0;
        virtual std::vector<uint8_t> getDNSKeyFormat() const = 0;
    };
    
    class RSAPublicKey : public PublicKey
    {
    public:
        RSAPublicKey( const std::vector<uint8_t> &exp, const std::vector<uint8_t> &mod );
	
        virtual std::string toString() const;
        const std::vector<uint8_t> &getExponent() const;
        const std::vector<uint8_t> &getModulus() const;
        std::vector<uint8_t> getDNSKeyFormat() const;
    private:
	std::shared_ptr<RSAPublicKeyImp> mImp;
    };
	

    class ZoneSigner
    {
    public:
        ZoneSigner( const Domainname &d, const std::string &ksk, const std::string &zsk );

        void sign( const uint8_t *message, size_t size,
                   std::vector<uint8_t> &signature, HashAlgorithm algo = DNSSEC_SHA256 ) const;
        void sign( const std::vector<uint8_t> &message,
                   std::vector<uint8_t> &signature, HashAlgorithm algo = DNSSEC_SHA256 ) const;
        void sign( const std::string &message,
                   std::vector<uint8_t> &signature, HashAlgorithm algo = DNSSEC_SHA256) const;

	std::shared_ptr<PublicKey> getKSKPublicKey() const;
	std::shared_ptr<PublicKey> getZSKPublicKey() const;

        std::vector<std::shared_ptr<RecordDS>> getDSRecords() const;
        std::vector<std::shared_ptr<RecordDNSKey>> getDNSKeyRecords() const;

        static void initialize();

    private:
        std::shared_ptr<ZoneSignerImp> mImp;
    };
}

#endif
