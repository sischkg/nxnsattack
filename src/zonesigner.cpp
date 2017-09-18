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

    std::vector<std::shared_ptr<PublicKey>> ZoneSigner::getKSKPublicKeys() const
    {
	return mImp->getKSKPublicKeys();
    }

    std::vector<std::shared_ptr<PublicKey>> ZoneSigner::getZSKPublicKeys() const
    {
	return mImp->getZSKPublicKeys();
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

    /*******************************************************************************************
     * ECDSAPublicKey
     *******************************************************************************************/

    ECDSAPublicKey::ECDSAPublicKey( const std::vector<uint8_t> &public_key )
	: mImp( new ECDSAPublicKeyImp( public_key ) )
    {}

    std::string ECDSAPublicKey::toString() const
    {
	return mImp->toString();
    }

    std::vector<uint8_t> ECDSAPublicKey::getDNSKEYFormat() const
    {
	return mImp->getDNSKEYFormat();
    }

}

