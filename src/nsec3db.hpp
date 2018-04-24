#ifndef NSEC3DB_HPP
#define NSEC3DB_HPP

#include "dns.hpp"
#include "zonesigner.hpp"
#include <map>

namespace dns
{
    void calculateNSEC3Hash( const Domainname &original,
                             const std::vector<uint8_t> &salt,
                             uint16_t iterate,
                             HashAlgorithm algorithm,
                             Domainname &nsec3_owner,
                             std::vector<uint8_t> &hash );

    class NSEC3Entry
    {
    public:
        NSEC3Entry( const Domainname &owner,
		    const Domainname &original,
		    const std::vector<uint8_t> &hash,
		    const std::vector<Type> &types,
		    bool is_temp )
            : mOwner( owner ),
              mOriginal( original ),
              mHash( hash ),
              mTypes( types ),
              mIsTemp( is_temp )
        {}

	void addTypes( const std::vector<Type> &types );

	const Domainname &getOwner() const { return mOwner; }
	const Domainname &getOriginal() const { return mOriginal; }
	const std::vector<uint8_t> &getHash() const { return mHash; }
	std::string getBase32Hash() const;
	const std::vector<Type> getTypes() const { return mTypes; }
	bool isTemp() const { return mIsTemp; }
    private:
        Domainname           mOwner;
	Domainname           mOriginal;
        std::vector<uint8_t> mHash;
        std::vector<Type>    mTypes;
	bool                 mIsTemp;
    };

    
    class NSEC3DB
    {
	typedef std::map<Domainname, NSEC3Entry> Container;
    public:
	NSEC3DB( const Domainname &apex,
		 const std::vector<uint8_t> &salt,
		 uint16_t iterate,
		 HashAlgorithm algo )
	    : mApex( apex ), mSalt( salt ), mIterate( iterate ), mHashAlgorithm( algo )
	{}

	void addNode( const Domainname &name, const Node &node );
	void addEmptyNonTerminals();
	void deleteTemp();
	ResourceRecord findNSEC3( const Domainname &name, TTL ttl ) const;
    private:
	Domainname mApex;
	std::vector<uint8_t> mSalt;
	uint16_t mIterate;
	HashAlgorithm mHashAlgorithm;
	Container mNSEC3Entries;

	void addNodeToContainer( Container &container, const Domainname &name, const std::vector<Type> &types );
    };

}

#endif
