#include "nsec3db.hpp"
#include "zonesignerimp.hpp"
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace dns
{

    static void calculateDigest( const PacketData &src,
				 EVP_MD_CTX *ctx,				 
				 HashAlgorithm algo,
				 PacketData &digest )
    {
	unsigned int digest_size = EVP_MAX_MD_SIZE;
	const EVP_MD *digest_algo  = enumToDigestMD( algo );

	EVP_DigestInit_ex( ctx, digest_algo, nullptr );

	int res = EVP_DigestUpdate( ctx, &src[0], src.size() );
        if ( 0 == res )
            throwException( "EVP_DigestUpdata failed" );
	digest.resize( digest_size );
	res = EVP_DigestFinal_ex( ctx, &digest[0], &digest_size );
        if ( 0 == res )
            throwException( "EVP_DigestFinal failed" );
	digest.resize( digest_size );
    }

    void calculateNSEC3Hash( const Domainname &original,
                             const Domainname &apex,
                             const PacketData &salt,
                             uint16_t iterate,
                             HashAlgorithm algorithm,
                             Domainname &nsec3_owner,
                             PacketData &hash )
    {
	PacketData hash_target;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	original.outputCanonicalWireFormat( hash_target );
	hash_target.insert( hash_target.end(), salt.begin(), salt.end() );

	calculateDigest( hash_target, ctx, algorithm, hash );

	for ( uint16_t i = 0 ; i < iterate ; i++ ) {
	    hash_target = hash;
	    hash_target.insert( hash_target.end(), salt.begin(), salt.end() );
	    calculateDigest( hash_target, ctx, algorithm, hash );
	}
	EVP_MD_CTX_free( ctx );

	std::string nsec3_label;
	encodeToBase32Hex( hash, nsec3_label );
	nsec3_owner = apex;
	nsec3_owner.addSubdomain( nsec3_label );
    }
    
    void NSEC3Entry::addTypes( const std::vector<Type> &types )
    {
	for( auto new_type : types ) {
	    auto itr = std::find( mTypes.begin(), mTypes.end(), new_type );
	    if ( itr == mTypes.end() )
		mTypes.push_back( new_type );
	}
    }

    std::string NSEC3Entry::getBase32Hash() const
    {
	std::string base32;
	encodeToBase32Hex( mHash, base32 );
	return base32;
    }

    void NSEC3DB::addNodeToContainer( NSEC3DB::Container &container, const Domainname &original, const std::vector<Type> &types )
    {
	PacketData hash;
	PacketData wildcard_hash;
	Domainname owner;
	Domainname wildcard_owner;
	Domainname wildcard_original;
	wildcard_original.addSubdomain( "*" );

	calculateNSEC3Hash( original, mApex, mSalt, mIterate, mHashAlgorithm, owner, hash );
	calculateNSEC3Hash( wildcard_original, mApex, mSalt, mIterate, mHashAlgorithm, wildcard_owner, wildcard_hash );

	auto nsec3entry = container.find( owner );
	if ( nsec3entry == container.end() ) {
	    std::pair<Domainname, NSEC3Entry> pair( owner,
						    NSEC3Entry( owner, original, hash, types, false ) );
	    container.insert( pair );
	}
	else {
	    if ( original == nsec3entry->second.getOwner() )
		nsec3entry->second.addTypes( types );
	    else {
		std::ostringstream os;
		os << "detected hash collision \""
		   << original << "\" and \"" << nsec3entry->first
		   << "\" => \"" << owner << "\".";
		throwException( os.str().c_str() );
	    }
	}

	auto wc_nsec3entry = container.find( wildcard_owner );
	if ( wc_nsec3entry == container.end() ) {
	    std::pair<Domainname, NSEC3Entry> wc_pair( wildcard_owner,
						       NSEC3Entry( wildcard_owner, wildcard_original, wildcard_hash, types, true ) );
	    container.insert( wc_pair );
	}
	else {
	    if ( original != nsec3entry->second.getOwner() )
		nsec3entry->second.addTypes( types );
	    else {
		std::ostringstream os;
		os << "detected hash collision \""
		   << original << "\" and \"" << nsec3entry->first
		   << "\" => \"" << owner << "\".";
		throwException( os.str() );
	    }
	}
    }

    void NSEC3DB::addNode( const Domainname &original, const Node &node )
    {
	std::vector<Type> types;
	for ( auto rrset = node.begin() ; rrset != node.end() ; rrset++ ) {
	    types.push_back( rrset->second->getType() );
	}

	addNodeToContainer( mNSEC3Entries, original, types );
    }

    void NSEC3DB::addEmptyNonTerminals()
    {
	Container new_nsec3_entries = mNSEC3Entries;
	int apex_label_count = mApex.getLabelCount();

	for ( auto entry : mNSEC3Entries ) {
	    if ( entry.first.getLabelCount() - apex_label_count > 1 ) {
		Domainname non_terminal = entry.first;
		non_terminal.popSubdomain();

		while ( non_terminal != mApex ) {
		    addNodeToContainer( new_nsec3_entries, non_terminal, std::vector<Type>() );
		    non_terminal.popSubdomain();
		}
	    }
	}
	mNSEC3Entries = new_nsec3_entries;
    }

    void NSEC3DB::deleteTemp()
    {
	Container new_nsec3_entries = mNSEC3Entries;
	for ( auto entry : mNSEC3Entries ) {
	    if ( ! entry.second.isTemp() )
		new_nsec3_entries.insert( entry );
	}
	mNSEC3Entries = new_nsec3_entries;
    }

    ResourceRecord NSEC3DB::find( const Domainname &name, TTL ttl ) const
    {
	Domainname owner;
	PacketData next_hash;
	std::vector<Type> types;
	auto nsec3_entry = mNSEC3Entries.lower_bound( name );
	auto next_entry  = mNSEC3Entries.upper_bound( name );
	if ( nsec3_entry == mNSEC3Entries.end() ) {
	    auto last = mNSEC3Entries.end();
	    last--;
	    owner = last->first.getCanonicalDomainname();
	    types = last->second.getTypes();
	    next_hash = mNSEC3Entries.begin()->second.getHash();
	}
	else if ( next_entry == mNSEC3Entries.end() ) {
	    owner = nsec3_entry->first.getCanonicalDomainname();
	    types = nsec3_entry->second.getTypes();
	    next_hash = mNSEC3Entries.begin()->second.getHash();
	}
	else {
	    owner = nsec3_entry->first.getCanonicalDomainname();
	    types = nsec3_entry->second.getTypes();
	    next_hash = next_entry->second.getHash();
	}

	ResourceRecord rr;
	rr.mDomainname = owner;
	rr.mClass      = CLASS_IN;
	rr.mType       = TYPE_NSEC3;
	rr.mTTL        = ttl;
	rr.mRData      = RDATAPtr( new RecordNSEC3( mHashAlgorithm,
						    0,
						    mIterate,
						    mSalt,
						    next_hash,
						    types ) );
	return rr;
    }
}

