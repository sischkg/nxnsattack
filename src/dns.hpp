#ifndef DNS_HPP
#define DNS_HPP

#include "utils.hpp"
#include "domainname.hpp"
#include <boost/cstdint.hpp>
#include <boost/shared_ptr.hpp>
#include <deque>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace dns
{
    typedef std::vector<uint8_t>::iterator       PacketIterator;
    typedef std::vector<uint8_t>::const_iterator ConstPacketIterator;

    typedef uint8_t Opcode;
    const Opcode    OPCODE_QUERY  = 0;
    const Opcode    OPCODE_NOTIFY = 4;
    const Opcode    OPCODE_UPDATE = 5;

    typedef uint16_t Class;
    const Class      CLASS_IN      = 1;
    const Class      CLASS_CH      = 3;
    const Class      CLASS_HS      = 4;
    const Class      CLASS_NONE    = 254;
    const Class      CLASS_ANY     = 255;
    const Class      UPDATE_NONE   = 254;
    const Class      UPDATE_EXIST  = 255;
    const Class      UPDATE_ADD    = 1;
    const Class      UPDATE_DELETE = 255;

    typedef uint16_t Type;
    const Type       TYPE_A           = 1;
    const Type       TYPE_NS          = 2;
    const Type       TYPE_CNAME       = 5;
    const Type       TYPE_SOA         = 6;
    const Type       TYPE_WKS         = 11;
    const Type       TYPE_MX          = 15;
    const Type       TYPE_TXT         = 16;
    const Type       TYPE_SIG         = 24;
    const Type       TYPE_KEY         = 25;
    const Type       TYPE_AAAA        = 28;
    const Type       TYPE_NXT         = 30;
    const Type       TYPE_NAPTR       = 35;
    const Type       TYPE_DNAME       = 39;
    const Type       TYPE_OPT         = 41;
    const Type       TYPE_APL         = 42;
    const Type       TYPE_DS          = 43;
    const Type       TYPE_RRSIG       = 46;
    const Type       TYPE_NSEC        = 47;
    const Type       TYPE_DNSKEY      = 48;
    const Type       TYPE_NSEC3       = 50;
    const Type       TYPE_NSEC3PARAM  = 51;
    const Type       TYPE_TLSA        = 52;
    const Type       TYPE_SPF         = 99;
    const Type       TYPE_TKEY        = 249;
    const Type       TYPE_TSIG        = 250;
    const Type       TYPE_IXFR        = 251;
    const Type       TYPE_AXFR        = 252;
    const Type       TYPE_ANY         = 255;
    const Type       TYPE_CAA         = 257;

    typedef uint32_t TTL;

    typedef uint16_t OptType;
    const OptType    OPT_NSID          = 3;
    const OptType    OPT_CLIENT_SUBNET = 8;
    const OptType    OPT_COOKIE        = 10;
    const OptType    OPT_TCP_KEEPALIVE = 11;

    typedef uint8_t    ResponseCode;
    const ResponseCode NO_ERROR       = 0;
    const ResponseCode NXRRSET        = 0;
    const ResponseCode FORMAT_ERROR   = 1;
    const ResponseCode SERVER_ERROR   = 2;
    const ResponseCode NAME_ERROR     = 3;
    const ResponseCode NXDOMAIN       = 3;
    const ResponseCode NOT_IMPLEENTED = 4;
    const ResponseCode REFUSED        = 5;
    const ResponseCode BADSIG         = 16;
    const ResponseCode BADKEY         = 17;
    const ResponseCode BADTIME        = 18;

    class RDATA;
    typedef std::shared_ptr<RDATA> RDATAPtr;
    typedef std::shared_ptr<const RDATA> ConstRDATAPtr;

    class RDATA
    {
    public:
        virtual ~RDATA()
        {
        }

        virtual std::string toZone() const                                  = 0;
        virtual std::string toString() const                                = 0;
        virtual void outputWireFormat( WireFormat &message ) const          = 0;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const = 0;
        virtual Type     type() const                                       = 0;
        virtual uint16_t size() const                                       = 0;
	virtual RDATA *clone() const                                 = 0;
	
        std::ostream &operator<<( std::ostream &os ) const
        {
            os << toString();
            return os;
        }
    };

    class RecordRaw : public RDATA
    {
    private:
        uint16_t             mRRType;
        std::vector<uint8_t> mData;

    public:
        RecordRaw( uint8_t t, const std::vector<uint8_t> &d )
	    : mRRType( t ), mData( d )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return mRRType;
        }
        virtual uint16_t size() const
        {
            return mData.size();
        }
	virtual RecordRaw *clone() const { return new RecordRaw( mRRType, mData ); }
    };

    class RecordA : public RDATA
    {
    private:
        uint32_t mSinAddr;

    public:
        RecordA( uint32_t in_sin_addr );
        RecordA( const std::string &in_address );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return TYPE_A;
        }
        virtual uint16_t size() const
        {
            return sizeof( mSinAddr );
        }
	virtual RecordA *clone() const { return new RecordA( mSinAddr ); }

	std::string getAddress() const;
        static RDATAPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordAAAA : public RDATA
    {
    private:
        uint8_t mSinAddr[ 16 ];

    public:
        RecordAAAA( const uint8_t *sin_addr );
        RecordAAAA( const std::string &address );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return TYPE_AAAA;
        }
        virtual uint16_t size() const
        {
            return sizeof( mSinAddr );
        }
	virtual RecordAAAA *clone() const { return new RecordAAAA( mSinAddr ); }

	std::string getAddress() const;

        static RDATAPtr parse( const uint8_t *begin, const uint8_t *end );
    };


    class RecordWKS : public RDATA
    {
    private:
        uint32_t          mSinAddr;
        uint8_t           mProtocol;
        std::vector<Type> mBitmap;

    public:
        RecordWKS( uint32_t sin_addr, uint8_t proto, const std::vector<Type> & );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual Type type() const
        {
            return TYPE_WKS;
        }
        virtual uint16_t size() const
        {
            return sizeof( mSinAddr );
        }
	virtual RecordWKS *clone() const { return new RecordWKS( mSinAddr, mProtocol, mBitmap ); }

	std::string getAddress() const;
        uint8_t     getProtocol() const { return mProtocol; }
        const std::vector<Type> &getBitmap() const { return mBitmap; }
        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end,
                               const uint8_t *rdata_begin,  const uint8_t *rdata_end );
    };


    class RecordNS : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordNS( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_NS;
        }
        virtual uint16_t size() const
        {
            return mDomainname.size();
        }
	virtual RecordNS *clone() const { return new RecordNS( mDomainname ); }
	const Domainname &getNameServer() const { return mDomainname; }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordMX : public RDATA
    {
    private:
        uint16_t   mPriority;
        Domainname mDomainname;

    public:
        RecordMX( uint16_t pri, const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_MX;
        }
        virtual uint16_t size() const
        {
            return sizeof( mPriority ) + mDomainname.size();
        }
	virtual RecordMX *clone() const { return new RecordMX( mPriority, mDomainname ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordTXT : public RDATA
    {
    private:
        std::vector<std::string> mData;

    public:
        RecordTXT( const std::string &data );
        RecordTXT( const std::vector<std::string> &data );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_TXT;
        }
        virtual uint16_t size() const;
	virtual RecordTXT *clone() const { return new RecordTXT( mData ); }
	const std::vector<std::string> &getTexts() const { return mData; }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordSPF : public RDATA
    {
    private:
        std::vector<std::string> data;

    public:
        RecordSPF( const std::string &data );
        RecordSPF( const std::vector<std::string> &data );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_SPF;
        }
        virtual uint16_t size() const;
	virtual RecordSPF *clone() const { return new RecordSPF( data ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordCNAME : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordCNAME( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_CNAME;
        }
        virtual uint16_t size() const
        {
            return mDomainname.size();
        }
	virtual RecordCNAME *clone() const { return new RecordCNAME( mDomainname ); }

        const Domainname &getCanonicalName() const { return mDomainname; }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordNAPTR : public RDATA
    {
    private:
        uint16_t    mOrder;
        uint16_t    mPreference;
        std::string mFlags;
        std::string mServices;
        std::string mRegexp;
        Domainname  mReplacement;

    public:
        RecordNAPTR( uint16_t           in_order,
                     uint16_t           in_preference,
                     const std::string &in_flags,
                     const std::string &in_services,
                     const std::string &in_regexp,
                     const Domainname & in_replacement );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_NAPTR;
        }
        virtual uint16_t size() const;
	virtual RecordNAPTR *clone() const { return new RecordNAPTR( mOrder, mPreference, mFlags, mServices, mRegexp, mReplacement ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordDNAME : public RDATA
    {
    private:
        Domainname mDomainname;

    public:
        RecordDNAME( const Domainname &name );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_DNAME;
        }
        virtual uint16_t size() const
        {
            return mDomainname.size();
        }
        const Domainname &getCanonicalName() const { return mDomainname; }

	virtual RecordDNAME *clone() const { return new RecordDNAME( mDomainname ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordSOA : public RDATA
    {
    private:
        Domainname mMName;
        Domainname mRName;
        uint32_t   mSerial;
        uint32_t   mRefresh;
        uint32_t   mRetry;
        uint32_t   mExpire;
        uint32_t   mMinimum;

    public:
        RecordSOA( const Domainname &mname,
                   const Domainname &rname,
                   uint32_t          serial,
                   uint32_t          refresh,
                   uint32_t          retry,
                   uint32_t          expire,
                   uint32_t          minimum );

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_SOA;
        }
        virtual uint16_t size() const;

        const std::string getMName() const
        {
            return mMName.toString();
        }
        const std::string getRName() const
        {
            return mRName.toString();
        }
	virtual RecordSOA *clone() const
	{
	    return new RecordSOA( mMName,
				  mRName,
                                  mSerial,
				  mRefresh,
				  mRetry,
				  mExpire,
				  mMinimum );
	}

	uint32_t getSerial() const { return mSerial; }
	uint32_t getRefresh() const { return mRefresh; }
	uint32_t getRetry() const { return mRetry; }
	uint32_t getExpire() const { return mExpire; }
	uint32_t getMinimum() const { return mMinimum; }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };


    struct APLEntry {
        uint16_t   mAddressFamily;
        uint8_t    mPrefix;
        bool       mNegation;
        PacketData mAFD;
    };

    class RecordAPL : public RDATA
    {
    private:
        std::vector<APLEntry> mAPLEntries;

    public:
        static const uint16_t IPv4    = 1;
        static const uint16_t IPv6    = 2;
        static const uint16_t Invalid = 0xffff;

        RecordAPL( const std::vector<APLEntry> &in_apls )
            : mAPLEntries( in_apls )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_APL;
        }
        virtual uint16_t size() const;
	virtual RecordAPL *clone() const { return new RecordAPL( mAPLEntries ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordCAA : public RDATA
    {
    private:
        uint8_t     mFlag;
        std::string mTag;
        std::string mValue;

    public:
        static const uint8_t CRITICAL     = 1;
        static const uint8_t NOT_CRITICAL = 0;

        RecordCAA( const std::string &tag, const std::string &value, uint8_t flag = NOT_CRITICAL )
            : mFlag( flag ), mTag( tag ), mValue( value )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_CAA;
        }
        virtual uint16_t size() const;
	virtual RecordCAA *clone() const { return new RecordCAA( *this ); }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordRRSIG : public RDATA
    {
    private:
        Type       mTypeCovered;
        uint8_t    mAlgorithm;
        uint8_t    mLabelCount;
        uint32_t   mOriginalTTL;
        uint32_t   mExpiration;
        uint32_t   mInception;
        uint16_t   mKeyTag;
        Domainname mSigner;
        std::vector<uint8_t> mSignature;

    public:
        static const uint16_t SIGNED_KEY = 1 << 7;
        static const uint8_t  RSAMD5     = 1;
        static const uint8_t  RSASHA1    = 5;
        static const uint8_t  RSASHA256  = 8;
        static const uint8_t  RSASHA512  = 10;

        RecordRRSIG( Type                       t,
                     uint8_t                    algo,
                     uint8_t                    label,
                     uint32_t                   ttl,
                     uint32_t                   expire,
                     uint32_t                   incept,
                     uint16_t                   tag,
                     const Domainname           &sign,
                     const std::vector<uint8_t> &sig )
            : mTypeCovered( t ),
              mAlgorithm( algo ),
              mLabelCount( label ),
              mOriginalTTL( ttl ),
              mExpiration( expire ),
              mInception( incept ),
              mKeyTag( tag ),
              mSigner( sign ),
              mSignature( sig )
        {
        }

        Type     getTypeCovered() const { return mTypeCovered; }
        uint8_t  getAlgorithm() const { return mAlgorithm; }
        uint8_t  getLabelCount() const { return mLabelCount; }
        uint32_t getOriginalTTL() const { return mOriginalTTL; }
        uint32_t getExpiration() const { return mExpiration; }
        uint32_t getInception() const { return mInception; }
        uint8_t  getKeyTag() const { return mKeyTag; }
        const Domainname           &getSigner() const { return mSigner; }
        const std::vector<uint8_t> &getSignature() const { return mSignature; }
 
        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const
        {
            return 2 +  // type_covered(uint16_t)
                1 +  // algorithm
                1 +  // label count
                4 +  // original ttl
                4 +  // expiration
                4 +  // inception
                2 +  // key tag
                mSigner.size() +
                mSignature.size();
        }

        virtual uint16_t type() const
        {
            return TYPE_RRSIG;
        }
	virtual RecordRRSIG *clone() const
	{
	    return new RecordRRSIG( mTypeCovered,
				    mAlgorithm,
				    mLabelCount,
				    mOriginalTTL,
				    mExpiration,
				    mInception,
				    mKeyTag,
				    mSigner,
				    mSignature );
	}

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };


    class RecordDNSKEY : public RDATA
    {
    private:
        uint16_t             mFlag;
        uint8_t              mAlgorithm;
        std::vector<uint8_t> mPublicKey;

    public:
        static const uint16_t SIGNED_KEY = 1 << 7;
        static const uint8_t  RSAMD5     = 1;
        static const uint8_t  RSASHA1    = 5;
        static const uint8_t  RSASHA256  = 8;
        static const uint8_t  RSASHA512  = 10;

        static const uint16_t KSK = 1 << 8;
        static const uint16_t ZSK = 0;

        RecordDNSKEY( uint16_t f, uint8_t algo, const std::vector<uint8_t> &key )
            : mFlag( f ), mAlgorithm( algo ), mPublicKey( key )
        {}
        
        uint16_t getFlag() const { return mFlag; }
        uint8_t  getAlgorithm() const { return mAlgorithm; }
        const std::vector<uint8_t> getPublicKey() const { return mPublicKey; }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const
        {
            return sizeof(mFlag) + sizeof(mAlgorithm) + 1 + mPublicKey.size();
        }

        virtual uint16_t type() const
        {
            return TYPE_DNSKEY;
        }

	virtual RecordDNSKEY *clone() const
	{
	    return new RecordDNSKEY( mFlag, mAlgorithm, mPublicKey );
	}

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };


    class RecordDS : public RDATA
    {
    private:
        uint16_t             key_tag;
        uint8_t              algorithm;
        uint8_t              digest_type;
        std::vector<uint8_t> digest;

    public:
        RecordDS( uint16_t tag, uint8_t alg, uint8_t dtype, const std::vector<uint8_t> &d )
            : key_tag( tag ), algorithm( alg ), digest_type( dtype ), digest( d )
        {}

        uint16_t getKeyTag()    const { return key_tag; }
        uint8_t  getAlgorighm() const { return algorithm; }
        uint8_t  getDigesType() const { return digest_type; }
        std::vector<uint8_t> getDigest() const { return digest; }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const
        {
            return 2 + 1 + 1 + digest.size();
        }

        virtual uint16_t type() const
        {
            return TYPE_DS;
        }

	virtual RecordDS *clone() const
	{
	    return new RecordDS( key_tag,
				 algorithm,
				 digest_type,
				 digest );
	}

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };


    class NSECBitmapField
    {
    public:
	class Window
	{
	public:
	    explicit Window( uint8_t i = 0 )
		: index( i )
	    {}

	    void        setIndex( uint8_t i ) { index = i; }
	    void        add( Type );
	    uint16_t    size() const;
	    void        outputWireFormat( WireFormat &message ) const;
	    std::string toString() const;
	    uint16_t    getIndex() const { return index; }
            uint8_t     getWindowSize() const;
            const std::vector<Type> &getTypes() const {  return types; }

	    static const uint8_t *parse( Window &ref_windown, const uint8_t *packet_begin, const uint8_t *bitmap_begin, const uint8_t *bitmap_end );

	private:
	    uint16_t          index;
	    std::vector<Type> types;

	    static uint8_t typeToBitmapIndex( Type );
	};

	void        add( Type );
	void        addWindow( const Window &win );
        std::vector<Type> getTypes() const;

	std::string toString() const;
	uint16_t    size() const;
	void        outputWireFormat( WireFormat &message ) const;

	static const uint8_t *parse( NSECBitmapField &ref_bitmaps,
                                     const uint8_t *packet_begin, const uint8_t *packet_end,
                                     const uint8_t *rdata_begin, const uint8_t *rdata_end );
    private:
	std::map<uint8_t, Window> windows;

	static uint8_t typeToWindowIndex( Type );
        //        static NSECBitmapField parse( const uint8_t *packet, const uint8_t *begin, const uint8_t *end );
    };

    class RecordNSEC : public RDATA
    {
    private:
        Domainname      next_domainname;
        NSECBitmapField bitmaps;

    public:
	RecordNSEC( const Domainname &next, const NSECBitmapField &b )
	    : next_domainname( next ), bitmaps( b )
	{}
	RecordNSEC( const Domainname &next, const std::vector<Type> &types );
        const Domainname &getNextDomainname() const { return next_domainname; }
        std::vector<Type> getTypes() const { return bitmaps.getTypes(); }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const;
        virtual uint16_t type() const
        {
            return TYPE_NSEC;
        }
	virtual RecordNSEC *clone() const
	{
	    return new RecordNSEC( next_domainname, bitmaps );
	}
	
        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    class RecordNSEC3 : public RDATA
    {
    public:
	typedef uint8_t HashAlgorithm;
    private:
	HashAlgorithm        mHashAlgorithm;
	uint8_t              mFlag;
	uint16_t             mIteration;
	std::vector<uint8_t> mSalt;
	std::vector<uint8_t> mNextHash;
        NSECBitmapField      mBitmaps;

    public:
	RecordNSEC3( HashAlgorithm              algo,
		     uint8_t                    flag,
		     uint16_t                   iteration,
		     const std::vector<uint8_t> &salt,
		     const std::vector<uint8_t> &next_hash,
		     const std::vector<Type>    &bitmaps );
	RecordNSEC3( HashAlgorithm               algo,
		     uint8_t                     flag,
		     uint16_t                    iteration,
		     const std::vector<uint8_t> &salt,
		     const std::vector<uint8_t> &next_hash,
		     const NSECBitmapField      &bitmaps )
	    : mHashAlgorithm( algo ),
	      mFlag( flag ),
	      mIteration( iteration ),
	      mSalt( salt ),
	      mNextHash( next_hash ),
	      mBitmaps( bitmaps )
	{}
	
	HashAlgorithm        getHashAlgoritm() const { return mHashAlgorithm; }
	uint8_t              getFlag() const { return mFlag; }
	uint16_t             getIteration() const { return mIteration; }
	std::vector<uint8_t> getSalt() const { return mSalt; }
	std::vector<uint8_t> getNextHash() const { return mNextHash; }
        std::vector<Type>    getTypes() const { return mBitmaps.getTypes(); }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const;
        virtual uint16_t type() const
        {
            return TYPE_NSEC3;
        }
	virtual RecordNSEC3 *clone() const
	{
	    return new RecordNSEC3( mHashAlgorithm, mFlag, mIteration, mSalt, mNextHash, mBitmaps.getTypes() );
	}
	
        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };


    class RecordNSEC3PARAM : public RDATA
    {
    public:
	typedef uint8_t HashAlgorithm;
    private:
	HashAlgorithm        mHashAlgorithm;
	uint8_t              mFlag;
	uint16_t             mIteration;
	std::vector<uint8_t> mSalt;

    public:
	RecordNSEC3PARAM( HashAlgorithm              algo,
                          uint8_t                    flag,
                          uint16_t                   iteration,
                          const std::vector<uint8_t> &salt );
	
	HashAlgorithm        getHashAlgoritm() const { return mHashAlgorithm; }
	uint8_t              getFlag() const { return mFlag; }
	uint16_t             getIteration() const { return mIteration; }
	std::vector<uint8_t> getSalt() const { return mSalt; }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const;
        virtual uint16_t type() const
        {
            return TYPE_NSEC3PARAM;
        }
	virtual RecordNSEC3PARAM *clone() const
	{
	    return new RecordNSEC3PARAM( mHashAlgorithm, mFlag, mIteration, mSalt );
	}
	
        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    const uint8_t PROTOCOL_TLS    = 0x01;
    const uint8_t PROTOCOL_MAIL   = 0x02;
    const uint8_t PROTOCOL_DNSSEC = 0x03;
    const uint8_t PROTOCOL_IPSEC  = 0x04;
    const uint8_t PROTOCOL_ANY    = 0xFF;

    const uint8_t ALGORITHM_DH = 0x02;

    class RecordKEY : public RecordDNSKEY
    {
    public:
	RecordKEY( uint16_t f, uint8_t a, const std::vector<uint8_t> &p )
	    : RecordDNSKEY( f, a, p )
	{}

        virtual uint16_t type() const
        {
            return TYPE_KEY;
        }

    	virtual RecordKEY *clone() const
	{
	    return new RecordKEY( getFlag(), getAlgorithm(), getPublicKey() );
	}
    };


    class RecordSIG : public RecordRRSIG
    {
    public:
        RecordSIG( Type                       t,
                   uint8_t                    algo,
                   uint8_t                    label,
                   uint32_t                   ttl,
                   uint32_t                   expire,
                   uint32_t                   incept,
                   uint16_t                   tag,
                   const Domainname           &sign,
                   const std::vector<uint8_t> &sig )
            : RecordRRSIG( t, algo, label, ttl, expire, incept, tag, sign, sig )
        {}

        virtual uint16_t type() const
        {
            return TYPE_SIG;
        }
	virtual RecordSIG *clone() const
	{
	    return new RecordSIG( getTypeCovered(),
				  getAlgorithm(),
				  getLabelCount(),
				  getOriginalTTL(),
				  getExpiration(),
				  getInception(),
				  getKeyTag(),
				  getSigner(),
				  getSignature() );
	}
    };


    class RecordNXT : public RecordNSEC
    {
    public:
	RecordNXT( const Domainname &next, const NSECBitmapField &b )
	    : RecordNSEC( next, b )
	{}
	RecordNXT( const Domainname &next, const std::vector<Type> &types )
	    : RecordNSEC( next, types )
	{}
	
        virtual uint16_t type() const
        {
            return TYPE_NXT;
        }
	virtual RecordNXT *clone() const
	{
	    return new RecordNXT( getNextDomainname(), getTypes() );
	}
    };
    
    class OptPseudoRROption
    {
    public:
        virtual ~OptPseudoRROption()
        {
        }
        virtual std::string toString() const                       = 0;
        virtual void        outputWireFormat( WireFormat & ) const = 0;
        virtual uint16_t    code() const                           = 0;
        virtual uint16_t    size() const                           = 0;
	virtual OptPseudoRROption *clone() const                   = 0;
    };

    typedef std::shared_ptr<OptPseudoRROption> OptPseudoRROptPtr;

    class RAWOption : public OptPseudoRROption
    {
    private:
        uint16_t             option_code;
        std::vector<uint8_t> option_data;

    public:
        RAWOption( uint16_t in_code, const std::vector<uint8_t> &in_data )
            : option_code( in_code ), option_data( in_data )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return option_code;
        }
        virtual uint16_t size() const
        {
            return option_data.size() + 2;
        }
	virtual RAWOption *clone() const
	{
	    return new RAWOption( option_code, option_data );
	}
    };

    class NSIDOption : public OptPseudoRROption
    {
    private:
        std::string nsid;

    public:
        NSIDOption( const std::string &id = "" ) : nsid( id )
        {
        }

        virtual std::string toString() const
        {
            return "NSID: \"" + nsid + "\"";
        }
        virtual void     outputWireFormat( WireFormat & ) const;
        virtual uint16_t code() const
        {
            return OPT_NSID;
        }
        virtual uint16_t size() const
        {
            return 2 + 2 + nsid.size();
        }
	virtual NSIDOption *clone() const
	{
	    return new NSIDOption( nsid );
	}

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class ClientSubnetOption : public OptPseudoRROption
    {
    private:
        uint16_t    family;
        uint8_t     source_prefix;
        uint8_t     scope_prefix;
        std::string address;

        static unsigned int getAddressSize( uint8_t prefix );

    public:
        static const int IPv4 = 1;
        static const int IPv6 = 2;

        ClientSubnetOption( uint16_t fam, uint8_t source, uint8_t scope, const std::string &addr )
            : family( fam ), source_prefix( source ), scope_prefix( scope ), address( addr )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_CLIENT_SUBNET;
        }
	virtual ClientSubnetOption *clone() const
	{
	    return new ClientSubnetOption( family, source_prefix, scope_prefix, address );
	}
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class CookieOption : public OptPseudoRROption
    {
    private:
        std::vector<uint8_t> mClientCookie;
        std::vector<uint8_t> mServerCookie;

    public:
        CookieOption( const std::vector<uint8_t> &client, const std::vector<uint8_t> &server = std::vector<uint8_t>() )
            : mClientCookie( client ), mServerCookie( server )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_COOKIE;
        }
	virtual CookieOption *clone() const
	{
	    return new CookieOption( mClientCookie, mServerCookie );
	}
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class TCPKeepaliveOption : public OptPseudoRROption
    {
    private:
        uint16_t mTimeout;

    public:
        TCPKeepaliveOption( uint16_t timeout )
            : mTimeout( timeout )
        {
        }

        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual uint16_t    code() const
        {
            return OPT_TCP_KEEPALIVE;
        }
	virtual TCPKeepaliveOption *clone() const
	{
	    return new TCPKeepaliveOption( mTimeout );
	}
        virtual uint16_t size() const;

        static OptPseudoRROptPtr parse( const uint8_t *begin, const uint8_t *end );
    };

    class RecordOptionsData : public RDATA
    {
    private:
        std::vector<OptPseudoRROptPtr> options;

    public:
        RecordOptionsData( const std::vector<OptPseudoRROptPtr> &in_options = std::vector<OptPseudoRROptPtr>() )
        {
	    for ( auto op : in_options )
		options.push_back( OptPseudoRROptPtr( op->clone() ) );
        }

	RecordOptionsData( const RecordOptionsData &data )
	{
	    for ( auto op : data.getOptions() )
		options.push_back( OptPseudoRROptPtr( op->clone() ) );
	}

	RecordOptionsData &operator=( const RecordOptionsData &data )
	{
	    options.clear();
	    for ( auto op : data.getOptions() )
		options.push_back( OptPseudoRROptPtr( op->clone() ) );
	    return *this;
	}

	void add( OptPseudoRROptPtr opt ) { options.push_back( opt ); }
        virtual std::string toZone() const { return ""; }
        virtual std::string toString() const;
        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t type() const
        {
            return TYPE_OPT;
        }
        virtual uint16_t size() const;
	virtual RecordOptionsData *clone() const
	{
	    return new RecordOptionsData( options );
	}
	
        const std::vector<OptPseudoRROptPtr> &getOptions() const
        {
            return options;
        }

        static RDATAPtr parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end );
    };

    struct OptPseudoRecord {
        Domainname mDomainname;
        uint16_t   mPayloadSize;
        uint8_t    mRCode;
        uint8_t    mVersion;
	bool       mDOBit;
        RDATAPtr   mOptions;

        OptPseudoRecord()
            : mDomainname( "." ),
              mPayloadSize( 1280 ),
              mRCode( 0 ),
              mDOBit(false),
              mOptions( RDATAPtr( new RecordOptionsData ) )
        {}

	OptPseudoRecord( const OptPseudoRecord &opt ) :
	    mDomainname( opt.mDomainname ),
	    mPayloadSize( opt.mPayloadSize ),
	    mRCode( opt.mRCode ),
	    mVersion( opt.mVersion ),
	    mDOBit( opt.mDOBit )
        {
	    if ( opt.mOptions )
		mOptions = RDATAPtr( opt.mOptions->clone() );
        }

	OptPseudoRecord &operator=( const OptPseudoRecord &rhs )
	{
	    mDomainname  = rhs.mDomainname;
	    mPayloadSize = rhs.mPayloadSize;
	    mRCode       = rhs.mRCode;
	    mVersion     = rhs.mVersion;
	    mDOBit       = rhs.mDOBit;
	    if ( rhs.mOptions )
		mOptions = RDATAPtr( rhs.mOptions->clone() );
	    else
		mOptions = RDATAPtr( new RecordOptionsData );
	    return *this;
	}
    };

    class RecordTKEY : public RDATA
    {
    public:
        Domainname domain;
        Domainname algorithm;
        uint32_t   inception;
        uint32_t   expiration;
        uint16_t   mode;
        uint16_t   error;
        PacketData key;
        PacketData other_data;

    public:
        RecordTKEY( const std::string &dom    = "",
                    const std::string &algo   = "HMAC-MD5.SIG-ALG.REG.INT",
                    uint32_t           incept = 0,
                    uint32_t           expire = 0,
                    uint16_t           m      = 0,
                    uint16_t           err    = 0,
                    PacketData         k      = PacketData(),
                    PacketData         other  = PacketData() )
            : domain( dom ), algorithm( algo ), inception( incept ), expiration( expire ), mode( m ), error( err ),
              key( k ), other_data( other )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TKEY;
        }
        virtual uint16_t size() const;
	virtual RecordTKEY *clone() const
	{
	    return new RecordTKEY( domain.toString(),
				   domain.toString(),
				   inception,
				   expiration,
				   mode,
				   error,
				   key,
				   other_data );
	}
    };

    struct TSIGInfo {
        std::string name;
        PacketData  key;
        std::string algorithm;
        PacketData  mac;
        uint64_t    signed_time;
        uint16_t    fudge;
        uint16_t    mac_size;
        uint16_t    original_id;
        uint16_t    error;
        PacketData  other;

        TSIGInfo()
            : name(), key(), algorithm( "HMAC-MD5.SIG-ALG.REG.INT" ), mac(), signed_time( 0 ), fudge( 0 ),
              mac_size( 0 ), original_id( 0 ), error( 0 ), other()
        {
        }
    };

    class RecordTSIGData : public RDATA
    {
    public:
        Domainname key_name;
        Domainname algorithm;
        uint64_t   signed_time;
        uint16_t   fudge;
        uint16_t   mac_size;
        PacketData mac;
        uint16_t   original_id;
        uint16_t   error;
        uint16_t   other_length;
        PacketData other;

    public:
        RecordTSIGData( const std::string &in_key_name     = "",
                        const std::string &in_algo         = "HMAC-MD5.SIG-ALG.REG.INT",
                        uint64_t           in_signed_time  = 0,
                        uint16_t           in_fudge        = 0,
                        uint16_t           in_mac_size     = 0,
                        const PacketData & in_mac          = PacketData(),
                        uint16_t           in_original_id  = 0,
                        uint16_t           in_error        = 0,
                        uint16_t           in_other_length = 0,
                        const PacketData & in_other        = PacketData() )
	: key_name( in_key_name ), algorithm( in_algo ), signed_time( in_signed_time ), fudge( in_fudge ),
	  mac_size( in_mac_size ), mac( in_mac ), original_id( in_original_id ), error( in_error ),
	  other_length( in_other_length ), other( in_other )
        {
        }

        virtual std::string toZone() const;
        virtual std::string toString() const;
        virtual void        outputWireFormat( WireFormat & ) const;
        virtual void        outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t    type() const
        {
            return TYPE_TSIG;
        }
        virtual uint16_t size() const;
	virtual RecordTSIGData *clone() const
	{
	    return new RecordTSIGData( key_name.toString(),
				       algorithm.toString(),
				       signed_time,
				       fudge,
				       mac_size,
				       mac,
				       original_id,
				       error,
				       other_length,
				       other );
	}
        static RDATAPtr
        parse( const uint8_t *packet_begin, const uint8_t *packet_end, const uint8_t *rdata_begin, const uint8_t *rdata_end, const Domainname &key_name );
    };

    class RecordTSIG
    {
    public:
        Domainname name;
        Domainname algorithm;
        uint64_t   signed_time;
        uint16_t   fudge;
        uint16_t   mac_size;
        PacketData mac;
        uint16_t   original_id;
        uint16_t   error;
        uint16_t   other_length;
        PacketData other;

    public:
        RecordTSIG( const std::string &in_name         = "",
                    const std::string &in_algo         = "HMAC-MD5.SIG-ALG.REG.INT",
                    uint64_t           in_signed_time  = 0,
                    uint16_t           in_fudge        = 0,
                    uint16_t           in_mac_size     = 0,
                    PacketData         in_mac          = PacketData(),
                    uint16_t           in_original_id  = 0,
                    uint16_t           in_error        = 0,
                    uint16_t           in_other_length = 0,
                    PacketData         in_other        = PacketData() )
	: name( in_name ), algorithm( in_algo ), signed_time( in_signed_time ), fudge( in_fudge ),
	  mac_size( in_mac_size ), mac( in_mac ), original_id( in_original_id ), error( in_error ),
	  other_length( in_other_length ), other( in_other )
        {
        }
    };

    struct QuestionSectionEntry {
        Domainname q_domainname;
        uint16_t   q_type;
        uint16_t   q_class;

        QuestionSectionEntry() : q_type( 0 ), q_class( 0 )
        {
        }

	uint16_t size() const;
    };

    struct ResourceRecord {
        Domainname r_domainname;
        uint16_t   r_type;
        uint16_t   r_class;
        uint32_t   r_ttl;
        RDATAPtr   r_resource_data;

        ResourceRecord() : r_type( 0 ), r_class( 0 ), r_ttl( 0 )
        {
        }

    	uint16_t size() const;

	ResourceRecord( const ResourceRecord &entry )
	    : r_domainname( entry.r_domainname ),
	      r_type( entry.r_type ),
	      r_class( entry.r_class ),
	      r_ttl( entry.r_ttl )
	{
	    if ( entry.r_resource_data )
		r_resource_data = RDATAPtr( entry.r_resource_data->clone() );
	}
	
	ResourceRecord &operator=( const ResourceRecord &rhs )
	{
	    r_domainname = rhs.r_domainname;
	    r_type       = rhs.r_type;
	    r_class      = rhs.r_class;
	    r_ttl        = rhs.r_ttl;
	    if ( rhs.r_resource_data )
		r_resource_data = RDATAPtr( rhs.r_resource_data->clone() );
	    else
		r_resource_data = RDATAPtr();
	    
	    return *this;
	}
    };

    struct PacketInfo {
        uint16_t id;

        uint8_t query_response;
        uint8_t opcode;
        bool    authoritative_answer;
        bool    truncation;
        bool    recursion_desired;

        bool    recursion_available;
        bool    checking_disabled;
        bool    zero_field;
        bool    authentic_data;
        uint8_t response_code;

        bool edns0;
        bool tsig;

	OptPseudoRecord opt_pseudo_rr;
        RecordTSIGData  tsig_rr;

        std::vector<QuestionSectionEntry> question_section;
        std::vector<ResourceRecord> answer_section;
        std::vector<ResourceRecord> authority_section;
        std::vector<ResourceRecord> additional_infomation_section;

        PacketInfo()
            : id( 0 ), query_response( 0 ), opcode( 0 ), authoritative_answer( 0 ), truncation( false ),
              recursion_desired( false ), recursion_available( false ), checking_disabled( false ), zero_field( 0 ),
              authentic_data( false ), response_code( 0 ), edns0( false ), tsig( false )
        {
        }

	bool isEDNS0() const
	{
	    return edns0;
	}

	bool isDNSSECOK() const
	{
	    return opt_pseudo_rr.mDOBit;
	}

        const std::vector<QuestionSectionEntry> &getQuestionSection() const { return question_section; }
        const std::vector<ResourceRecord> &getAnswerSection() const { return answer_section; }
        const std::vector<ResourceRecord> &getAuthoritySection() const { return authority_section; }
        const std::vector<ResourceRecord> &getAdditionalInfomationSection() const { return additional_infomation_section; }

        void pushQuestionSection( const QuestionSectionEntry &e ) { return question_section.push_back( e ); }
        void pushAnswerSection( const ResourceRecord &e ) { return answer_section.push_back( e ); }
        void pushAuthoritySection( const ResourceRecord &e ) { return authority_section.push_back( e ); }
        void pushAdditionalInfomationSection( const ResourceRecord &e ) { return additional_infomation_section.push_back( e ); }

        void clearQuestionSection() { return question_section.clear(); }
        void clearAnswerSection() { return answer_section.clear(); }
        void clearAuthoritySection() { return authority_section.clear(); }
        void clearAdditionalInfomationSection() { return additional_infomation_section.clear(); }

        void generateMessage( WireFormat & ) const;
        uint32_t getMessageSize() const;
    };

    PacketInfo parseDNSMessage( const uint8_t *begin, const uint8_t *end );
    std::ostream &operator<<( std::ostream &os, const PacketInfo &query );
    std::ostream &printHeader( std::ostream &os, const PacketInfo &packet );
    std::string typeCodeToString( Type t );
    std::string responseCodeToString( uint8_t rcode );
    Type stringToTypeCode( const std::string & );

    struct PacketHeaderField {
        uint16_t id;

        uint8_t recursion_desired : 1;
        uint8_t truncation : 1;
        uint8_t authoritative_answer : 1;
        uint8_t opcode : 4;
        uint8_t query_response : 1;

        uint8_t response_code : 4;
        uint8_t checking_disabled : 1;
        uint8_t authentic_data : 1;
        uint8_t zero_field : 1;
        uint8_t recursion_available : 1;

        uint16_t question_count;
        uint16_t answer_count;
        uint16_t authority_count;
        uint16_t additional_infomation_count;
    };

    struct SOAField {
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    };

    ResourceRecord generateOptPseudoRecord( const OptPseudoRecord & );

    void
    addTSIGResourceRecord( const TSIGInfo &tsig_info, WireFormat &message, const PacketData &query_mac = PacketData() );
    bool
    verifyTSIGResourceRecord( const TSIGInfo &tsig_info, const PacketInfo &packet_info, const WireFormat &message );

    
    template <typename Type>
    Type get_bytes( const uint8_t **pos )
    {
        Type v = *reinterpret_cast<const Type *>( *pos );
        *pos += sizeof( Type );
        return v;
    }
}

#endif
