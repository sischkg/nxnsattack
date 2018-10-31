#ifndef RR_GENERATOR_HPP
#define RR_GENERATOR_HPP

#include "dns.hpp"
#include "zone.hpp"
#include <boost/noncopyable.hpp>
#include <boost/random.hpp>

namespace dns
{
    /**********************************************************
     * RandomGenarator
     **********************************************************/
    class RandomGenerator : private boost::noncopyable
    {
    public:
	uint32_t rand( uint32_t = 0xffffffff );
        std::vector<uint8_t> randStream( unsigned int );
        std::vector<uint8_t> randSizeStream( unsigned int );

	static RandomGenerator &getInstance();
    private:
        static RandomGenerator *mInstance;
        RandomGenerator();
    };


    inline uint32_t getRandom( uint32_t base = 0xffffffff )
    {
        return RandomGenerator::getInstance().rand( base );
    }

    inline std::vector<uint8_t> getRandomStream( unsigned int size )
    {
        return RandomGenerator::getInstance().randStream( size );
    }

    inline std::vector<uint8_t> getRandomSizeStream( unsigned int max_size )
    {
        return RandomGenerator::getInstance().randSizeStream( max_size );
    }


    inline bool withChance( float ratio )
    {
        if ( ratio < 0 || ratio > 1 )
            throw std::logic_error( "invalid ratio of change" );
        return getRandom( 0xffff ) < 0xffff * ratio; 
    }

    class DomainnameGenerator
    {
    public:
        Domainname generate( const Domainname &hint1, const Domainname &hint2 );
        Domainname generate();
        std::string generateLabel();
    };

    Domainname generateDomainname();

    class RDATAGeneratable
    {
    public:
        virtual ~RDATAGeneratable() {}
        virtual std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 ) = 0;
        virtual std::shared_ptr<RDATA> generate() = 0;
    };

    class ResourceRecordGenerator
    {
    public:
        ResourceRecordGenerator();

        RRSet generate( const PacketInfo &hint1, const Domainname &hint2 );

    private:
        std::vector<std::shared_ptr<RDATAGeneratable>> mGenerators;
    };

    class RawGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    template <class T> 
    class XNameGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    typedef XNameGenerator<RecordNS>    NSGenerator;
    typedef XNameGenerator<RecordCNAME> CNAMEGenerator;
    typedef XNameGenerator<RecordDNAME> DNAMEGenerator;
    
    class AGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class AAAAGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class WKSGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class SOAGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class RRSIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class DNSKEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class DSGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class NSECGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class NSEC3Generator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class NSEC3PARAMGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class TKEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class TSIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class SIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class KEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class NXTGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint1, const Domainname &hint2 );
        std::shared_ptr<RDATA> generate();
    };

    class OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint ) = 0;
	virtual std::shared_ptr<OptPseudoRROption> generate() = 0;
    };

    class RawOptionGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };

    class NSIDGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };

    class ClientSubnetGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };


    class CookieGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };

    class TCPKeepaliveGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };

    class KeyTagGenerator : public OptGeneratable
    {
    public:
	virtual std::shared_ptr<OptPseudoRROption> generate( const PacketInfo &hint );
	virtual std::shared_ptr<OptPseudoRROption> generate();
    };

    class OptionGenerator
    {
    public:
        OptionGenerator();

	void generate( PacketInfo &packet );
    private:
        std::vector<std::shared_ptr<OptGeneratable>> mGenerators;
    };

}

#endif
