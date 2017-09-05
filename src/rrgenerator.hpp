#ifndef RR_GENERATOR_HPP
#define RR_GENERATOR_HPP

#include "dns.hpp"
#include "zone.hpp"
#include <boost/noncopyable.hpp>

namespace dns
{
    /**********************************************************
     * RandomGenarator
     **********************************************************/
    class RandomGenerator : private boost::noncopyable
    {
    public:
	uint32_t rand( uint32_t = 0 );
        std::vector<uint8_t> randStream( unsigned int );

	static RandomGenerator &getInstance();
    private:
        static RandomGenerator *mInstance;
        RandomGenerator();
    };


    inline uint32_t getRandom( uint32_t base = 0 )
    {
        return RandomGenerator::getInstance().rand( base );
    }

    inline std::vector<uint8_t> getRandomStream( unsigned int size )
    {
        return RandomGenerator::getInstance().randStream( size );
    }


    class DomainnameGenerator
    {
    public:
        Domainname generate( const Domainname &hint );
        Domainname generate();
    private:
        std::string generateLabel();
    };

    class RDATAGeneratable
    {
    public:
        virtual ~RDATAGeneratable() {}
        virtual std::shared_ptr<RDATA> generate( const PacketInfo &hint ) = 0;
        virtual std::shared_ptr<RDATA> generate() = 0;
    };

    class ResourceRecordGenerator
    {
    public:
        ResourceRecordGenerator();

        RRSet generate( const PacketInfo &hint );

    private:
        std::vector<std::shared_ptr<RDATAGeneratable>> mGenerators;
    };

    template <class T> 
    class XNameGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    typedef XNameGenerator<RecordNS>    NSGenerator;
    typedef XNameGenerator<RecordCNAME> CNAMEGenerator;
    typedef XNameGenerator<RecordDNAME> DNAMEGenerator;
    
    class AGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class AAAAGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class SOAGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class RRSIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class DNSKEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class DSGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class NSECGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class TKEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class TSIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class SIGGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class KEYGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };

    class NXTGenerator : public RDATAGeneratable
    {
    public:
        std::shared_ptr<RDATA> generate( const PacketInfo &hint );
        std::shared_ptr<RDATA> generate();
    };
}

#endif
