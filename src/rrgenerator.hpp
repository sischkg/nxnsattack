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

    class ResourceDataGeneratable
    {
    public:
        virtual ~ResourceDataGeneratable() {}
        virtual std::shared_ptr<ResourceData> generate( const PacketInfo &hint ) = 0;
        virtual std::shared_ptr<ResourceData> generate() = 0;
    };

    class ResourceRecordGenerator
    {
    public:
        ResourceRecordGenerator();

        RRSet generate( const PacketInfo &hint );

    private:
        std::vector<std::shared_ptr<ResourceDataGeneratable>> mGenerators;
    };

    template <class T> 
    class XNameGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    typedef XNameGenerator<RecordNS>    NSGenerator;
    typedef XNameGenerator<RecordCNAME> CNAMEGenerator;
    typedef XNameGenerator<RecordDNAME> DNAMEGenerator;
    
    class AGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class AAAAGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class SOAGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class RRSIGGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class DNSKEYGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class DSGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class NSECGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class TKEYGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class TSIGGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class SIGGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class KEYGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

    class NXTGenerator : public ResourceDataGeneratable
    {
    public:
        std::shared_ptr<ResourceData> generate( const PacketInfo &hint );
        std::shared_ptr<ResourceData> generate();
    };

}

#endif
