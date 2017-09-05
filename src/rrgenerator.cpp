#include "rrgenerator.hpp"
#include <boost/noncopyable.hpp>
#include <sys/types.h>
#include <unistd.h>
#include <cstdlib>

namespace dns
{
    /**********************************************************
     * RandomGenarator
     **********************************************************/    
    RandomGenerator *RandomGenerator::mInstance = nullptr;
    
    RandomGenerator::RandomGenerator()
    {
	std::srand( getpid() * time( nullptr ) );
    }

    uint32_t RandomGenerator::rand( uint32_t base )
    {
	if ( base == 0 )
	    return std::rand();
	return std::rand() % base;
    }

    std::vector<uint8_t> RandomGenerator::randStream( unsigned int size )
    {
        std::vector<uint8_t> stream;
        for ( unsigned int i = 0 ; i < size ; i++ )
            stream.push_back( this->rand( 0xff ) );
	return stream;
    }

    RandomGenerator &RandomGenerator::getInstance()
    {
	if ( mInstance == nullptr )
	    mInstance = new RandomGenerator();
	return *mInstance;
    }
    
    /**********************************************************
     * DomainnameGenarator
     **********************************************************/
    std::string DomainnameGenerator::generateLabel()
    {
        std::string label;
        unsigned int label_size = 1 + getRandom( 63 );
        for ( unsigned int i = 0 ; i < label_size ; i++ )
            label.push_back( getRandom( 256 ) );
        return label;
    }

    Domainname DomainnameGenerator::generate()
    {
        unsigned int label_count = 1 + getRandom( 100 );
        unsigned int domainname_size = 0;
        std::deque<std::string> labels;
        for ( unsigned int i = 0 ; i < label_count ; i++ ) {
            auto label = generateLabel();
            if ( domainname_size + label.size() + 1 >= 255 )
                break;
            labels.push_back( label );
            domainname_size += ( label.size() + 1 );
        }

        return Domainname( labels );
    }

    Domainname DomainnameGenerator::generate( const Domainname &hint )
    {
        Domainname result = hint;
        switch ( getRandom( 4 ) ) {
        case 0:
            return result;
        case 1: // erase labels;
            {
                unsigned int erased_label_count = getRandom( hint.getLabels().size() );
                for ( unsigned int i = 0 ; i < erased_label_count ; i++ ) {
                    result.popSubdomain();
                }

                return result; 
            }
        case 2: // append labels as sudomain;
            {
                unsigned int label_count        = hint.getLabels().size();
                unsigned int append_label_count = getRandom( 255 - hint.getLabels().size() );
                unsigned int domainname_size    = hint.size();
                for ( unsigned int i = 0 ; i < append_label_count ; i++ ) {
                    std::string new_label = generateLabel();
                    if ( label_count + 1 >= 128 || domainname_size + new_label.size() + 1 >= 255 )
                        break;
                    result.addSubdomain( new_label );
                    domainname_size += ( new_label.size() + 1 );
                    label_count++;
                }

                return result; 
            }
        case 3: // replace labels;
            {
                unsigned int erased_label_count = getRandom( hint.getLabels().size() );
                for ( unsigned int i = 0 ; i < erased_label_count ; i++ ) {
                    result.popSubdomain();
                }

                unsigned int label_count        = result.getLabels().size();
                unsigned int append_label_count = getRandom( 255 - result.getLabels().size() );
                unsigned int domainname_size    = result.size();
                for ( unsigned int i = 0 ; i < append_label_count ; i++ ) {
                    std::string new_label = generateLabel();
                    if ( label_count + 1 >= 128 || domainname_size + new_label.size() + 1 >= 255 )
                        break;
                    result.addSubdomain( new_label );
                    domainname_size += ( new_label.size() + 1 );
                    label_count++;
                }

                return result; 
            }
        default:
            throw std::logic_error( "generate domainname error" );
        }
    }

    static Domainname generateDomainname( const Domainname &hint )
    {
        DomainnameGenerator g;
        return g.generate( hint );
    }

    static Domainname generateDomainname()
    {
        DomainnameGenerator g;
        return g.generate();
    }


    Domainname getDomainname( const PacketInfo &hint )
    {
        std::vector<Domainname> names;
        for ( auto rr : hint.getQuestionSection() ) {
            names.push_back( rr.q_domainname );
        }
        for ( auto rr : hint.getAnswerSection() ) {
            names.push_back( rr.r_domainname );
        }
        for ( auto rr : hint.getAuthoritySection() ) {
            names.push_back( rr.r_domainname );
        }
        for ( auto rr : hint.getAdditionalInfomationSection() ) {
            names.push_back( rr.r_domainname );
        }

        unsigned int index = getRandom( names.size() );
        std::cerr << "index: " << index << ", "
                  << "size: "  << names.size() << ", "
                  << "Domainname: " << names[index] << std::endl;
        return names[getRandom( names.size() )];
    }


    /**********************************************************
     * XNAMEGenarator
     **********************************************************/
    template<class T>
    std::shared_ptr<RDATA> XNameGenerator<T>::generate( const PacketInfo &hint )
    {
        Domainname hint_name;
        uint32_t qdcount = hint.getQuestionSection().size();
        uint32_t ancount = hint.getAnswerSection().size();
        uint32_t nscount = hint.getAuthoritySection().size();
        uint32_t adcount = hint.getAdditionalInfomationSection().size();

        uint32_t index = getRandom( qdcount + ancount + nscount + adcount );
        if ( index < qdcount ) {
            hint_name = hint.getQuestionSection()[index].q_domainname;
        }
        else if ( index < qdcount + ancount ) {
            hint_name = hint.getAnswerSection()[index - qdcount].r_domainname;
        }
        else if ( index < qdcount + ancount + nscount ) {
            hint_name = hint.getAuthoritySection()[index - qdcount - ancount].r_domainname;
        }
        else if ( index < qdcount + ancount + nscount + adcount ) {
            hint_name = hint.getAuthoritySection()[index - qdcount - ancount - nscount].r_domainname;
        }
        else {
            throw std::logic_error( "invalid index of XNameGenerator::generate( hint )" );
        }

        return std::shared_ptr<RDATA>( new T( DomainnameGenerator().generate( hint_name ) ) );
    }

    template<class T>
    std::shared_ptr<RDATA> XNameGenerator<T>::generate()
    {
        return std::shared_ptr<RDATA>( new T( DomainnameGenerator().generate() ) );
    }


    /**********************************************************
     * AGenarator
     **********************************************************/
    std::shared_ptr<RDATA> AGenerator::generate( const PacketInfo &hint )
    {
        std::vector<std::shared_ptr<RDATA> > record_a_list;
        for ( auto rr : hint.getAnswerSection() ) {
            if ( rr.r_type == TYPE_A ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }
        for ( auto rr : hint.getAuthoritySection() ) {
            if ( rr.r_type == TYPE_A ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }
        for ( auto rr : hint.getAdditionalInfomationSection() ) {
            if ( rr.r_type == TYPE_A ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }
 
        if ( record_a_list.size() == 0 )
            return generate();

        std::cerr << "hint: " << hint << std::endl;
        std::cerr << "record_a_list size: " << record_a_list.size() << std::endl;
        unsigned int index = getRandom( record_a_list.size() );
        std::cerr << "index: " << index << std::endl;
	return std::shared_ptr<RDATA>( record_a_list[index]->clone() );
    }

    std::shared_ptr<RDATA> AGenerator::generate()
    {
        return std::shared_ptr<RDATA>( new RecordA( getRandom() ) );
    }

    
    /**********************************************************
     * AAAAGenarator
     **********************************************************/
    std::shared_ptr<RDATA> AAAAGenerator::generate( const PacketInfo &hint )
    {
        std::vector<std::shared_ptr<RDATA> > record_a_list;
        for ( auto rr : hint.getAnswerSection() ) {
            if ( rr.r_type == TYPE_AAAA ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }
        for ( auto rr : hint.getAuthoritySection() ) {
            if ( rr.r_type == TYPE_AAAA ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }
        for ( auto rr : hint.getAdditionalInfomationSection() ) {
            if ( rr.r_type == TYPE_AAAA ) {
                record_a_list.push_back( rr.r_resource_data );
            }
        }

        if ( record_a_list.size() == 0 )
            return generate();

        std::cerr << "hint: " << hint << std::endl;
        std::cerr << "record_a_list size: " << record_a_list.size() << std::endl;
        unsigned int index = getRandom( record_a_list.size() );
        std::cerr << "index: " << index << std::endl;
	return std::shared_ptr<RDATA>( record_a_list[index]->clone() );
    }

    std::shared_ptr<RDATA> AAAAGenerator::generate()
    {
        std::vector<uint8_t> sin_addr = getRandomStream( 16 );
        return std::shared_ptr<RDATA>( new RecordAAAA( &sin_addr[0] ) );
    }


    /**********************************************************
     * SOAGenarator
     **********************************************************/
    std::shared_ptr<RDATA> SOAGenerator::generate( const PacketInfo &hint )
    {
	return std::shared_ptr<RDATA>( new RecordSOA( getDomainname( hint ),
                                                             getDomainname( hint ),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom() ) );
    }

    std::shared_ptr<RDATA> SOAGenerator::generate()
    {
	return std::shared_ptr<RDATA>( new RecordSOA( generateDomainname(),
                                                             generateDomainname(),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom(),
                                                             getRandom() ));
    }

    /**********************************************************
     * RRSIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> RRSIGGenerator::generate( const PacketInfo &hint )
    {
        std::vector<uint8_t> signature = getRandomStream( 256 );

	std::shared_ptr<RDATA> p( new RecordRRSIG( getRandom( 0xffff ), // type covered
                                                          getRandom( 0xff ),   // algorithm
                                                          getRandom( 0xff ),   // label
                                                          getRandom(),         // original ttl
                                                          getRandom(),         // expiration
                                                          getRandom(),         // inception
                                                          getRandom( 0xffff ), // key tag
                                                          generateDomainname( getDomainname( hint ) ),
                                                          signature ) );
        return p;
    }

    std::shared_ptr<RDATA> RRSIGGenerator::generate()
    {
        std::vector<uint8_t> signature = getRandomStream( 256 );
	return std::shared_ptr<RDATA>( new RecordRRSIG( getRandom( 0xffff ), // type covered
                                                               getRandom( 0xff ),   // algorithm
                                                               getRandom( 0xff ),   // label
                                                               getRandom(),         // original ttl
                                                               getRandom(),         // expiration
                                                               getRandom(),         // inception
                                                               getRandom( 0xffff ), // key tag
                                                               generateDomainname(),
                                                               signature ) );
    }

    /**********************************************************
     * DNSKEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> DNSKEYGenerator::generate( const PacketInfo &hint )
    {
        std::vector<uint8_t> public_key = getRandomStream( 132 );
	return std::shared_ptr<RDATA>( new RecordDNSKEY( getRandom() % 2 ? RecordDNSKEY::KSK : RecordDNSKEY::ZSK,
                                                                RecordDNSKEY::RSASHA1,
                                                                public_key ) );
    }

    std::shared_ptr<RDATA> DNSKEYGenerator::generate()
    {
        std::vector<uint8_t> public_key = getRandomStream( 132 );
	return std::shared_ptr<RDATA>( new RecordDNSKEY( getRandom() % 2 ? RecordDNSKEY::KSK : RecordDNSKEY::ZSK,
                                                                RecordDNSKEY::RSASHA1,
                                                                public_key ) );
    }


    /**********************************************************
     * DSGenarator
     **********************************************************/
    std::shared_ptr<RDATA> DSGenerator::generate( const PacketInfo &hint )
    {
        if ( getRandom( 2 ) ) {
            std::vector<uint8_t> hash = getRandomStream( 20 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ),
                                                                5,
                                                                1,
                                                                hash ) );
        }
        else {
            std::vector<uint8_t> hash = getRandomStream( 32 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ),
                                                                5,
                                                                2,
                                                                hash ) );
        }
    }

    std::shared_ptr<RDATA> DSGenerator::generate()
    {
        if ( getRandom( 2 ) ) {
            std::vector<uint8_t> hash = getRandomStream( 40 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ),
                                                                5,
                                                                1,
                                                                hash ) );
        }
        else {
            std::vector<uint8_t> hash = getRandomStream( 64 );
            return std::shared_ptr<RDATA>( new RecordDS( getRandom( 0xffff ),
                                                                5,
                                                                2,
                                                                hash ) );
        }
    }


    /**********************************************************
     * NSECGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NSECGenerator::generate( const PacketInfo &hint )
    {
        std::vector<Type> types;
        unsigned int type_count = getRandom( 0xffff );
        for ( unsigned int i = 0 ; i < type_count ; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC( getDomainname( hint ),
                                                              types ) );
    }

    std::shared_ptr<RDATA> NSECGenerator::generate()
    {
        std::vector<Type> types;
        unsigned int type_count = getRandom( 0xffff );
        for ( unsigned int i = 0 ; i < type_count ; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC( generateDomainname(), types ) );
    }

    /**********************************************************
     * SIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> SIGGenerator::generate( const PacketInfo &hint )
    {
        std::vector<uint8_t> signature = getRandomStream( 256 );

	std::shared_ptr<RDATA> p( new RecordSIG( getRandom( 0xffff ), // type covered
							getRandom( 0xff ),   // algorithm
							getRandom( 0xff ),   // label
							getRandom(),         // original ttl
							getRandom(),         // expiration
							getRandom(),         // inception
							getRandom( 0xffff ), // key tag
							generateDomainname( getDomainname( hint ) ),
							signature ) );
        return p;
    }

    std::shared_ptr<RDATA> SIGGenerator::generate()
    {
        std::vector<uint8_t> signature = getRandomStream( 256 );
	return std::shared_ptr<RDATA>( new RecordSIG( getRandom( 0xffff ), // type covered
							     getRandom( 0xff ),   // algorithm
							     getRandom( 0xff ),   // label
							     getRandom(),         // original ttl
							     getRandom(),         // expiration
							     getRandom(),         // inception
							     getRandom( 0xffff ), // key tag
							     generateDomainname(),
							     signature ) );
    }

    /**********************************************************
     * KEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> KEYGenerator::generate( const PacketInfo &hint )
    {
        std::vector<uint8_t> public_key = getRandomStream( 132 );
	return std::shared_ptr<RDATA>( new RecordKEY( 0xffff,
							     RecordDNSKEY::RSASHA1,
							     public_key ) );
    }

    std::shared_ptr<RDATA> KEYGenerator::generate()
    {
        std::vector<uint8_t> public_key = getRandomStream( 132 );
	return std::shared_ptr<RDATA>( new RecordKEY( getRandom( 0xffff ),
							     RecordDNSKEY::RSASHA1,
							     public_key ) );
    }

    /**********************************************************
     * NXTGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NXTGenerator::generate( const PacketInfo &hint )
    {
        std::vector<Type> types;
        unsigned int type_count = getRandom( 0xffff );
        for ( unsigned int i = 0 ; i < type_count ; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNXT( getDomainname( hint ),
							     types ) );
    }

    std::shared_ptr<RDATA> NXTGenerator::generate()
    {
        std::vector<Type> types;
        unsigned int type_count = getRandom( 0xffff );
        for ( unsigned int i = 0 ; i < type_count ; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNXT( generateDomainname(), types ) );
    }


    /**********************************************************
     * ResourceRecordGenarator
     **********************************************************/
    ResourceRecordGenerator::ResourceRecordGenerator()
    {
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new CNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AAAAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SOAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new RRSIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNSKEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSECGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new KEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NXTGenerator ) );
    }


    RRSet ResourceRecordGenerator::generate( const PacketInfo &hint )
    {
        Class class_table[] = { CLASS_IN, CLASS_CH, CLASS_HS, CLASS_NONE, CLASS_ANY };

        std::shared_ptr<RDATA> resource_data = mGenerators[ getRandom( mGenerators.size() )]->generate( hint );

        RRSet rrset( getDomainname( hint ),
                     class_table[ getRandom( sizeof(class_table)/sizeof(Class) ) ],
                     resource_data->type(),
                     getRandom( 60 ) );
        rrset.add( resource_data );

        return rrset;
    }
}
