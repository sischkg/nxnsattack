#include "rrgenerator.hpp"
#include <boost/noncopyable.hpp>
#include <sys/types.h>
#include <unistd.h>
#include <cstdlib>
#include <sstream>

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

    std::vector<uint8_t> RandomGenerator::randSizeStream( unsigned int max_size )
    {
        unsigned int size = rand( max_size );
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
	if ( getRandom( 32 ) == 0 )
	    return "*";
        unsigned int label_size = 1 + getRandom( 62 );
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
        return names[index];
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
            hint_name = hint.getAdditionalInfomationSection()[index - qdcount - ancount - nscount].r_domainname;
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
     * RAWGenarator
     **********************************************************/
    std::shared_ptr<RDATA> RawGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<RDATA> RawGenerator::generate()
    {
        uint16_t size = getRandom( 0xffff );
        std::vector<uint8_t> data;
        for ( uint16_t i = 0 ; i < size ; i++ )
            data.push_back( getRandom( 0xff ) );
        return std::shared_ptr<RDATA>( new RecordRaw( getRandom( 0xff ), data ) );
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

        unsigned int index = getRandom( record_a_list.size() );
	return std::shared_ptr<RDATA>( record_a_list[index]->clone() );
    }

    std::shared_ptr<RDATA> AGenerator::generate()
    {
        return std::shared_ptr<RDATA>( new RecordA( getRandom() ) );
    }


    /**********************************************************
     * WKSGenarator
     **********************************************************/
    std::shared_ptr<RDATA> WKSGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<RDATA> WKSGenerator::generate()
    {
        std::vector<Type> bitmap;
        if ( getRandom( 32 ) == 0 )
            bitmap.resize( 0 );
        else if ( getRandom( 32 ) == 0 ) {
            bitmap.resize( 256 * 256 );
            for ( unsigned int i = 0 ; i < bitmap.size() ; i++ )
                bitmap[i] = i;
        }
        else {
            bitmap.resize( getRandom( 256 * 256 ) );
            for ( unsigned int i = 0 ; i < bitmap.size() ; i++ )
                bitmap[i] = getRandom( 256 * 256 );
        }
            
        return std::shared_ptr<RDATA>( new RecordWKS( getRandom(), getRandom( 256 ), bitmap ) );
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

        unsigned int index = getRandom( record_a_list.size() );
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
        std::vector<uint8_t> signature = getRandomSizeStream( 256 );

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
        std::vector<uint8_t> signature = getRandomSizeStream( 256 );
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
     * NSEC3Genarator
     **********************************************************/
    std::shared_ptr<RDATA> NSEC3Generator::generate( const PacketInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<RDATA> NSEC3Generator::generate()
    {
        uint8_t optout = 0x07;
        if ( getRandom( 8 ) ) {
            optout = 0;
        }
        std::vector<Type> types;
        unsigned int type_count = getRandom( 0xffff );
        for ( unsigned int i = 0 ; i < type_count ; i++ ) {
            types.push_back( getRandom( 0xffff ) );
        }

        return std::shared_ptr<RDATA>( new RecordNSEC3( 0x01,
                                                        optout,
                                                        getRandom( 0x00ff ),
                                                        getRandomSizeStream( 0xff ),
                                                        getRandomStream( 20 ),
                                                        types ) );
    }


    /**********************************************************
     * NSEC3PARAMGenarator
     **********************************************************/
    std::shared_ptr<RDATA> NSEC3PARAMGenerator::generate( const PacketInfo &hint )
    {
        return generate();
    }

    std::shared_ptr<RDATA> NSEC3PARAMGenerator::generate()
    {
        uint8_t optout = 0x07;
        if ( getRandom( 8 ) ) {
            optout = 0;
        }

        return std::shared_ptr<RDATA>( new RecordNSEC3PARAM( 0x01,
                                                             optout,
                                                             getRandom( 0x00ff ),
                                                             getRandomSizeStream( 0xff ) ) );
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
        std::vector<uint8_t> signature = getRandomSizeStream( 256 );
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
     * TKEYGenarator
     **********************************************************/
    std::shared_ptr<RDATA> TKEYGenerator::generate( const PacketInfo &hint )
    {
	std::string algo = "HMAC-MD5.SIG-ALG.REG.INT";
	if ( getRandom( 1 ) ) {
	    algo = generateDomainname().toString();
	}

	std::vector<uint8_t> signature = getRandomStream( 16 );

	std::shared_ptr<RDATA> p( new RecordTKEY( generateDomainname( getDomainname( hint ) ).toString(), // domain
						  algo,                                                   // algorithm
						  getRandom(),         // inception
						  getRandom(),         // expiration
						  0,
						  0,
						  signature ) );
        return p;
    }

    std::shared_ptr<RDATA> TKEYGenerator::generate()
    {
	std::string algo = "HMAC-MD5.SIG-ALG.REG.INT";
	if ( getRandom( 1 ) ) {
	    algo = generateDomainname().toString();
	}

	std::vector<uint8_t> signature = getRandomStream( 16 );

	std::shared_ptr<RDATA> p( new RecordTKEY( generateDomainname().toString(), // domain
						  algo,                            // algorithm
						  getRandom(),         // inception
						  getRandom(),         // expiration
						  0,
						  0,
						  signature ) );
        return p;
    }

    /**********************************************************
     * TSIGGenarator
     **********************************************************/
    std::shared_ptr<RDATA> TSIGGenerator::generate( const PacketInfo &hint )
    {
	std::string algo = "HMAC-MD5.SIG-ALG.REG.INT";
	if ( getRandom( 1 ) ) {
	    algo = generateDomainname().toString();
	}
	
	std::vector<uint8_t> signature = getRandomStream( 16 );
	uint64_t signed_time = (uint64_t)getRandom() + (((uint64_t)getRandom() ) << 32 );

	std::vector<uint8_t> other = getRandomStream( getRandom( 0xff00 ) );

	return std::shared_ptr<RDATA>( new RecordTSIGData( generateDomainname( getDomainname( hint ) ).toString(), // domain
                                                           algo,                                                   // algorithm
                                                           signed_time,              // signed time
                                                           getRandom( 0xffff ),      // fudge
                                                           signature,                // mac
                                                           getRandom( 0xffff ),      // original id
                                                           getRandom( 0xffff ),      // error
                                                           other ) );
    }

    std::shared_ptr<RDATA> TSIGGenerator::generate()
    {
	std::string algo = "HMAC-MD5.SIG-ALG.REG.INT";
	if ( getRandom( 1 ) ) {
	    algo = generateDomainname().toString();
	}
	
	std::vector<uint8_t> signature = getRandomStream( 16 );
	uint64_t signed_time = (uint64_t)getRandom() + (((uint64_t)getRandom() ) << 32 );

	std::vector<uint8_t> other = getRandomStream( getRandom( 0xff00 ) );

	return std::shared_ptr<RDATA>( new RecordTSIGData( generateDomainname().toString(), // domain
                                                           algo,                            // algorithm
                                                           signed_time,              // signed time
                                                           getRandom( 0xffff ),      // fudge
                                                           signature,                // mac
                                                           getRandom( 0xffff ),      // original id
                                                           getRandom( 0xffff ),      // error
                                                           other ) );
    }


    /**********************************************************
     * ResourceRecordGenarator
     **********************************************************/
    ResourceRecordGenerator::ResourceRecordGenerator()
    {
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new RawGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new CNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNAMEGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new AAAAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new WKSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SOAGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new RRSIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DNSKEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new DSGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSECGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSEC3Generator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NSEC3PARAMGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new SIGGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new KEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new NXTGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new TKEYGenerator ) );
        mGenerators.push_back( std::shared_ptr<RDATAGeneratable>( new TSIGGenerator ) );
    }


    RRSet ResourceRecordGenerator::generate( const PacketInfo &hint )
    {
        Class class_table[] = { CLASS_IN, CLASS_CH, CLASS_HS, CLASS_NONE, CLASS_ANY };

        std::shared_ptr<RDATA> resource_data = mGenerators[ getRandom( mGenerators.size() )]->generate( hint );

        Domainname owner;
        if ( resource_data->type() == TYPE_NSEC3 ) {
            std::string hash;
            encodeToBase32Hex( getRandomStream( 20 ), hash ); 
            owner = getDomainname( hint );
            owner.addSubdomain( hash );
        }
        else {
            owner = getDomainname( hint );
        }

        RRSet rrset( owner,
                     class_table[ getRandom( sizeof(class_table)/sizeof(Class) ) ],
                     resource_data->type(),
                     getRandom( 60 ) );
        rrset.add( resource_data );

        return rrset;
    }

    std::shared_ptr<OptPseudoRROption> RawOptionGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<OptPseudoRROption> RawOptionGenerator::generate()
    {
	ssize_t length = getRandom( 0xffff );
	std::vector<uint8_t> data;
	for ( ssize_t i = 0 ; i < length ; i++ )
	    data.push_back( getRandom( 0xff ) );
	return std::shared_ptr<OptPseudoRROption>( new RAWOption( getRandom( 0x0f ), data ) );
    }

    std::shared_ptr<OptPseudoRROption> NSIDGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<OptPseudoRROption> NSIDGenerator::generate()
    {
	ssize_t length = getRandom( 0xff00 );
	std::string id;
	for ( ssize_t i = 0 ; i < length ; i++ )
	    id.push_back( getRandom( 0xff ) );
	return std::shared_ptr<OptPseudoRROption>( new NSIDOption( id ) );
    }

    std::shared_ptr<OptPseudoRROption> ClientSubnetGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<OptPseudoRROption> ClientSubnetGenerator::generate()
    {
	if ( getRandom( 2 ) ) {
	    std::ostringstream os;
	    os << getRandom( 0xff ) << "." << getRandom( 0xff ) << "." << getRandom( 0xff ) << getRandom( 0xff );
	    return std::shared_ptr<OptPseudoRROption>( new ClientSubnetOption( ClientSubnetOption::IPv4,
									       getRandom( 32 ),
									       getRandom( 32 ),
									       os.str() ) );
	}
	else {
	    std::ostringstream os;
	    os << std::hex << getRandom( 0xff );
	    for ( int i = 0 ; i < 15 ; i++ )
		os << ":" << getRandom( 0xff );
	    return std::shared_ptr<OptPseudoRROption>( new ClientSubnetOption( ClientSubnetOption::IPv6,
									       getRandom( 128 ),
									       getRandom( 128 ),
									       os.str() ) );
	}
    }


    std::shared_ptr<OptPseudoRROption> CookieGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<OptPseudoRROption> CookieGenerator::generate()
    {
        std::vector<uint8_t> client, server;
        unsigned int client_length = getRandom( 64 );
        unsigned int server_length = getRandom( 64 );
        
        for ( unsigned int i = 0 ; i < client_length ; i++ )
            client.push_back( getRandom( 0xff ) );
        for ( unsigned int i = 0 ; i < server_length ; i++ )
            server.push_back( getRandom( 0xff ) );

        return std::shared_ptr<OptPseudoRROption>( new CookieOption( client, server ) );
    }


    std::shared_ptr<OptPseudoRROption> TCPKeepaliveGenerator::generate( const PacketInfo &hint )
    {
	return generate();
    }

    std::shared_ptr<OptPseudoRROption> TCPKeepaliveGenerator::generate()
    {
        uint16_t timeout = 0;
        if ( getRandom( 4 ) ) {
            timeout = getRandom( 0xffff );
        }
        return std::shared_ptr<OptPseudoRROption>( new TCPKeepaliveOption( timeout ) );
    }

    /**********************************************************
     * OptionGenarator
     **********************************************************/
    OptionGenerator::OptionGenerator()
    {
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new RawOptionGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new NSIDGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new ClientSubnetGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new CookieGenerator ) );
        mGenerators.push_back( std::shared_ptr<OptGeneratable>( new TCPKeepaliveGenerator ) );
    }


    void OptionGenerator::generate( PacketInfo &packet )
    {
	if ( ! packet.isEDNS0() )
	    return;

        std::shared_ptr<OptPseudoRROption> option = mGenerators[ getRandom( mGenerators.size() )]->generate( packet );
	std::dynamic_pointer_cast<RecordOptionsData>( packet.opt_pseudo_rr.mOptions )->add( option );
    }

}

