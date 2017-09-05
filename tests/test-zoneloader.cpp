#include "dns.hpp"
#include "zoneloader.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class TimestampTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};


TEST_F( TimestampTest, timestamp_to_epoch )
{
    //
    // $ date +%s --date="2017/07/01 02:30:40 UTC"
    // 1498876240
    // 
    EXPECT_EQ( 1498876240, dns::timestamp_to_epoch( "20170701023040" ) );
}

class ParseTxtTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};


TEST_F( ParseTxtTest, parse_character_string )
{
    const char *TXT = "\"text\"";
    std::vector<std::string> txt = dns::parse_txt( TXT );
    EXPECT_EQ( 1, txt.size() );
    EXPECT_STREQ( "text", txt[0].c_str() );
}

TEST_F( ParseTxtTest, parse_character_strings )
{
    const char *TXT = "\"text-1\" \"text-2\"";
    std::vector<std::string> txt = dns::parse_txt( TXT );
    EXPECT_EQ( 2, txt.size() );
    EXPECT_STREQ( "text-1", txt[0].c_str() );
    EXPECT_STREQ( "text-2", txt[1].c_str() );
}

class ZoneLoaderTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

const char *ZONE_CONFIG_YAML_SOA =
    "- owner: example.com\n"
    "  type:  SOA\n"
    "  ttl:   3600\n"
    "  record:\n"
    "  - mname:   ns01.example.com\n"
    "    rname:   hostmaster.example.com\n"
    "    serial:  2017050101\n"
    "    refresh: 3600\n"
    "    retry:   1800\n"
    "    expire:  8640000\n"
    "    minimum: 300\n";


TEST_F( ZoneLoaderTest, Load_SOA )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::yamlloader::load( zone, "example.com", ZONE_CONFIG_YAML_SOA );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone" + std::string( ZONE_CONFIG_YAML_SOA );
 
    auto node = zone.findNode( "example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "zone apex is loaded";

    auto rrset = node->find( dns::TYPE_SOA );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "soa record is loaded";
    EXPECT_EQ( rrset->count(), 1 ) << "one soa record is loaded";
    
    std::shared_ptr<const dns::RecordSOA> soa;
    ASSERT_NO_THROW( {
	    soa = std::dynamic_pointer_cast<const dns::RecordSOA>( (*rrset)[0] );
	} );
    EXPECT_STREQ( "ns01.example.com.", soa->getMName().c_str() );
    EXPECT_STREQ( "hostmaster.example.com.", soa->getRName().c_str() );
    EXPECT_EQ( 2017050101, soa->getSerial() );
    EXPECT_EQ( 3600,       soa->getRefresh() );
    EXPECT_EQ( 1800,       soa->getRetry() );
    EXPECT_EQ( 8640000,    soa->getExpire() );
    EXPECT_EQ( 300,        soa->getMinimum() );
}


const char *ZONE_CONFIG_YAML_A =
    "- owner: example.com\n"
    "  type:  SOA\n"
    "  ttl:   3600\n"
    "  record:\n"
    "  - mname:   ns01.example.com\n"
    "    rname:   hostmaster.example.com\n"
    "    serial:  2017050101\n"
    "    refresh: 3600\n"
    "    retry:   1800\n"
    "    expire:  8640000\n"
    "    minimum: 3600\n"
    "- owner: www.example.com\n"
    "  type:  A\n"
    "  ttl:   300\n"
    "  record:\n"
    "  - address: 192.168.0.1\n"
    "  - address: 192.168.0.2\n";

TEST_F( ZoneLoaderTest, Load_A )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::yamlloader::load( zone, "example.com", ZONE_CONFIG_YAML_A );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone:" + std::string( ZONE_CONFIG_YAML_A );

    auto node = zone.findNode( "www.example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "www.example.com is loaded from YAML";

    auto rrset = node->find( dns::TYPE_A );
    ASSERT_FALSE( rrset.get() == nullptr ) <<  "A records are loaded from YAML";
    ASSERT_EQ( 2, rrset->count() ) <<  "2 A records are loaded from YAML";
    
    std::shared_ptr<const dns::RecordA> a;
    ASSERT_NO_THROW( {
	    a = std::dynamic_pointer_cast<const dns::RecordA>( (*rrset)[0] );
	} );
    EXPECT_EQ( "192.168.0.1", a->getAddress() );
    ASSERT_NO_THROW( {
	    a = std::dynamic_pointer_cast<const dns::RecordA>( (*rrset)[1] );
	} );
    EXPECT_EQ( "192.168.0.2", a->getAddress() );
}


const char *ZONE_CONFIG_YAML_NS =
                                              "- owner: example.com\n"
                                              "  type:  SOA\n"
                                              "  ttl:   3600\n"
                                              "  record:\n"
                                              "  - mname:   ns01.example.com\n"
                                              "    rname:   hostmaster.example.com\n"
                                              "    serial:  2017050101\n"
                                              "    refresh: 3600\n"
                                              "    retry:   1800\n"
                                              "    expire:  8640000\n"
                                              "    minimum: 3600\n"
                                              "- owner: example.com\n"
                                              "  type:  NS\n"
                                              "  ttl:   300\n"
                                              "  record:\n"
                                              "  - nameserver: ns01.example.com\n"
                                              "  - nameserver: ns02.example.com\n";

TEST_F( ZoneLoaderTest, Load_NS )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::yamlloader::load( zone, "example.com", ZONE_CONFIG_YAML_NS );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone:" + std::string( ZONE_CONFIG_YAML_NS );

    auto node = zone.findNode( "example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "example.com is loaded";

    auto rrset = node->find( dns::TYPE_NS );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "a record is loaded";

    ASSERT_EQ( 2, rrset->count() ) << "2 NS records";
    std::shared_ptr<const dns::RecordNS> ns01;
    ASSERT_NO_THROW( {
	    ns01 = std::dynamic_pointer_cast<const dns::RecordNS>( (*rrset)[0] );
	} );
    EXPECT_STREQ( "ns01.example.com.", ns01->getNameServer().toString().c_str() );
    std::shared_ptr<const dns::RecordNS> ns02;
    ASSERT_NO_THROW( {
	    ns02 = std::dynamic_pointer_cast<const dns::RecordNS>( (*rrset)[1] );
	} );
    EXPECT_STREQ( "ns02.example.com.", ns02->getNameServer().toString().c_str() );
}


TEST_F( ZoneLoaderTest, Load_Full_SOA )
{
    const char *ZONE_CONFIG_FULL_SOA =  "example.com.  3600 IN SOA ns01.example.com. hostmaster.example.com. 2017050101 3600 1800 8640000 300";

    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::full::load( zone, "example.com", ZONE_CONFIG_FULL_SOA );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone" + std::string( ZONE_CONFIG_FULL_SOA );
 
    auto node = zone.findNode( "example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "zone apex is loaded";

    auto rrset = node->find( dns::TYPE_SOA );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "soa record is loaded";
    EXPECT_EQ( rrset->count(), 1 ) << "one soa record is loaded";
    
    std::shared_ptr<const dns::RecordSOA> soa;
    ASSERT_NO_THROW( {
	    soa = std::dynamic_pointer_cast<const dns::RecordSOA>( (*rrset)[0] );
	} );
    EXPECT_STREQ( "ns01.example.com.", soa->getMName().c_str() );
    EXPECT_STREQ( "hostmaster.example.com.", soa->getRName().c_str() );
    EXPECT_EQ( 2017050101, soa->getSerial() );
    EXPECT_EQ( 3600,       soa->getRefresh() );
    EXPECT_EQ( 1800,       soa->getRetry() );
    EXPECT_EQ( 8640000,    soa->getExpire() );
    EXPECT_EQ( 300,        soa->getMinimum() );
}

TEST_F( ZoneLoaderTest, Load_Full_SOA2 )
{
    const char *ZONE_CONFIG_FULL_SOA =  "siskrn.co.				      3600 IN SOA	siskrn.co. hostmaster.siskrn.co. 1500338838 86400 3600 604800 10800";

    dns::Zone zone( "siskrn.co" );
    ASSERT_NO_THROW( {
            try {
                dns::full::load( zone, "siskrn.co", ZONE_CONFIG_FULL_SOA );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone" + std::string( ZONE_CONFIG_FULL_SOA );
 
    auto node = zone.findNode( "siskrn.co" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "zone apex is loaded";

    auto rrset = node->find( dns::TYPE_SOA );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "soa record is loaded";
    EXPECT_EQ( rrset->count(), 1 ) << "one soa record is loaded";
    
    std::shared_ptr<const dns::RecordSOA> soa;
    ASSERT_NO_THROW( {
	    soa = std::dynamic_pointer_cast<const dns::RecordSOA>( (*rrset)[0] );
	} );
    EXPECT_STREQ( "siskrn.co.", soa->getMName().c_str() );
    EXPECT_STREQ( "hostmaster.siskrn.co.", soa->getRName().c_str() );
    EXPECT_EQ( 1500338838, soa->getSerial() );
    EXPECT_EQ( 86400,      soa->getRefresh() );
    EXPECT_EQ( 3600,       soa->getRetry() );
    EXPECT_EQ( 604800,     soa->getExpire() );
    EXPECT_EQ( 10800,      soa->getMinimum() );
}


const char *ZONE_CONFIG_FULL_A = \
    "www.example.com.  3600 IN A  192.168.0.101\n"
    "www.example.com.  3600 IN A  192.168.0.102\n";

TEST_F( ZoneLoaderTest, Load_Full_A )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::full::load( zone, "example.com", ZONE_CONFIG_FULL_A );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone:" + std::string( ZONE_CONFIG_FULL_A );

    auto node = zone.findNode( "www.example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "www.example.com is loaded from FULL";

    auto rrset = node->find( dns::TYPE_A );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "a records are loaded from FULL";
    EXPECT_EQ( 2, rrset->count() ) << "2 A records are loaded from FULL";
 
    std::shared_ptr<const dns::RecordA> a;
    ASSERT_NO_THROW( {
	    a = std::dynamic_pointer_cast<const dns::RecordA>( (*rrset)[0] );
	} );
    EXPECT_EQ( "192.168.0.101", a->getAddress() );

    ASSERT_NO_THROW( {
	    a = std::dynamic_pointer_cast<const dns::RecordA>( (*rrset)[1] );
	} );
    EXPECT_EQ( "192.168.0.102", a->getAddress() );
}


const char *ZONE_CONFIG_FULL_NSEC = "ns01.example.com. 3600 IN NSEC  ns02.example.com. A RRSIG NSEC";

TEST_F( ZoneLoaderTest, Load_Full_NSEC )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::full::load( zone, "example.com", ZONE_CONFIG_FULL_NSEC );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone:" + std::string( ZONE_CONFIG_FULL_NSEC );

    auto node = zone.findNode( "ns01.example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "ns01.example.com is loaded from FULL";

    auto rrset = node->find( dns::TYPE_NSEC );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "NSEC records are loaded from FULL";
    EXPECT_EQ( 1, rrset->count() ) << "NSEC records is loaded from FULL";
 
    std::shared_ptr<const dns::RecordNSEC> nsec;
    ASSERT_NO_THROW( {
	    nsec = std::dynamic_pointer_cast<const dns::RecordNSEC>( (*rrset)[0] );
	} );
    EXPECT_EQ( "ns02.example.com", nsec->getNextDomainname() );
    ASSERT_EQ( 3,               nsec->getTypes().size() );
    EXPECT_EQ( dns::TYPE_A,     nsec->getTypes()[0] );
    EXPECT_EQ( dns::TYPE_RRSIG, nsec->getTypes()[1] );
    EXPECT_EQ( dns::TYPE_NSEC,  nsec->getTypes()[2] );
}

const char *ZONE_CONFIG_FULL_TXT =  "example.com.  3600 IN TXT \"text-1\" \"text-2\"";


TEST_F( ZoneLoaderTest, Load_Full_TXT )
{
    dns::Zone zone( "example.com" );
    ASSERT_NO_THROW( {
            try {
                dns::full::load( zone, "example.com", ZONE_CONFIG_FULL_TXT );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone" + std::string( ZONE_CONFIG_FULL_TXT );
 
    auto node = zone.findNode( "example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "zone apex is loaded";

    auto rrset = node->find( dns::TYPE_TXT );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "txt record is loaded";
    EXPECT_EQ( rrset->count(), 1 ) << "one txt record is loaded";
    
    std::shared_ptr<const dns::RecordTXT> txt;
    ASSERT_NO_THROW( {
	    txt = std::dynamic_pointer_cast<const dns::RecordTXT>( (*rrset)[0] );
	} );
    ASSERT_EQ( 2, txt->getTexts().size() );
    EXPECT_STREQ( "text-1", txt->getTexts()[0].c_str() );
    EXPECT_STREQ( "text-2", txt->getTexts()[1].c_str() );
}


TEST_F( ZoneLoaderTest, dump )
{
    dns::Zone zone( "example.com" );

    dns::Node::RRSetPtr rrset_soa( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_SOA, 3600 ) );
    rrset_soa->add( dns::RDATAPtr( new dns::RecordSOA( "ns01.example.com",
                                                       "hostmaster.example.com",
                                                       1,
                                                       86400,
                                                       3600,
                                                       16800,
                                                       300 ) ) );

    dns::Node::RRSetPtr rrset_a( new dns::RRSet( "www.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    rrset_a->add( dns::RDATAPtr( new dns::RecordA( "192.168.0.1" ) ) );
    rrset_a->add( dns::RDATAPtr( new dns::RecordA( "192.168.0.2" ) ) );

    dns::Node::RRSetPtr rrset_ns( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_NS, 86400 ) );
    rrset_ns->add( dns::RDATAPtr( new dns::RecordNS( "ns01.example.com" ) ) );
    rrset_ns->add( dns::RDATAPtr( new dns::RecordNS( "ns02.example.com" ) ) );

    dns::Node::RRSetPtr rrset_ns01( new dns::RRSet( "ns01.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    rrset_ns01->add( dns::RDATAPtr( new dns::RecordA( "192.168.0.101" ) ) );
    dns::Node::RRSetPtr rrset_ns02( new dns::RRSet( "ns02.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    rrset_ns02->add( dns::RDATAPtr( new dns::RecordA( "192.168.0.102" ) ) );

    zone.add( rrset_soa );
    zone.add( rrset_a );
    zone.add( rrset_ns );
    zone.add( rrset_ns01 );
    zone.add( rrset_ns02 );

    std::string zonefile = dns::full::dump( zone );

    EXPECT_FALSE( zonefile.find( "example.com.\t3600\tIN\tSOA\tns01.example.com. hostmaster.example.com. 1 86400 3600 16800 300" ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "www.example.com.\t3600\tIN\tA\t192.168.0.1" ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "www.example.com.\t3600\tIN\tA\t192.168.0.2" ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "example.com.\t86400\tIN\tNS\tns01.example.com." ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "example.com.\t86400\tIN\tNS\tns02.example.com." ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "ns01.example.com.\t3600\tIN\tA\t192.168.0.101" ) == std::string::npos );
    EXPECT_FALSE( zonefile.find( "ns02.example.com.\t3600\tIN\tA\t192.168.0.102" ) == std::string::npos );
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
