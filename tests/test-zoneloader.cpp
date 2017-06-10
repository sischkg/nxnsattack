#include "dns.hpp"
#include "zoneloader.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

// The fixture for testing class Foo.
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
    std::shared_ptr<dns::Zone> zone;
    ASSERT_NO_THROW( {
            try {
                zone = dns::load( "example.com", ZONE_CONFIG_YAML_SOA );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone" + std::string( ZONE_CONFIG_YAML_SOA );
 
    auto node = zone->findNode( "example.com" );
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
    "  - address: 192.168.0.1\n";

TEST_F( ZoneLoaderTest, Load_A )
{
    std::shared_ptr<dns::Zone> zone;
    ASSERT_NO_THROW( {
            try {
                zone = dns::load( "example.com", ZONE_CONFIG_YAML_A );
            }
            catch ( std::runtime_error &e ) {
                std::cerr << e.what() << std::endl;
                throw;
            }
        } )
        << "can load zone:" + std::string( ZONE_CONFIG_YAML_A );
 
    auto node = zone->findNode( "www.example.com" );
    EXPECT_FALSE( node.get() == nullptr ) <<  "www.example.com is loaded";

    auto rrset = node->find( dns::TYPE_A );
    EXPECT_FALSE( rrset.get() == nullptr ) <<  "a record is loaded";

    std::shared_ptr<const dns::RecordA> a;
    ASSERT_NO_THROW( {
	    a = std::dynamic_pointer_cast<const dns::RecordA>( (*rrset)[0] );
	} );
    EXPECT_EQ( "192.168.0.1", a->getAddress() );
}



int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
