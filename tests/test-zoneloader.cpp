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
    "    minimum: 3600\n";


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

    auto soa = node->find( dns::TYPE_SOA );
    EXPECT_FALSE( soa.get() == nullptr ) <<  "soa record is loaded";
    
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

    auto a = node->find( dns::TYPE_A );
    EXPECT_FALSE( a.get() == nullptr ) <<  "a record is loaded";
    
}



int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
