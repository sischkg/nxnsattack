#include "zone.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>


class RRSetTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( RRSetTest, AddRRData )
{
    dns::RRSet rrset( "www.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 );

    EXPECT_NO_THROW( { rrset.add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.1" ) ) ); } );
    EXPECT_NO_THROW( { rrset.add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.2" ) ) ); } );
    EXPECT_EQ( 2, rrset.count() );
    auto a = rrset.begin();
    EXPECT_STREQ( "192.168.0.1", (*a)->toString().c_str() );
    a++;
    EXPECT_STREQ( "192.168.0.2", (*a)->toString().c_str() );
}


class NodeTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( NodeTest, AddSet )
{
    dns::Node::RRSetPtr rrset_a( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    EXPECT_NO_THROW( { rrset_a->add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.1" ) ) ); } );
    EXPECT_NO_THROW( { rrset_a->add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.2" ) ) ); } );

    dns::Node::RRSetPtr rrset_ns( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_NS, 86400 ) );
    EXPECT_NO_THROW( { rrset_ns->add( dns::ResourceDataPtr( new dns::RecordNS( "ns01.example.com" ) ) ); } );
    EXPECT_NO_THROW( { rrset_ns->add( dns::ResourceDataPtr( new dns::RecordNS( "ns02.example.com" ) ) ); } );

    dns::Node node;
    EXPECT_NO_THROW( { node.add( rrset_ns ); } );
    EXPECT_NO_THROW( { node.add( rrset_a ); } );

    auto found_rrset_a = node.find( dns::TYPE_A );
    EXPECT_EQ( dns::TYPE_A, found_rrset_a->getType() );
    EXPECT_EQ( 3600, found_rrset_a->getTTL() );

    auto found_rrset_ns = node.find( dns::TYPE_NS );
    EXPECT_EQ( dns::TYPE_NS, found_rrset_ns->getType() );
    EXPECT_EQ( 86400, found_rrset_ns->getTTL() );

}


class ZoneTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( ZoneTest, AddSet )
{
    dns::Zone zone( "example.com" );

    dns::Node::RRSetPtr rrset_soa( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_SOA, 3600 ) );
    EXPECT_NO_THROW( { rrset_soa->add( dns::ResourceDataPtr( new dns::RecordSOA( "ns01.example.com",
                                                                                 "hostmaster.example.com",
                                                                                 1,
                                                                                 86400,
                                                                                 3600,
                                                                                 16800,
                                                                                 300 ) ) ); } );

    dns::Node::RRSetPtr rrset_a( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );
    EXPECT_NO_THROW( { rrset_a->add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.1" ) ) ); } );
    EXPECT_NO_THROW( { rrset_a->add( dns::ResourceDataPtr( new dns::RecordA( "192.168.0.2" ) ) ); } );

    dns::Node::RRSetPtr rrset_ns( new dns::RRSet( "example.com", dns::CLASS_IN, dns::TYPE_NS, 86400 ) );
    EXPECT_NO_THROW( { rrset_ns->add( dns::ResourceDataPtr( new dns::RecordNS( "ns01.example.com" ) ) ); } );
    EXPECT_NO_THROW( { rrset_ns->add( dns::ResourceDataPtr( new dns::RecordNS( "ns02.example.com" ) ) ); } );

    dns::Node::RRSetPtr rrset_www( new dns::RRSet( "www.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 ) );

    EXPECT_NO_THROW( { zone.add( rrset_a ); } );
    EXPECT_NO_THROW( { zone.add( rrset_ns ); } );
    EXPECT_NO_THROW( { zone.add( rrset_www ); } );

}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
