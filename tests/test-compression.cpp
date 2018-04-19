#include "dns.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class OffsetDBTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( OffsetDBTest, OneDomain )
{
    dns::Domainname example( "example.com" );
    WireFormat message;

    dns::OffsetDB db;
    db.outputWireFormat( example, message );

    EXPECT_EQ(  13, message.size() ); //  sizeof "example.com" == 1 + 7 + 1 + 3 + 1

    EXPECT_EQ(   7, message[0] );
    EXPECT_EQ( 'e', message[1] );
    EXPECT_EQ( 'x', message[2] );
    EXPECT_EQ( 'a', message[3] );
    EXPECT_EQ( 'm', message[4] );
    EXPECT_EQ( 'p', message[5] );
    EXPECT_EQ( 'l', message[6] );
    EXPECT_EQ( 'e', message[7] );

    EXPECT_EQ(   3, message[8] );
    EXPECT_EQ( 'c', message[9] );
    EXPECT_EQ( 'o', message[10] );
    EXPECT_EQ( 'm', message[11] );

    EXPECT_EQ(   0, message[12] );
}

TEST_F( OffsetDBTest, CompressTwoDomain )
{
    dns::Domainname example( "example.com" );
    WireFormat message;

    dns::OffsetDB db;
    db.outputWireFormat( example, message );
    db.outputWireFormat( example, message );

    EXPECT_EQ(  15, message.size() ); //  sizeof "example.com" == 1 + 7 + 1 + 3 + 1 + 2

    EXPECT_EQ(   7, message[0] );
    EXPECT_EQ( 'e', message[1] );
    EXPECT_EQ( 'x', message[2] );
    EXPECT_EQ( 'a', message[3] );
    EXPECT_EQ( 'm', message[4] );
    EXPECT_EQ( 'p', message[5] );
    EXPECT_EQ( 'l', message[6] );
    EXPECT_EQ( 'e', message[7] );

    EXPECT_EQ(   3, message[8] );
    EXPECT_EQ( 'c', message[9] );
    EXPECT_EQ( 'o', message[10] );
    EXPECT_EQ( 'm', message[11] );

    EXPECT_EQ(   0, message[12] );

    EXPECT_EQ( 0xC0, message[13] );
    EXPECT_EQ( 0x00, message[14] );
}

TEST_F( OffsetDBTest, CompressParentDomain )
{
    dns::Domainname example( "example.com" );
    dns::Domainname test( "test.com" );
    WireFormat message;

    dns::OffsetDB db;
    db.outputWireFormat( example, message );
    db.outputWireFormat( test, message );

    EXPECT_EQ(  20, message.size() ); //   sizeof "example.com" == 1 + 7 + 1 + 3 + 1  = 13
                                      // + sizeof "test"        == 1 + 4              =  5
                                      // + sizeof offset        == 2                  =  2

    EXPECT_EQ(   7, message[0] );
    EXPECT_EQ( 'e', message[1] );
    EXPECT_EQ( 'x', message[2] );
    EXPECT_EQ( 'a', message[3] );
    EXPECT_EQ( 'm', message[4] );
    EXPECT_EQ( 'p', message[5] );
    EXPECT_EQ( 'l', message[6] );
    EXPECT_EQ( 'e', message[7] );

    EXPECT_EQ(   3, message[8] );
    EXPECT_EQ( 'c', message[9] );
    EXPECT_EQ( 'o', message[10] );
    EXPECT_EQ( 'm', message[11] );

    EXPECT_EQ(   0, message[12] );

    EXPECT_EQ(   4, message[13] );
    EXPECT_EQ( 't', message[14] );
    EXPECT_EQ( 'e', message[15] );
    EXPECT_EQ( 's', message[16] );
    EXPECT_EQ( 't', message[17] );

    EXPECT_EQ( 0xC0, message[18] );
    EXPECT_EQ( 0x08, message[19] );
}

TEST_F( OffsetDBTest, NoCompress )
{
    dns::Domainname example( "example.com" );
    dns::Domainname test( "test.net" );
    WireFormat message;

    dns::OffsetDB db;
    db.outputWireFormat( example, message );
    db.outputWireFormat( test, message );

    EXPECT_EQ(  23, message.size() ); //   sizeof "example.com" == 1 + 7 + 1 + 3 + 1  = 13
                                      // + sizeof "test.net"    == 1 + 4 + 1 + 3 + 1  = 10

    EXPECT_EQ(   7, message[0] );
    EXPECT_EQ( 'e', message[1] );
    EXPECT_EQ( 'x', message[2] );
    EXPECT_EQ( 'a', message[3] );
    EXPECT_EQ( 'm', message[4] );
    EXPECT_EQ( 'p', message[5] );
    EXPECT_EQ( 'l', message[6] );
    EXPECT_EQ( 'e', message[7] );

    EXPECT_EQ(   3, message[8] );
    EXPECT_EQ( 'c', message[9] );
    EXPECT_EQ( 'o', message[10] );
    EXPECT_EQ( 'm', message[11] );

    EXPECT_EQ(   0, message[12] );

    EXPECT_EQ(   4, message[13] );
    EXPECT_EQ( 't', message[14] );
    EXPECT_EQ( 'e', message[15] );
    EXPECT_EQ( 's', message[16] );
    EXPECT_EQ( 't', message[17] );

    EXPECT_EQ(   3, message[18] );
    EXPECT_EQ( 'n', message[19] );
    EXPECT_EQ( 'e', message[20] );
    EXPECT_EQ( 't', message[21] );

    EXPECT_EQ(   0, message[22] );
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
