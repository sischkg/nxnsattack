#include "dns.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <boost/log/trivial.hpp>

class RRTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( RRTest, OutputRecordA )
{
    dns::ResourceRecord rr;
    rr.mDomainname = "example.com";
    rr.mType = dns::TYPE_A;
    rr.mClass = dns::CLASS_IN;
    rr.mTTL = 0x01020304;
    rr.mRData = dns::RDATAPtr( new dns::RecordA( "127.0.0.1" ) );

    dns::OffsetDB offset;
    WireFormat message;
    
    dns::generateResourceRecord( rr, message, offset );

    EXPECT_EQ(  27, message.size() );

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

    EXPECT_EQ(   0, message[13] );  // TYPE_A
    EXPECT_EQ(   1, message[14] );

    EXPECT_EQ(   0, message[15] );  // CLASS_IN
    EXPECT_EQ(   1, message[16] );

    EXPECT_EQ( 0x01, message[17] );  // TTL = 0x01020304
    EXPECT_EQ( 0x02, message[18] );
    EXPECT_EQ( 0x03, message[19] );
    EXPECT_EQ( 0x04, message[20] );

    EXPECT_EQ(   0, message[21] );  // RDATA Length = 4
    EXPECT_EQ(   4, message[22] );    
    
    EXPECT_EQ(  127, message[23] );  // 127.0.0.1
    EXPECT_EQ(    0, message[24] );
    EXPECT_EQ(    0, message[25] );
    EXPECT_EQ(    1, message[26] );
}

TEST_F( RRTest, OutputRecordNS )
{
    dns::ResourceRecord rr;
    rr.mDomainname = "example.com";
    rr.mType = dns::TYPE_NS;
    rr.mClass = dns::CLASS_IN;
    rr.mTTL = 0x01020304;
    rr.mRData = dns::RDATAPtr( new dns::RecordNS( "ns.example.com" ) );

    dns::OffsetDB offset;
    WireFormat message;
    
    dns::generateResourceRecord( rr, message, offset );

    EXPECT_EQ(  28, message.size() );

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

    EXPECT_EQ(   0, message[13] );  // TYPE_NS
    EXPECT_EQ(   2, message[14] );

    EXPECT_EQ(   0, message[15] );  // CLASS_IN
    EXPECT_EQ(   1, message[16] );

    EXPECT_EQ( 0x01, message[17] );  // TTL = 0x01020304
    EXPECT_EQ( 0x02, message[18] );
    EXPECT_EQ( 0x03, message[19] );
    EXPECT_EQ( 0x04, message[20] );

    EXPECT_EQ(   0, message[21] );  // RDATA Length = 5
    EXPECT_EQ(   5, message[22] );    
    
    EXPECT_EQ(    2, message[23] );  // ns.
    EXPECT_EQ(  'n', message[24] );
    EXPECT_EQ(  's', message[25] );
    EXPECT_EQ( 0xc0, message[26] );
    EXPECT_EQ(    0, message[27] );
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
