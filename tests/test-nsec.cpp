#include "zone.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>


class WindowTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }

    uint32_t typeToIndex( dns::Type t )
    {
	t = 0xff & t;
	uint8_t index = 7 - ( t % 8 );
	return 1 << index;
    }
};

TEST_F( WindowTest, WriteFormatOnlyA )
{
    dns::NSECBitmapField::Window win( 0 );
    win.add( dns::TYPE_A );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 is 0;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( dns::TYPE_A ), (uint32_t)message[2] );
}

TEST_F( WindowTest, WriteFormatAandSOA )
{
    dns::NSECBitmapField::Window win( 0 );
    win.add( dns::TYPE_A );
    win.add( dns::TYPE_SOA );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 and TYPE_SOA = 0x0006 is 0;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( dns::TYPE_A ) | typeToIndex( dns::TYPE_SOA ), (uint32_t)message[2] );
}


TEST_F( WindowTest, WriteFormatOnlyType0x0201 )
{
    dns::NSECBitmapField::Window win( 2 );
    win.add( 0x0201 );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 2, message[0] ); // Index of Type_0x0201 is 2;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), (uint32_t)message[2] );
}

TEST_F( WindowTest, WriteFormatOnlyMX )
{
    dns::NSECBitmapField::Window win( 0 );
    win.add( dns::TYPE_MX );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0015 is 0;
    EXPECT_EQ( 2, message[1] ); // window size = 2
    EXPECT_EQ( 0, message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), (uint32_t)message[3] );
}

TEST_F( WindowTest, WriteFormatAandMX )
{
    dns::NSECBitmapField::Window win( 0 );
    win.add( dns::TYPE_A );
    win.add( dns::TYPE_MX );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 and TYPE_MX = 0x0015 is 0;
    EXPECT_EQ( 2, message[1] ); // window size = 2 (TYPE_MX_flag is 1 << 14 )
    EXPECT_EQ( typeToIndex( dns::TYPE_A  ), (uint32_t)message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), (uint32_t)message[3] );
}


class NSECBitmapFieldTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }

    uint8_t typeToIndex( dns::Type t )
    {
	t = 0xff & t;
	uint8_t index = 7 - ( t % 8 );
	return 1 << index;
    }
};

TEST_F( NSECBitmapFieldTest, WriteFormatOnlyA )
{
    dns::NSECBitmapField bitmaps;
    bitmaps.add( dns::TYPE_A );

    WireFormat message;
    bitmaps.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 is 0;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( dns::TYPE_A ), (uint32_t)message[2] );
}

TEST_F( NSECBitmapFieldTest, WriteFormatAandMX )
{
    dns::NSECBitmapField bitmaps;
    bitmaps.add( dns::TYPE_A );
    bitmaps.add( dns::TYPE_MX );

    WireFormat message;
    bitmaps.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 and TYPE_MX = 15 is 0;
    EXPECT_EQ( 2, message[1] ); // window size = 3
    EXPECT_EQ( typeToIndex( dns::TYPE_A ),  (uint32_t)message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), (uint32_t)message[3] );
}

TEST_F( NSECBitmapFieldTest, WriteFormatOnlyTYPE0201 )
{
    dns::NSECBitmapField bitmaps;
    bitmaps.add( 0x0201 );

    WireFormat message;
    bitmaps.outputWireFormat( message );

    EXPECT_EQ( 2, message[0] ); // Index of TYPE_0201 = 0x0201 is 2;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), (uint32_t)message[2] );
}


TEST_F( NSECBitmapFieldTest, WriteFormatMXandType0201 )
{
    dns::NSECBitmapField bitmaps;
    bitmaps.add( dns::TYPE_MX );
    bitmaps.add( 0x0201 );

    WireFormat message;
    bitmaps.outputWireFormat( message );

    EXPECT_EQ( 0, message[0] ); // Index of TYPE_A = 0x0001 is 0;
    EXPECT_EQ( 2, message[1] ); // window size = 3
    EXPECT_EQ( 0, message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), (uint32_t)message[3] );

    EXPECT_EQ( 2, message[4] ); // Index of TYPE_0201 = 0x0201 is 2;
    EXPECT_EQ( 1, message[5] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), (uint32_t)message[6] );
}

TEST_F( NSECBitmapFieldTest, WriteFormatRFC4034 )
{
   dns::NSECBitmapField bitmaps;
   bitmaps.add( dns::TYPE_A );
   bitmaps.add( dns::TYPE_MX );
   bitmaps.add( dns::TYPE_RRSIG );
   bitmaps.add( dns::TYPE_NSEC );
   bitmaps.add( 0x04d2 );

    WireFormat message;
    bitmaps.outputWireFormat( message );
    ASSERT_EQ( 37, message.size() );

    EXPECT_EQ( 0x00, (uint32_t)message[0] );
    EXPECT_EQ( 0x06, (uint32_t)message[1] );
    EXPECT_EQ( 0x40, (uint32_t)message[2] );
    EXPECT_EQ( 0x01, (uint32_t)message[3] );
    EXPECT_EQ( 0x00, (uint32_t)message[4] );
    EXPECT_EQ( 0x00, (uint32_t)message[5] );
    EXPECT_EQ( 0x00, (uint32_t)message[6] );
    EXPECT_EQ( 0x03, (uint32_t)message[7] );

    EXPECT_EQ( 0x04, (uint32_t)message[8] );
    EXPECT_EQ( 0x1b, (uint32_t)message[9] );
    EXPECT_EQ( 0x00, (uint32_t)message[10] );
    EXPECT_EQ( 0x00, (uint32_t)message[11] );
    EXPECT_EQ( 0x00, (uint32_t)message[12] );
    EXPECT_EQ( 0x00, (uint32_t)message[13] );
    EXPECT_EQ( 0x00, (uint32_t)message[14] );
    EXPECT_EQ( 0x00, (uint32_t)message[15] );

    EXPECT_EQ( 0x00, (uint32_t)message[16] );
    EXPECT_EQ( 0x00, (uint32_t)message[17] );
    EXPECT_EQ( 0x00, (uint32_t)message[18] );
    EXPECT_EQ( 0x00, (uint32_t)message[19] );
    EXPECT_EQ( 0x00, (uint32_t)message[20] );
    EXPECT_EQ( 0x00, (uint32_t)message[21] );
    EXPECT_EQ( 0x00, (uint32_t)message[22] );
    EXPECT_EQ( 0x00, (uint32_t)message[23] );

    EXPECT_EQ( 0x00, (uint32_t)message[24] );
    EXPECT_EQ( 0x00, (uint32_t)message[25] );
    EXPECT_EQ( 0x00, (uint32_t)message[26] );
    EXPECT_EQ( 0x00, (uint32_t)message[27] );
    EXPECT_EQ( 0x00, (uint32_t)message[28] );
    EXPECT_EQ( 0x00, (uint32_t)message[29] );
    EXPECT_EQ( 0x00, (uint32_t)message[30] );
    EXPECT_EQ( 0x00, (uint32_t)message[31] );

    EXPECT_EQ( 0x00, (uint32_t)message[32] );
    EXPECT_EQ( 0x00, (uint32_t)message[33] );
    EXPECT_EQ( 0x00, (uint32_t)message[34] );
    EXPECT_EQ( 0x00, (uint32_t)message[35] );
    EXPECT_EQ( 0x20, (uint32_t)message[36] );
}


class RecordNSECTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }

    uint8_t typeToIndex( dns::Type t )
    {
	t = 0xff & t;
	uint8_t index = 7 - ( t % 8 );
	return 1 << index;
    }
};


TEST_F( RecordNSECTest, WriteFormatNSECRFC4034 )
{
    std::vector<dns::Type> types;
    types.push_back( dns::TYPE_A );
    types.push_back( dns::TYPE_MX );
    types.push_back( dns::TYPE_RRSIG );
    types.push_back( dns::TYPE_NSEC );
    types.push_back( 0x04d2 );

    dns::RecordNSEC nsec( "host.example.com", types );
    WireFormat message;
    dns::OffsetDB offset_db;
    nsec.outputWireFormat( message, offset_db );
    ASSERT_EQ( 55, message.size() );

    EXPECT_EQ( 0x04, (uint32_t)message[0] );
    EXPECT_EQ( 'h', message[1] );
    EXPECT_EQ( 'o', message[2] );
    EXPECT_EQ( 's', message[3] );
    EXPECT_EQ( 't', message[4] );

    EXPECT_EQ( 0x07, (uint32_t)message[5] );
    EXPECT_EQ( 'e', message[6] );
    EXPECT_EQ( 'x', message[7] );
    EXPECT_EQ( 'a', message[8] );
    EXPECT_EQ( 'm', message[9] );
    EXPECT_EQ( 'p', message[10] );
    EXPECT_EQ( 'l', message[11] );
    EXPECT_EQ( 'e', message[12] );

    EXPECT_EQ( 0x03, (uint32_t)message[13] );
    EXPECT_EQ( 'c', message[14] );
    EXPECT_EQ( 'o', message[15] );
    EXPECT_EQ( 'm', message[16] );

    EXPECT_EQ( 0x00, (uint32_t)message[17] );

    EXPECT_EQ( 0x00, (uint32_t)message[18] );
    EXPECT_EQ( 0x06, (uint32_t)message[19] );
    EXPECT_EQ( 0x40, (uint32_t)message[20] );
    EXPECT_EQ( 0x01, (uint32_t)message[21] );
    EXPECT_EQ( 0x00, (uint32_t)message[22] );
    EXPECT_EQ( 0x00, (uint32_t)message[23] );
    EXPECT_EQ( 0x00, (uint32_t)message[24] );
    EXPECT_EQ( 0x03, (uint32_t)message[25] );

    EXPECT_EQ( 0x04, (uint32_t)message[26] );
    EXPECT_EQ( 0x1b, (uint32_t)message[27] );
    EXPECT_EQ( 0x00, (uint32_t)message[28] );
    EXPECT_EQ( 0x00, (uint32_t)message[29] );
    EXPECT_EQ( 0x00, (uint32_t)message[30] );
    EXPECT_EQ( 0x00, (uint32_t)message[31] );
    EXPECT_EQ( 0x00, (uint32_t)message[32] );
    EXPECT_EQ( 0x00, (uint32_t)message[33] );

    EXPECT_EQ( 0x00, (uint32_t)message[34] );
    EXPECT_EQ( 0x00, (uint32_t)message[35] );
    EXPECT_EQ( 0x00, (uint32_t)message[36] );
    EXPECT_EQ( 0x00, (uint32_t)message[37] );
    EXPECT_EQ( 0x00, (uint32_t)message[38] );
    EXPECT_EQ( 0x00, (uint32_t)message[39] );
    EXPECT_EQ( 0x00, (uint32_t)message[40] );
    EXPECT_EQ( 0x00, (uint32_t)message[41] );

    EXPECT_EQ( 0x00, (uint32_t)message[42] );
    EXPECT_EQ( 0x00, (uint32_t)message[43] );
    EXPECT_EQ( 0x00, (uint32_t)message[44] );
    EXPECT_EQ( 0x00, (uint32_t)message[45] );
    EXPECT_EQ( 0x00, (uint32_t)message[46] );
    EXPECT_EQ( 0x00, (uint32_t)message[47] );
    EXPECT_EQ( 0x00, (uint32_t)message[48] );
    EXPECT_EQ( 0x00, (uint32_t)message[49] );

    EXPECT_EQ( 0x00, (uint32_t)message[50] );
    EXPECT_EQ( 0x00, (uint32_t)message[51] );
    EXPECT_EQ( 0x00, (uint32_t)message[52] );
    EXPECT_EQ( 0x00, (uint32_t)message[53] );
    EXPECT_EQ( 0x20, (uint32_t)message[54] );
  
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
