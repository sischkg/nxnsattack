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

    uint8_t typeToIndex( dns::Type t )
    {
	t = 0xff & t;
	uint8_t index = 8 - ( t % 8 );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_A ), message[2] );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_A ) | typeToIndex( dns::TYPE_SOA ), message[2] );
}


TEST_F( WindowTest, WriteFormatOnlyType0x0201 )
{
    dns::NSECBitmapField::Window win( 2 );
    win.add( 0x0201 );

    WireFormat message;
    win.outputWireFormat( message );

    EXPECT_EQ( 2, message[0] ); // Index of Type_0x0201 is 2;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), message[2] );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), message[3] );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_A  ), message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), message[3] );
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
	uint8_t index = 8 - ( t % 8 );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_A ), message[2] );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_A ), message[2] );
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), message[3] );
}

TEST_F( NSECBitmapFieldTest, WriteFormatOnlyTYPE0201 )
{
    dns::NSECBitmapField bitmaps;
    bitmaps.add( 0x0201 );

    WireFormat message;
    bitmaps.outputWireFormat( message );

    EXPECT_EQ( 2, message[0] ); // Index of TYPE_0201 = 0x0201 is 2;
    EXPECT_EQ( 1, message[1] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), message[2] );
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
    EXPECT_EQ( typeToIndex( dns::TYPE_MX ), message[3] );

    EXPECT_EQ( 2, message[4] ); // Index of TYPE_0201 = 0x0201 is 2;
    EXPECT_EQ( 1, message[5] ); // window size = 1
    EXPECT_EQ( typeToIndex( 0x201 ), message[6] );
}


int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
