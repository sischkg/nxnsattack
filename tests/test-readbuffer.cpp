#include "readbuffer.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class ReadBufferTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( ReadBufferTest, readUInt8 )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, };
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x00, msg.readUInt8() );
    EXPECT_EQ( 0x01, msg.readUInt8() );
    EXPECT_EQ( 0x02, msg.readUInt8() );
    EXPECT_EQ( 0x03, msg.readUInt8() );
}

TEST_F( ReadBufferTest, readUInt16 )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, };
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x0100, msg.readUInt16() );
    EXPECT_EQ( 0x0302, msg.readUInt16() );
}

TEST_F( ReadBufferTest, readUInt32 )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x03020100, msg.readUInt32() );
    EXPECT_EQ( 0x07060504, msg.readUInt32() );
}

TEST_F( ReadBufferTest, readUInt64 )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x0706050403020100, msg.readUInt64() );
}

TEST_F( ReadBufferTest, readUInt16NtoH )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, };
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x0001, msg.readUInt16NtoH() );
    EXPECT_EQ( 0x0203, msg.readUInt16NtoH() );
}

TEST_F( ReadBufferTest, readUInt32NtoH )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x00010203, msg.readUInt32NtoH() );
    EXPECT_EQ( 0x04050607, msg.readUInt32NtoH() );
}

TEST_F( ReadBufferTest, readUInt64NtoH )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ReadBuffer msg( buf, sizeof( buf ) );
    
    EXPECT_EQ( 0x0001020304050607, msg.readUInt64NtoH() );
}

TEST_F( ReadBufferTest, readBuffer )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ReadBuffer msg( buf, sizeof( buf ) );

    std::vector<uint8_t> dst;
    msg.readBuffer( dst, 3 );
    EXPECT_EQ( 3, dst.size() );
    EXPECT_EQ( 0x00, dst[0] );
    EXPECT_EQ( 0x01, dst[1] );
    EXPECT_EQ( 0x02, dst[2] );

    msg.readBuffer( dst, 4 );
    EXPECT_EQ( 4, dst.size() );
    EXPECT_EQ( 0x03, dst[0] );
    EXPECT_EQ( 0x04, dst[1] );
    EXPECT_EQ( 0x05, dst[2] );
    EXPECT_EQ( 0x06, dst[3] );
}

TEST_F( ReadBufferTest, readBuffer_from_short_buffer )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02, };
    ReadBuffer msg( buf, sizeof( buf ) );

    std::vector<uint8_t> dst;
    msg.readBuffer( dst, 5 );
    EXPECT_EQ( 3, dst.size() );
    EXPECT_EQ( 0x00, dst[0] );
    EXPECT_EQ( 0x01, dst[1] );
    EXPECT_EQ( 0x02, dst[2] );

    EXPECT_THROW( { msg.readBuffer( dst, 5 ); }, std::runtime_error );
}


TEST_F( ReadBufferTest, checkOutOfBonund_uint8 )
{
    uint8_t buf[] = { 0x00, 0x01 };
    ReadBuffer msg( buf, sizeof( buf ) );

    EXPECT_NO_THROW( { msg.readUInt8(); } );
    EXPECT_NO_THROW( { msg.readUInt8(); } );
    EXPECT_THROW( { msg.readUInt8(); }, std::runtime_error );
}

TEST_F( ReadBufferTest, checkOutOfBonund_uint16 )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02 };
    ReadBuffer msg( buf, sizeof( buf ) );

    EXPECT_NO_THROW( { msg.readUInt16(); } );
    EXPECT_THROW( { msg.readUInt16(); }, std::runtime_error );
}


TEST_F( ReadBufferTest, getRemainedSize )
{
    uint8_t buf[] = { 0x00, 0x01, 0x02 };
    ReadBuffer msg( buf, sizeof( buf ) );

    EXPECT_EQ( 3, msg.getRemainedSize() );
    msg.readUInt16();
    EXPECT_EQ( 1, msg.getRemainedSize() );
    msg.readUInt8();
    EXPECT_EQ( 0, msg.getRemainedSize() );
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
