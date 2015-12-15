#include "wireformat.hpp"
#include <iostream>
#include <cstring>
#include "gtest/gtest.h"

// The fixture for testing class Foo.
class WireFormatTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {}

    virtual void TearDown()
    {}
};


TEST_F(WireFormatTest, default_size_0)
{
    WireFormat msg;
    EXPECT_EQ( 0, msg.size() ) << "default size is 0 (no data)";
}

TEST_F(WireFormatTest, size_1)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    
    EXPECT_EQ( 1, msg.size() );
    EXPECT_EQ( 0, msg[0] );
}

TEST_F(WireFormatTest, size_2)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    
    EXPECT_EQ( 2, msg.size() );
    EXPECT_EQ( 1, msg[1] );
}

TEST_F(WireFormatTest, size_3)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    
    EXPECT_EQ( 3, msg.size() );
    EXPECT_EQ( 2, msg[2] );
}

TEST_F(WireFormatTest, size_4)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );
    
    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 3, msg[3] );
}


TEST_F(WireFormatTest, pop_back)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );

    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 3, msg.pop_back() );
    EXPECT_EQ( 3, msg.size() );
    EXPECT_EQ( 2, msg[2] );
}

TEST_F(WireFormatTest, ng_pop_back)
{
    WireFormat msg;

    EXPECT_THROW( { msg.pop_back(); }, std::runtime_error );
}

TEST_F(WireFormatTest, check_index)
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );

    EXPECT_NO_THROW( { msg[0]; } );
    EXPECT_NO_THROW( { msg[1]; } );
    EXPECT_NO_THROW( { msg[2]; } );
    EXPECT_NO_THROW( { msg[3]; } );
    EXPECT_THROW( { msg[4]; }, std::runtime_error );
}


TEST_F(WireFormatTest, pushUint16HtoN)
{
    WireFormat msg( 4 );
    msg.pushUInt16HtoN( 0x0102 );

    EXPECT_EQ( 2, msg.size() );
    EXPECT_EQ( 0x01, msg[0] );
    EXPECT_EQ( 0x02, msg[1] );
}

TEST_F(WireFormatTest, pushUint32HtoN)
{
    WireFormat msg( 4 );
    msg.pushUInt32HtoN( 0x01020304 );

    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 0x01, msg[0] );
    EXPECT_EQ( 0x02, msg[1] );
    EXPECT_EQ( 0x03, msg[2] );
    EXPECT_EQ( 0x04, msg[3] );
}



int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

