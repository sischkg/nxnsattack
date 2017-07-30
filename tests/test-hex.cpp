#include "utils.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class HexTest : public ::testing::Test
{
public:
};

TEST_F( HexTest, encodeToHex_empty )
{
    std::vector<uint8_t> src;
    std::string          dst;
    encodeToHex( src, dst );
    EXPECT_EQ( "00", dst );
}

TEST_F( HexTest, encodeToHex_0x01 )
{
    std::vector<uint8_t> src;
    std::string          dst;

    src.push_back( 0x01 );
    encodeToHex( src, dst );
    EXPECT_EQ( "01", dst );
}

TEST_F( HexTest, encodeToHex_0x0f )
{
    std::vector<uint8_t> src;
    std::string          dst;

    src.push_back( 0x0f );
    encodeToHex( src, dst );

    EXPECT_EQ( "0F", dst );
}

TEST_F( HexTest, encodeToHex_0xf0 )
{
    std::vector<uint8_t> src;
    std::string          dst;

    src.push_back( 0xf0 );
    encodeToHex( src, dst );

    EXPECT_EQ( "F0", dst );
}

TEST_F( HexTest, encodeToHex_0x01f0 )
{
    std::vector<uint8_t> src;
    std::string          dst;

    src.push_back( 0x01 );
    src.push_back( 0xf0 );
    encodeToHex( src, dst );

    EXPECT_EQ( "01F0", dst );
}

TEST_F( HexTest, decodeFromHex_empty )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "", dst );

    ASSERT_EQ( 1, dst.size() );
    EXPECT_EQ( 0, dst[0] );
}

TEST_F( HexTest, decodeFromHex_01 )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "01", dst );

    ASSERT_EQ( 1, dst.size() );
    EXPECT_EQ( 1, dst[0] );
}

TEST_F( HexTest, decodeFromHex_0f )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "0f", dst );

    ASSERT_EQ( 1, dst.size() );
    EXPECT_EQ( 0x0f, dst[0] );
}

TEST_F( HexTest, decodeFromHex_aF )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "af", dst );

    ASSERT_EQ( 1, dst.size() );
    EXPECT_EQ( 0xaf, dst[0] );
}

TEST_F( HexTest, decodeFromHex_f0 )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "f0", dst );

    ASSERT_EQ( 1, dst.size() );
    EXPECT_EQ( 0xf0, dst[0] );
}

TEST_F( HexTest, decodeFromHex_01f0 )
{
    std::vector<uint8_t> dst;

    decodeFromHex( "010f", dst );

    ASSERT_EQ( 2, dst.size() );
    EXPECT_EQ( 0x01, dst[0] );
    EXPECT_EQ( 0x0f, dst[1] );
}


TEST_F( HexTest, decodeFromHex_bad_char )
{
    std::vector<uint8_t> dst;

    ASSERT_THROW( {
	    decodeFromHex( "010z", dst );
	}, std::runtime_error );
}

TEST_F( HexTest, decodeFromHex_bad_length )
{
    std::vector<uint8_t> dst;

    ASSERT_THROW( {
	    decodeFromHex( "010", dst );
	}, std::runtime_error );
}



int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
