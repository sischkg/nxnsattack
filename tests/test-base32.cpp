#include "utils.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <algorithm>

class Base32HexTest : public ::testing::Test
{
public:
    std::vector<uint8_t> bin;
    std::string          str;

    void setup()
    {
        bin.clear();
        str.clear();
    }

    void setup_bin( const char *src )
    {
        ssize_t len = std::strlen( src );
        bin.resize( len );
        std::copy( src, src + len, bin.begin() );
    }
};

TEST_F( Base32HexTest, encodable_0_bytes )
{
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 0, str.size() );
}

TEST_F( Base32HexTest, encodable_1_byte_f )
{
    setup_bin( "f" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 2, str.size() );
    EXPECT_EQ( "CO", str );
}

TEST_F( Base32HexTest, encodable_2_byte_fo )
{
    setup_bin( "fo" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 4, str.size() );
    EXPECT_EQ( "CPNG", str );
}

TEST_F( Base32HexTest, encodable_3_byte_foo )
{
    setup_bin( "foo" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 5, str.size() );
    EXPECT_EQ( "CPNMU", str );
}

TEST_F( Base32HexTest, encodable_4_byte_foob )
{
    setup_bin( "foob" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 7, str.size() );
    EXPECT_EQ( "CPNMUOG", str );
}

TEST_F( Base32HexTest, encodable_5_byte_fooba )
{
    setup_bin( "fooba" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 8, str.size() );
    EXPECT_EQ( "CPNMUOJ1", str );
}

TEST_F( Base32HexTest, encodable_6_byte_foobar )
{
    setup_bin( "foobar" );
    encodeToBase32Hex( bin, str );
    EXPECT_EQ( 10, str.size() );
    EXPECT_EQ( "CPNMUOJ1E8", str );
}


TEST_F( Base32HexTest, decodable_0_bytes )
{
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 0, bin.size() );
}

TEST_F( Base32HexTest, decodable_1_byte_f )
{
    str = "CO";
    std::vector<uint8_t> expected = { 'f', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 1, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, decodable_2_byte_fo )
{
    str = "CPNG";
    std::vector<uint8_t> expected = { 'f', 'o', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 2, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, decodable_3_byte_foo )
{
    str = "CPNMU";
    std::vector<uint8_t> expected = { 'f', 'o', 'o', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 3, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, decodable_4_byte_foob )
{
    str = "CPNMUOG";
    std::vector<uint8_t> expected = { 'f', 'o', 'o', 'b', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 4, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, decodable_5_byte_fooba )
{
    str = "CPNMUOJ1";
    std::vector<uint8_t> expected = { 'f', 'o', 'o', 'b', 'a', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 5, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, decodable_6_byte_foobar )
{
    str = "CPNMUOJ1E8";
    std::vector<uint8_t> expected = { 'f', 'o', 'o', 'b', 'a', 'r', };
    decodeFromBase32Hex( str, bin );
    EXPECT_EQ( 6, bin.size() );
    EXPECT_EQ( bin, expected );
}

TEST_F( Base32HexTest, self_test )
{
    for ( unsigned int append_count = 0 ; append_count < 64 ; append_count++ ) {
        for ( uint16_t s = 0 ; s < 0x0100 ; s++ ) {
            std::vector<uint8_t> src, result;
            std::string          dst;
        
            for ( unsigned int j = 0 ; j < append_count ; j++ ) {
                src.push_back( 0 );
            }
            src.push_back( s );

            encodeToBase32Hex( src, dst );
            decodeFromBase32Hex( dst, result );

            EXPECT_EQ( src, result );
        }
    }
}




int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
