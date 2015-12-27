#include "utils.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

// The fixture for testing class Foo.
class Base64Test : public ::testing::Test
{
protected:
    char    encoded[ 1000 ];
    uint8_t decoded[ 1000 ];

public:
    virtual void SetUp()
    {
        std::memset( decoded, 0, sizeof( decoded ) );
        std::memset( encoded, 0, sizeof( encoded ) );
    }

    virtual void TearDown()
    {
    }
};

TEST_F( Base64Test, encodable_0_bytes )
{
    uint8_t data[] = {};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded, end ) << "encoded data is \"\"";
    EXPECT_EQ( 0, encoded[ 0 ] ) << "encoded data is NULL terminated";
}

TEST_F( Base64Test, encodable_1_bytes )
{
    uint8_t data[] = {'a'};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded + 4, end ) << "encoded data size of \"a\" is 4";
    EXPECT_STREQ( "YQ==", encoded ) << "encoded data is \"YQ==\"";
}

TEST_F( Base64Test, encodable_2_bytes )
{
    uint8_t data[] = {'a', 'b'};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded + 4, end ) << "encoded data size of \"ab\" is 4";
    EXPECT_STREQ( "YWI=", encoded ) << "encoded data is \"YWI=\"";
}

TEST_F( Base64Test, encodable_3_bytes )
{
    uint8_t data[] = {'a', 'b', 'c'};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded + 4, end ) << "encoded data size of \"abc\" is 4";
    EXPECT_STREQ( "YWJj", encoded ) << "encoded data is \"YWJj\"";
}

TEST_F( Base64Test, encodable_4_bytes )
{
    uint8_t data[] = {'a', 'b', 'c', 'd'};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded + 8, end ) << "encoded data size of \"abcd\" is 8";
    EXPECT_STREQ( "YWJjZA==", encoded ) << "encoded data is \"YWJjZA==\"";
}

TEST_F( Base64Test, encodable_5_bytes )
{
    uint8_t data[] = {'a', 'b', 'c', 'd', 'e'};
    char *  end    = encode_to_base64( data, data + sizeof( data ), encoded );

    EXPECT_EQ( encoded + 8, end ) << "encoded data size of \"abcde\" is 8";
    EXPECT_STREQ( "YWJjZGU=", encoded ) << "encoded data is \"YWJjZGU=\"";
}

TEST_F( Base64Test, decodable_0_bytes )
{
    char     data[] = "";
    uint8_t *end    = decode_from_base64( data, data + std::strlen( data ), decoded );

    EXPECT_EQ( decoded, end ) << "decoded data is \"\"";
}

TEST_F( Base64Test, decodable_1_bytes )
{
    char     data[] = "YQ==";
    uint8_t *end    = decode_from_base64( data, data + std::strlen( data ), decoded );

    EXPECT_EQ( decoded + 1, end ) << "decoded data size of \"YQ==\" is a";
    EXPECT_EQ( 'a', decoded[ 0 ] ) << "decoded data is \"a\"";
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
