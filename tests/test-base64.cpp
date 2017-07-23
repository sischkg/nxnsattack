#include "utils.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

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

TEST_F( Base64Test, decodable_2_bytes )
{
    char     data[] = "YWI=";
    uint8_t *end    = decode_from_base64( data, data + std::strlen( data ), decoded );

    EXPECT_EQ( decoded + 2, end ) << "decoded data size of \"YWI=\" is a";
    EXPECT_EQ( 'a', decoded[ 0 ] ) << "decoded data is \"a\"";
    EXPECT_EQ( 'b', decoded[ 1 ] ) << "decoded data is \"b\"";
}

TEST_F( Base64Test, decodable_3_bytes )
{
    char     data[] = "YWJj";
    uint8_t *end    = decode_from_base64( data, data + std::strlen( data ), decoded );

    EXPECT_EQ( decoded + 3, end ) << "decoded data size of \"YQJj\" is a";
    EXPECT_EQ( 'a', decoded[ 0 ] ) << "decoded data is \"a\"";
    EXPECT_EQ( 'b', decoded[ 1 ] ) << "decoded data is \"b\"";
    EXPECT_EQ( 'c', decoded[ 2 ] ) << "decoded data is \"c\"";
}

TEST_F( Base64Test, decodable_4_bytes )
{
    char     data[] = "YWJjZA==";
    uint8_t *end    = decode_from_base64( data, data + std::strlen( data ), decoded );

    EXPECT_EQ( decoded + 4, end ) << "decoded data size of \"YWJjZA==\" is abcde";
    EXPECT_EQ( 'a', decoded[ 0 ] ) << "decoded data is \"a\"";
    EXPECT_EQ( 'b', decoded[ 1 ] ) << "decoded data is \"b\"";
    EXPECT_EQ( 'c', decoded[ 2 ] ) << "decoded data is \"c\"";
    EXPECT_EQ( 'd', decoded[ 3 ] ) << "decoded data is \"d\"";
}


TEST_F( Base64Test, size_encodable_0_bytes )
{
    uint8_t      data[] = {};
    unsigned int size   = encode_to_base64_size( data, data + sizeof( data ) );

    EXPECT_EQ( 0, size ) << "size = 0";
}

TEST_F( Base64Test, size_encodable_1_bytes )
{
    uint8_t      data[] = {'a'};
    unsigned int size   = encode_to_base64_size( data, data + sizeof( data ) );

    EXPECT_EQ( 4, size ) << "size = 4";
}

TEST_F( Base64Test, size_encodable_2_bytes )
{
    uint8_t      data[] = {'a', 'b'};
    unsigned int size   = encode_to_base64_size( data, data + sizeof( data ) );

    EXPECT_EQ( 4, size ) << "size = 4";
}

TEST_F( Base64Test, size_encodable_3_bytes )
{
    uint8_t      data[] = {'a', 'b', 'c'};
    unsigned int size   = encode_to_base64_size( data, data + sizeof( data ) );

    EXPECT_EQ( 4, size ) << "size = 4";
}

TEST_F( Base64Test, size_encodable_4_bytes )
{
    uint8_t      data[] = {'a', 'b', 'c', 'd'};
    unsigned int size   = encode_to_base64_size( data, data + sizeof( data ) );

    EXPECT_EQ( 8, size ) << "size = 8";
}

TEST_F( Base64Test, size_decodable_0_bytes )
{
    char         data[] = "";
    unsigned int size   = decode_from_base64_size( data, data + std::strlen( data ) );

    EXPECT_EQ( 0, size ) << "size = 0";
}

TEST_F( Base64Test, size_decodable_1_bytes )
{
    char         data[] = "YQ==";
    unsigned int size   = decode_from_base64_size( data, data + std::strlen( data ) );

    EXPECT_EQ( 1, size ) << "size = 1";
}

TEST_F( Base64Test, size_decodable_2_bytes )
{
    char         data[] = "YWI=";
    unsigned int size   = decode_from_base64_size( data, data + std::strlen( data ) );

    EXPECT_EQ( 2, size ) << "size = 2";
}

TEST_F( Base64Test, size_decodable_3_bytes )
{
    char         data[] = "YWJj";
    unsigned int size   = decode_from_base64_size( data, data + std::strlen( data ) );

    EXPECT_EQ( 3, size ) << "size = 3";
}

TEST_F( Base64Test, size_decodable_4_bytes )
{
    char         data[] = "YWJjZA==";
    unsigned int size   = decode_from_base64_size( data, data + std::strlen( data ) );

    EXPECT_EQ( 4, size ) << "size = 4";
}

TEST_F( Base64Test, self_test )
{
    for ( unsigned int i = 0; i < 256; i++ ) {
        for ( unsigned int j = 0; j < 256; j++ ) {
            std::vector<uint8_t> source, destination;
            std::string          encoded;

            source.push_back( i );
            source.push_back( j );

            encode_to_base64( source, encoded );
            decode_from_base64( encoded, destination );

            EXPECT_EQ( source[ 0 ], destination[ 0 ] ) << "1st data";
            EXPECT_EQ( source[ 1 ], destination[ 1 ] ) << "2nd data";
        }
    }
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
