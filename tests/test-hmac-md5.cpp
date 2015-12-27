#include "wireformat.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <openssl/hmac.h>

// The fixture for testing class Foo.
class HmacMD5Test : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( HmacMD5Test, rfc2202_test_case_1 )
{
    uint8_t key[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
		      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
    unsigned char data[] = "Hi There";
    uint8_t digest[16];
    unsigned int digest_size = 16;
    uint8_t expected[] = {
	0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d,
    };

    HMAC( EVP_md5(), key, 16, data, 8, digest, &digest_size );

    for ( unsigned int i = 0 ; i < sizeof(expected) ; i++ ) {
        EXPECT_EQ( expected[ i ], digest[ i ] );
    }
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}



