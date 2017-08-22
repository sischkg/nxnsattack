#include "zonesigner.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>


class DNSKEYTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

const char *KSK_DNSKEY_BASE64 =
    "AwEAAdYg5E46kVXXLNnVZYGutuUr8WuBOw+D/La0MnQYIn6POg61eMtN"
    "5JBKZBmO+fP4Pw9Rddt4xVjN4OmxUkcRJ/rdi/SzMTo4/kqUuHKm3uRX"
    "CKtwkfDCOgN1jm/ORGkVb7vFAmRYyAO6LxkcRZHBpqtHp10uPt+Qeh4+"
    "TodQo688AC54ldJSt0NZIMRYgcfodfzs+zmIBvB5lNaNlsOtTCr9W+7A"
    "m2J5H79YFYqPaNz7ON2u8c1hpSb55gQYKBVXuIG84D5xAWboc7a/tpk0"
    "EnwXCvhCj5m40xVjJOrgD5TrwMTrJml2KwgyGcIxABxji+N6kCHZkma9"
    "gtgAyD++xw0=";

const char *PUBLIC_EXPONENT_BASE64 = "AQAB";

const char *MODULUS_BASE64 =
    "1iDkTjqRVdcs2dVlga625Svxa4E7D4P8trQydBgifo86DrV4y03kkEpk"
    "GY758/g/D1F123jFWM3g6bFSRxEn+t2L9LMxOjj+SpS4cqbe5FcIq3CR"
    "8MI6A3WOb85EaRVvu8UCZFjIA7ovGRxFkcGmq0enXS4+35B6Hj5Oh1Cj"
    "rzwALniV0lK3Q1kgxFiBx+h1/Oz7OYgG8HmU1o2Ww61MKv1b7sCbYnkf"
    "v1gVio9o3Ps43a7xzWGlJvnmBBgoFVe4gbzgPnEBZuhztr+2mTQSfBcK"
    "+EKPmbjTFWMk6uAPlOvAxOsmaXYrCDIZwjEAHGOL43qQIdmSZr2C2ADI"
    "P77HDQ==";

TEST_F( DNSKEYTest, CompareDNSKEY )
{
    std::vector<uint8_t> ksk_dnskey, expected, public_exponent, modulus;
    decode_from_base64( KSK_DNSKEY_BASE64,      expected );
    decode_from_base64( PUBLIC_EXPONENT_BASE64, public_exponent );
    decode_from_base64( MODULUS_BASE64,         modulus );

    dns::RSAPublicKey public_key( public_exponent, modulus );
    ksk_dnskey = public_key.getDNSKEYFormat();
    EXPECT_EQ( expected, ksk_dnskey );
}




int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
