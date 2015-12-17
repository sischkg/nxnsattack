#include "utils.hpp"
#include <iostream>
#include <sstream>
#include <cstring>
#include <openssl/md5.h>
#include "gtest/gtest.h"

class MD5Test : public ::testing::Test
{
protected:
    char data[1000];
    uint8_t result[17];
    uint8_t expected[16];
    char result_text[32];
    
public:
    virtual void SetUp()
    {
    std::memset( data, 0, sizeof(data) );
    std::memset( result, 0, sizeof(result) );
    std::memset( result_text, 0, sizeof(result_text) );
    }

    virtual void TearDown()
    {}
};

TEST_F(MD5Test, encodable_0_bytes)
{
    uint8_t data[] = { 'a', 'b', }; 

    MD5_CTX c;
    int r = MD5_Init(&c);
    r = MD5_Update(&c, data, sizeof(data) );
    r = MD5_Final(expected, &c);

    md5( data, sizeof(data), result );
    std::ostringstream os;
    for ( unsigned int i = 0; i < sizeof(result) ; i++ ){
    os << (uint16_t)result[i];
    std::cerr << (uint16_t)result[i] << std::endl;
    }

    for ( int i = 0 ; i< 16 ; i++ ) {
    EXPECT_EQ( expected[i], result[i] );
    }
}


int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
