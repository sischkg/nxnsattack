#include "tokenizer.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>
#include <boost/log/trivial.hpp>


class TokenizerTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};


TEST_F( TokenizerTest, no_quote_no_escape )
{
    std::vector<std::string> tokens = tokenize( "a bb ccc" );
    ASSERT_EQ( 3, tokens.size() ) <<  "3 tokens";
    EXPECT_EQ( "a",   tokens[0] );
    EXPECT_EQ( "bb",  tokens[1] );
    EXPECT_EQ( "ccc", tokens[2] );
}

TEST_F( TokenizerTest, oen_token )
{
    std::vector<std::string> tokens = tokenize( "one" );
    ASSERT_EQ( 1, tokens.size() ) <<  "1 token";
    EXPECT_EQ( "one",   tokens[0] );
}

TEST_F( TokenizerTest, quoted_token )
{
    std::vector<std::string> tokens = tokenize( "\"a bb ccc\" 22 333" );
    ASSERT_EQ( 3, tokens.size() ) <<  "3 token";
    EXPECT_EQ( "a bb ccc", tokens[0] );
    EXPECT_EQ( "22",       tokens[1] );
    EXPECT_EQ( "333",      tokens[2] );
}

TEST_F( TokenizerTest, escaped_token )
{
    std::vector<std::string> tokens = tokenize( "1\\2345 \\ 678" );
    ASSERT_EQ( 2, tokens.size() ) <<  "2 token";
    EXPECT_EQ( "12345", tokens[0] );
    EXPECT_EQ( " 678",  tokens[1] );
}


TEST_F( TokenizerTest, SOA )
{
    const char *ZONE_CONFIG_FULL_SOA =  "example.com.  3600 IN SOA ns01.example.com. hostmaster.example.com. 2017050101 3600 1800 8640000 300";
    std::vector<std::string> tokens = tokenize( ZONE_CONFIG_FULL_SOA );

    ASSERT_EQ( 11, tokens.size() ) <<  "11 token";
    EXPECT_EQ( "example.com.",            tokens[0] );
    EXPECT_EQ( "3600",                    tokens[1] );
    EXPECT_EQ( "IN",                      tokens[2] );
    EXPECT_EQ( "SOA",                     tokens[3] );
    EXPECT_EQ( "ns01.example.com.",       tokens[4] );
    EXPECT_EQ( "hostmaster.example.com.", tokens[5] );
    EXPECT_EQ( "2017050101",              tokens[6] );
    EXPECT_EQ( "3600",                    tokens[7] );
    EXPECT_EQ( "1800",                    tokens[8] );
    EXPECT_EQ( "8640000",                 tokens[9] );
    EXPECT_EQ( "300",                     tokens[10] );
}

TEST_F( TokenizerTest, SOA2 )
{
    const char *ZONE_CONFIG_FULL_SOA =  "siskrn.co.				      3600 IN SOA	siskrn.co. hostmaster.siskrn.co. 1500338838 86400 3600 604800 10800";
    std::vector<std::string> tokens = tokenize( ZONE_CONFIG_FULL_SOA );

    ASSERT_EQ( 11, tokens.size() ) <<  "11 token";
    EXPECT_EQ( "siskrn.co.",            tokens[0] );
    EXPECT_EQ( "3600",                  tokens[1] );
    EXPECT_EQ( "IN",                    tokens[2] );
    EXPECT_EQ( "SOA",                   tokens[3] );
    EXPECT_EQ( "siskrn.co.",            tokens[4] );
    EXPECT_EQ( "hostmaster.siskrn.co.", tokens[5] );
    EXPECT_EQ( "1500338838",            tokens[6] );
    EXPECT_EQ( "86400",                 tokens[7] );
    EXPECT_EQ( "3600",                  tokens[8] );
    EXPECT_EQ( "604800",                tokens[9] );
    EXPECT_EQ( "10800",                 tokens[10] );
}



int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
