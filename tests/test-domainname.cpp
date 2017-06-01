#include "dns.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

// The fixture for testing class Foo.
class DomainnameTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};


TEST_F( DomainnameTest, ConstructFromString )
{
    dns::Domainname example_com( std::string( "example.com" ) );

    EXPECT_STREQ( "example", example_com.getLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getLabels()[1].c_str() );
    EXPECT_STREQ( "example", example_com.getCanonicalLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getCanonicalLabels()[1].c_str() );
}

TEST_F( DomainnameTest, ConstructFromStringHasUpperCase )
{
    dns::Domainname example_com( std::string( "EXAMPLE.Com" ) );

    EXPECT_STREQ( "EXAMPLE", example_com.getLabels()[0].c_str() );
    EXPECT_STREQ( "Com",     example_com.getLabels()[1].c_str() );
    EXPECT_STREQ( "example", example_com.getCanonicalLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getCanonicalLabels()[1].c_str() );
}

TEST_F( DomainnameTest, ConstructFromLiteral )
{
    dns::Domainname example_com( "example.com" );

    EXPECT_STREQ( "example", example_com.getLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getLabels()[1].c_str() );
    EXPECT_STREQ( "example", example_com.getCanonicalLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getCanonicalLabels()[1].c_str() );
}

TEST_F( DomainnameTest, ConstructFromLiteralHasUpperCase )
{
    dns::Domainname example_com( "EXAMPLE.Com" );

    EXPECT_STREQ( "EXAMPLE", example_com.getLabels()[0].c_str() );
    EXPECT_STREQ( "Com",     example_com.getLabels()[1].c_str() );
    EXPECT_STREQ( "example", example_com.getCanonicalLabels()[0].c_str() );
    EXPECT_STREQ( "com",     example_com.getCanonicalLabels()[1].c_str() );
}

TEST_F( DomainnameTest, subdomain )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child.example.com" );

    EXPECT_TRUE( parent.isSubDomain( child ) ) << "child.example.com is subdomain of example.com";
}

TEST_F( DomainnameTest, case_insenstive )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child.EXAMPLE.com" );

    EXPECT_TRUE( parent.isSubDomain( child ) ) << "child.EXAMPLE.com is subdomain of example.com";
}

TEST_F( DomainnameTest, paranet_is_not_subdomain )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child.example.jp" );

    EXPECT_FALSE( parent.isSubDomain( child ) ) << "child.example.jp is not subdomain of example.com";
}

TEST_F( DomainnameTest, not_subdomain )
{
    dns::Domainname parent( "child.example.com" );
    dns::Domainname child( "example.com" );

    EXPECT_FALSE( parent.isSubDomain( child ) ) << "example.com is not subdomain of child.example.com";
}

TEST_F( DomainnameTest, same_domainname )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "example.com" );

    EXPECT_TRUE( parent.isSubDomain( child ) ) << "example.com is subdomain of example.com";
}

TEST_F( DomainnameTest, relative_name )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child.example.com" );

    EXPECT_EQ( dns::Domainname( "child" ), parent.getRelativeDomainname( child ) )
        << "relative domainname of child.example.com to example.com is child.";
}

TEST_F( DomainnameTest, relative_name_2 )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child2.child.example.com" );

    EXPECT_EQ( dns::Domainname( "child2.child" ), parent.getRelativeDomainname( child ) )
        << "relative domainname of child2.child.example.com to example.com is child2.child.";
}


TEST_F( DomainnameTest, no_subodmain_error )
{
    dns::Domainname parent( "example.com" );
    dns::Domainname child( "child.example.jp" );

    EXPECT_THROW( { parent.getRelativeDomainname( child ); }, dns::DomainnameError )
        << "if child is not subdomain, DomainnameError is thrown.";
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
