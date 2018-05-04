#include "nsecdb.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>


class NSECDBTest : public ::testing::Test
{
public:
    dns::NSECDB mNSECDB;

public:
    NSECDBTest()
        : mNSECDB( "example.com" )
    {}

    virtual void SetUp()
    {
        dns::Node::RRSetPtr soa = std::make_shared<dns::RRSet>( "example.com", dns::CLASS_IN, dns::TYPE_SOA, 3600 );
        soa->add( std::make_shared<dns::RecordSOA>( "ns.example.com", "hostmaster.example.com", 1, 86400, 3600, 8640000, 3600 ) );
        dns::Node::RRSetPtr ns = std::make_shared<dns::RRSet>( "example.com", dns::CLASS_IN, dns::TYPE_NS, 3600 );
        ns->add( std::make_shared<dns::RecordNS>( "ns.example.com" ) );
        dns::Node::RRSetPtr mx = std::make_shared<dns::RRSet>( "example.com", dns::CLASS_IN, dns::TYPE_MX, 3600 );
        mx->add( std::make_shared<dns::RecordMX>( 10, "mail.example.com" ) ); 

        dns::Node::RRSetPtr www = std::make_shared<dns::RRSet>( "www.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 );
        www->add( std::make_shared<dns::RecordA>( "192.2.0.1" ) );

        dns::Node::RRSetPtr mail = std::make_shared<dns::RRSet>( "mail.example.com", dns::CLASS_IN, dns::TYPE_A, 3600 );
        mail->add( std::make_shared<dns::RecordA>( "192.2.0.2" ) );

        dns::Zone::NodePtr apex_node = std::make_shared<dns::Node>();
        dns::Zone::NodePtr www_node = std::make_shared<dns::Node>();
        dns::Zone::NodePtr mail_node = std::make_shared<dns::Node>();
        apex_node->add( soa ).add( ns ).add( mx );
        www_node->add( www );
        mail_node->add( mail );

        mNSECDB.addNode( "example.com",      *apex_node );
        mNSECDB.addNode( "www.example.com",  *www_node );
        mNSECDB.addNode( "mail.example.com", *mail_node );
    }

    virtual void TearDown()
    {
    }

};

TEST_F( NSECDBTest, find )
{
    auto nsec_rr = mNSECDB.find( "wwww.example.com", 300 );
    EXPECT_EQ( "www.example.com", nsec_rr.mDomainname );
    EXPECT_EQ( dns::CLASS_IN,     nsec_rr.mClass );
    EXPECT_EQ( dns::TYPE_NSEC,    nsec_rr.mType );
    EXPECT_EQ( 300,               nsec_rr.mTTL );

    auto nsec_rd = std::dynamic_pointer_cast<dns::RecordNSEC>( nsec_rr.mRData );
            
    EXPECT_EQ( "example.com",   nsec_rd->getNextDomainname() );
    EXPECT_EQ( 3,               nsec_rd->getTypes().size() );   // A, NSEC, RRSIG
    EXPECT_EQ( dns::TYPE_A,     nsec_rd->getTypes()[0] );
    EXPECT_EQ( dns::TYPE_NSEC,  nsec_rd->getTypes()[1] );
    EXPECT_EQ( dns::TYPE_RRSIG, nsec_rd->getTypes()[2] );
}

TEST_F( NSECDBTest, find_for_2 )
{
    auto nsec_rr = mNSECDB.find( "ww.example.com", 300 );
    EXPECT_EQ( "mail.example.com", nsec_rr.mDomainname );
    EXPECT_EQ( dns::CLASS_IN,     nsec_rr.mClass );
    EXPECT_EQ( dns::TYPE_NSEC,    nsec_rr.mType );
    EXPECT_EQ( 300,               nsec_rr.mTTL );

    auto nsec_rd = std::dynamic_pointer_cast<dns::RecordNSEC>( nsec_rr.mRData );
            
    EXPECT_EQ( "www.example.com", nsec_rd->getNextDomainname() );
    EXPECT_EQ( 3,                 nsec_rd->getTypes().size() );
    EXPECT_EQ( dns::TYPE_A,       nsec_rd->getTypes()[0] );
    EXPECT_EQ( dns::TYPE_NSEC,    nsec_rd->getTypes()[1] );
    EXPECT_EQ( dns::TYPE_RRSIG,   nsec_rd->getTypes()[2] );
}

TEST_F( NSECDBTest, find_for_wildcard )
{
    auto nsec_rr = mNSECDB.find( "*.example.com", 300 );
    EXPECT_EQ( "example.com",  nsec_rr.mDomainname );
    EXPECT_EQ( dns::CLASS_IN,  nsec_rr.mClass );
    EXPECT_EQ( dns::TYPE_NSEC, nsec_rr.mType );
    EXPECT_EQ( 300,            nsec_rr.mTTL );

    auto nsec_rd = std::dynamic_pointer_cast<dns::RecordNSEC>( nsec_rr.mRData );
            
    EXPECT_EQ( "mail.example.com",  nsec_rd->getNextDomainname() );
    EXPECT_EQ( 5,                   nsec_rd->getTypes().size() ); // SOA + NS + MX + NSEC + RRSIG
}

TEST_F( NSECDBTest, find_for_nodata )
{
    auto nsec_rr = mNSECDB.find( "mail.example.com", 300 );
    EXPECT_EQ( "mail.example.com",  nsec_rr.mDomainname );
    EXPECT_EQ( dns::CLASS_IN,       nsec_rr.mClass );
    EXPECT_EQ( dns::TYPE_NSEC,      nsec_rr.mType );
    EXPECT_EQ( 300,                 nsec_rr.mTTL );

    auto nsec_rd = std::dynamic_pointer_cast<dns::RecordNSEC>( nsec_rr.mRData );
            
    EXPECT_EQ( "www.example.com",  nsec_rd->getNextDomainname() );
    EXPECT_EQ( 3,                  nsec_rd->getTypes().size() ); // A, NSEC, RRSIG
}

TEST_F( NSECDBTest, find_for_nodata_last )
{
    auto nsec_rr = mNSECDB.find( "www.example.com", 300 );
    EXPECT_EQ( "www.example.com",  nsec_rr.mDomainname );
    EXPECT_EQ( dns::CLASS_IN,      nsec_rr.mClass );
    EXPECT_EQ( dns::TYPE_NSEC,     nsec_rr.mType );
    EXPECT_EQ( 300,                nsec_rr.mTTL );

    auto nsec_rd = std::dynamic_pointer_cast<dns::RecordNSEC>( nsec_rr.mRData );
            
    EXPECT_EQ( "example.com",  nsec_rd->getNextDomainname() );
    EXPECT_EQ( 3,              nsec_rd->getTypes().size() ); // A, NSEC, RRSIG
}



int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
