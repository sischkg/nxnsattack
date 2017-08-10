#include "wireformat.hpp"
#include "gtest/gtest.h"
#include <cstring>
#include <iostream>

class WireFormatTest : public ::testing::Test
{

public:
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

TEST_F( WireFormatTest, default_size_0 )
{
    WireFormat msg;
    EXPECT_EQ( 0, msg.size() ) << "default size is 0 (no data)";
}

TEST_F( WireFormatTest, size_1 )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );

    EXPECT_EQ( 1, msg.size() );
    EXPECT_EQ( 0, msg[ 0 ] );
}

TEST_F( WireFormatTest, size_2 )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );

    EXPECT_EQ( 2, msg.size() );
    EXPECT_EQ( 1, msg[ 1 ] );
}

TEST_F( WireFormatTest, size_3 )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );

    EXPECT_EQ( 3, msg.size() );
    EXPECT_EQ( 2, msg[ 2 ] );
}

TEST_F( WireFormatTest, size_4 )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );

    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 3, msg[ 3 ] );
}

TEST_F( WireFormatTest, pop_back )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );

    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 3, msg.pop_back() );
    EXPECT_EQ( 3, msg.size() );
    EXPECT_EQ( 2, msg[ 2 ] );
}

TEST_F( WireFormatTest, ng_pop_back )
{
    WireFormat msg;

    EXPECT_THROW( { msg.pop_back(); }, std::runtime_error );
}

TEST_F( WireFormatTest, check_index )
{
    WireFormat msg( 4 );
    msg.push_back( 0 );
    msg.push_back( 1 );
    msg.push_back( 2 );
    msg.push_back( 3 );

    EXPECT_NO_THROW( { msg[ 0 ]; } );
    EXPECT_NO_THROW( { msg[ 1 ]; } );
    EXPECT_NO_THROW( { msg[ 2 ]; } );
    EXPECT_NO_THROW( { msg[ 3 ]; } );
    EXPECT_THROW( { msg[ 4 ]; }, std::runtime_error );
}

TEST_F( WireFormatTest, push_buffer )
{
    WireFormat msg( 4 );

    uint8_t data[] = {
        0, 1, 2,
    };

    msg.pushBuffer( data, data + sizeof( data ) );
    EXPECT_EQ( 3, msg.size() );
    EXPECT_EQ( 0, msg[ 0 ] );
    EXPECT_EQ( 1, msg[ 1 ] );
    EXPECT_EQ( 2, msg[ 2 ] );
    EXPECT_THROW( { msg[ 3 ]; }, std::runtime_error );
}

TEST_F( WireFormatTest, push_buffer2 )
{
    WireFormat msg( 4 );

    uint8_t data[] = {0, 1, 2, 3, 4};

    msg.pushBuffer( data, data + sizeof( data ) );
    EXPECT_EQ( 5, msg.size() );
    EXPECT_EQ( 0, msg[ 0 ] );
    EXPECT_EQ( 1, msg[ 1 ] );
    EXPECT_EQ( 2, msg[ 2 ] );
    EXPECT_EQ( 3, msg[ 3 ] );
    EXPECT_EQ( 4, msg[ 4 ] );
    EXPECT_THROW( { msg[ 5 ]; }, std::runtime_error );
}

TEST_F( WireFormatTest, pushUint16HtoN )
{
    WireFormat msg( 4 );
    msg.pushUInt16HtoN( 0x0102 );

    EXPECT_EQ( 2, msg.size() );
    EXPECT_EQ( 0x01, msg[ 0 ] );
    EXPECT_EQ( 0x02, msg[ 1 ] );
}

TEST_F( WireFormatTest, pushUint32HtoN )
{
    WireFormat msg( 4 );
    msg.pushUInt32HtoN( 0x01020304 );

    EXPECT_EQ( 4, msg.size() );
    EXPECT_EQ( 0x01, msg[ 0 ] );
    EXPECT_EQ( 0x02, msg[ 1 ] );
    EXPECT_EQ( 0x03, msg[ 2 ] );
    EXPECT_EQ( 0x04, msg[ 3 ] );
}

TEST_F( WireFormatTest, setBuffers_size_1 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 1, data, 4 );

    EXPECT_EQ( 1, msg.header.msg_iovlen );
    EXPECT_EQ( 1, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
}

TEST_F( WireFormatTest, setBuffers_size_2 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 2, data, 4 );

    EXPECT_EQ( 1, msg.header.msg_iovlen );
    EXPECT_EQ( 2, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
}

TEST_F( WireFormatTest, setBuffers_size_3 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 3, data, 4 );

    EXPECT_EQ( 1, msg.header.msg_iovlen );
    EXPECT_EQ( 3, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x03, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 2 ] );
}

TEST_F( WireFormatTest, setBuffers_size_4 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 4, data, 4 );

    EXPECT_EQ( 1, msg.header.msg_iovlen );
    EXPECT_EQ( 4, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x03, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x04, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 3 ] );
}

TEST_F( WireFormatTest, setBuffers_size_5 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 5, data, 4 );

    EXPECT_EQ( 2, msg.header.msg_iovlen );
    EXPECT_EQ( 4, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 1, msg.header.msg_iov[ 1 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x03, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x04, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 3 ] );
    EXPECT_EQ( 0x11, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 0 ] );
}

TEST_F( WireFormatTest, setBuffers_size_8 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 8, data, 4 );

    EXPECT_EQ( 2, msg.header.msg_iovlen );
    EXPECT_EQ( 4, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 4, msg.header.msg_iov[ 1 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x03, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x04, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 3 ] );
    EXPECT_EQ( 0x11, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x12, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x13, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x14, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 3 ] );
}

TEST_F( WireFormatTest, setBuffers_size_9 )
{
    uint8_t data0[] = {
        0x01, 0x02, 0x03, 0x04,
    };
    uint8_t data1[] = {
        0x11, 0x12, 0x13, 0x14,
    };
    uint8_t data2[] = {
        0x21, 0x22, 0x23, 0x24,
    };
    std::vector<uint8_t *> data;
    data.push_back( data0 );
    data.push_back( data1 );
    data.push_back( data2 );

    WireFormat::MessageHeader msg;
    msg.setBuffers( 9, data, 4 );

    EXPECT_EQ( 3, msg.header.msg_iovlen );
    EXPECT_EQ( 4, msg.header.msg_iov[ 0 ].iov_len );
    EXPECT_EQ( 4, msg.header.msg_iov[ 1 ].iov_len );
    EXPECT_EQ( 1, msg.header.msg_iov[ 2 ].iov_len );
    EXPECT_EQ( 0x01, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x02, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x03, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x04, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 0 ].iov_base )[ 3 ] );
    EXPECT_EQ( 0x11, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 0 ] );
    EXPECT_EQ( 0x12, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 1 ] );
    EXPECT_EQ( 0x13, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 2 ] );
    EXPECT_EQ( 0x14, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 1 ].iov_base )[ 3 ] );
    EXPECT_EQ( 0x21, reinterpret_cast<uint8_t *>( msg.header.msg_iov[ 2 ].iov_base )[ 0 ] );
}

TEST_F( WireFormatTest, compare_length_1 )
{
    uint8_t lhs_data[] = {
        0x01, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02, 0x03, 0x04,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_TRUE( lhs < rhs ); 
}

TEST_F( WireFormatTest, compare_length_2 )
{
    uint8_t lhs_data[] = {
        0x01, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02, 0x03,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_FALSE( lhs < rhs ); 
}

TEST_F( WireFormatTest, compare_length_3 )
{
    uint8_t lhs_data[] = {
        0x01, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_FALSE( lhs < rhs ); 
}

TEST_F( WireFormatTest, compare_value_1 )
{
    uint8_t lhs_data[] = {
        0x01, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02, 0x04,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_TRUE( lhs < rhs ); 
}

TEST_F( WireFormatTest, compare_value_2 )
{
    uint8_t lhs_data[] = {
        0x01, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02, 0x02,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_FALSE( lhs < rhs ); 
}

TEST_F( WireFormatTest, compare_value_3 )
{
    uint8_t lhs_data[] = {
        0x02, 0x02, 0x03,
    };
    uint8_t rhs_data[] = {
        0x01, 0x02, 0x04,
    };

    WireFormat lhs( lhs_data, lhs_data + sizeof(lhs_data) );
    WireFormat rhs( rhs_data, rhs_data + sizeof(rhs_data) );

    EXPECT_FALSE( lhs < rhs ); 
}

int main( int argc, char **argv )
{
    ::testing::InitGoogleTest( &argc, argv );
    return RUN_ALL_TESTS();
}
