#include "wireformat.hpp"
#include "utils.hpp"
#include <cstring>

WireFormat::WireFormat( uint16_t buffer_size ) : mBufferSize( buffer_size ), mEnd( 0 )
{
}

WireFormat::WireFormat( const std::vector<uint8_t> &data, uint16_t buffer_size ) : mBufferSize( buffer_size ), mEnd( 0 )
{
    for ( auto i = data.begin(); i != data.end(); i++ ) {
        push_back( *i );
    }
}

WireFormat::WireFormat( const uint8_t *begin, const uint8_t *end, uint16_t buffer_size )
    : mBufferSize( buffer_size ), mEnd( 0 )
{
    for ( auto i = begin; i != end; i++ ) {
        push_back( *i );
    }
}

WireFormat::~WireFormat()
{
    clear();
}

void WireFormat::clear()
{
    for ( auto i = mBuffers.begin(); i != mBuffers.end(); ++i ) {
        delete[] * i;
    }
    mBuffers.resize( 0 );
    mEnd = 0;
}

uint16_t WireFormat::send( int fd, const sockaddr *dest, socklen_t dest_length, int flags ) const
    throw( std::runtime_error )
{
    if ( mEnd == 0 )
        return 0;

    MessageHeader msg;
    msg.setDestination( dest, dest_length );
    msg.setBuffers( mEnd, mBuffers, mBufferSize );

retry:
    uint16_t sent_size = sendmsg( fd, &msg.header, flags );
    if ( sent_size < 0 ) {
        if ( errno == EINTR || errno == EAGAIN )
            goto retry;
        else {
            throw SocketError( get_error_message( "cannot write data to peer", errno ) );
        }
    }

    return sent_size;
}

std::vector<uint8_t> WireFormat::get() const
{
    std::vector<uint8_t> ret;
    ret.resize( size() );

    for ( unsigned int i = 0; i < mEnd; i++ ) {
        ret[ i ] = at( i );
    }

    return ret;
}

WireFormat::MessageHeader::MessageHeader()
{
    std::memset( &header, 0, sizeof( header ) );
}

WireFormat::MessageHeader::~MessageHeader()
{
    delete[] header.msg_iov;
}

void WireFormat::MessageHeader::setBuffers( uint16_t size, const std::vector<uint8_t *> buffers, uint16_t buffer_size )
{
    unsigned int buffer_count = ( size - 1 ) / buffer_size + 1;
    unsigned int last_buffer  = ( size - 1 ) / buffer_size;

    header.msg_iov    = new iovec[ buffer_count ];
    header.msg_iovlen = buffer_count;

    for ( unsigned int i = 0; i < last_buffer; i++ ) {
        header.msg_iov[ i ].iov_base = const_cast<uint8_t *>( buffers[ i ] );
        header.msg_iov[ i ].iov_len  = buffer_size;
    }
    header.msg_iov[ last_buffer ].iov_base = const_cast<uint8_t *>( buffers[ last_buffer ] );
    if ( size % buffer_size == 0 )
        header.msg_iov[ last_buffer ].iov_len = buffer_size;
    else
        header.msg_iov[ last_buffer ].iov_len = size % buffer_size;
}

void WireFormat::MessageHeader::setDestination( const sockaddr *dest, uint16_t len )
{
    if ( dest != nullptr ) {
        header.msg_name    = const_cast<sockaddr *>( dest );
        header.msg_namelen = len;
    } else {
        header.msg_name    = nullptr;
        header.msg_namelen = 0;
    }

    header.msg_control    = nullptr;
    header.msg_controllen = 0;
    header.msg_flags      = 0;
}
