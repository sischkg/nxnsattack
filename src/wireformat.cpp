#include "wireformat.hpp"
#include "utils.hpp"

WireFormat::WireFormat( uint16_t buffer_size )
    : mBufferSize( buffer_size ), mEnd( 0 )
{}

WireFormat::WireFormat( const std::vector<uint8_t> &data, uint16_t buffer_size )
    : mBufferSize( buffer_size ), mEnd( 0 )
{
    for ( auto i = data.begin() ; i != data.end() ; i++ ) {
	push_back( *i );
    }
}


WireFormat::~WireFormat()
{
    clear();
}

void WireFormat::clear()
{
    for ( auto i = mBuffers.begin() ; i != mBuffers.end() ; ++i ) {
	delete [] *i;
    }
    mBuffers.resize( 0 );
    mEnd = 0;
}

uint16_t WireFormat::send( int fd, const sockaddr *dest, socklen_t dest_length, int flags ) const throw( std::runtime_error)
{
    if ( mEnd == 0 )
	return 0;

    unsigned int buffer_count = ( mEnd - 1 ) / mBufferSize + 1;
    unsigned int last_buffer  = ( mEnd - 1 ) / mBufferSize;
    msghdr hdr;

    if ( dest != nullptr ) {
        hdr.msg_name    = const_cast<sockaddr *>( dest );
        hdr.msg_namelen = dest_length;
    }
    else {
        hdr.msg_name = nullptr;
        hdr.msg_namelen = 0;
    }

    hdr.msg_control    = nullptr;
    hdr.msg_controllen = 0;
    hdr.msg_flags      = 0;

    hdr.msg_iov    = new iovec[ buffer_count ];
    hdr.msg_iovlen = buffer_count;
    
    for ( unsigned int i = 0 ; i < last_buffer ; i++ ) {
        iovec iov;
        iov.iov_base = mBuffers[i];
        iov.iov_len  = mBufferSize;
        hdr.msg_iov[i] = iov;
    }
    hdr.msg_iov[last_buffer].iov_base = mBuffers[last_buffer];
    if ( mEnd % mBufferSize == 0 )
	hdr.msg_iov[last_buffer].iov_len  = mBufferSize;
    else
	hdr.msg_iov[last_buffer].iov_len  = mEnd % mBufferSize;

    uint16_t sent_size = sendmsg( fd, &hdr, flags );
    if ( sent_size < 0 ) {
	throw std::runtime_error( get_error_message( "cannot sent packet", errno ) );
    }

    return sent_size;
}

std::vector<uint8_t> WireFormat::get() const
{
    std::vector<uint8_t> ret;
    ret.resize( size() );

    for ( unsigned int i = 0 ; i < mEnd ; i++ ) {
	ret[i] = at( i );
    }

    return ret;
}
