#include "readbuffer.hpp"
#include <algorithm>
#include <endian.h>

ReadBuffer::ReadBuffer( const PacketData &buf )
    : mBuffer( buf ), mPosition( 0 )
{}

ReadBuffer::ReadBuffer( const uint8_t *begin, const uint8_t *end )
    : mBuffer( begin, end ), mPosition( 0 )
{}

ReadBuffer::ReadBuffer( const uint8_t *begin, unsigned int size )
    : mBuffer( begin, begin + size ), mPosition( 0 )
{}


uint16_t ReadBuffer::readUInt16NtoH()
{
    return ntohs( readUInt16() );
}

uint32_t ReadBuffer::readUInt32NtoH()
{
    return ntohl( readUInt32() );
}

uint64_t ReadBuffer::readUInt64NtoH()
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint64_t net = readUInt64();
    return
	( ( 0xff00000000000000 & net ) >> 56 ) +
	( ( 0x00ff000000000000 & net ) >> 40 ) +
	( ( 0x0000ff0000000000 & net ) >> 24 ) +
	( ( 0x000000ff00000000 & net ) >>  8 ) +
	( ( 0x00000000ff000000 & net ) <<  8 ) +
	( ( 0x0000000000ff0000 & net ) << 24 ) +
	( ( 0x000000000000ff00 & net ) << 40 ) +
	( ( 0x00000000000000ff & net ) << 56 );
#else
    return readUInt64();
#endif
}

unsigned int ReadBuffer::readBuffer( PacketData &buf, unsigned int req_size )
{
    unsigned int read_size;
    if ( mPosition >= mBuffer.size() )
	throw std::runtime_error( "Not remained data" );

    unsigned int remained_size = mBuffer.size() - mPosition;
    if ( remained_size > req_size )
	read_size = req_size;
    else
	read_size = remained_size;

    buf.resize( read_size );
    std::copy( &mBuffer[0] + mPosition, &mBuffer[0] + mPosition + read_size, &buf[0] );
    mPosition += read_size;
    return read_size;
}

unsigned int ReadBuffer::getRemainedSize() const
{
    if ( mBuffer.size() < mPosition )
	return 0;
    return mBuffer.size() - mPosition;
}
