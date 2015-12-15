#include "wireformat.hpp"

WireFormat::WireFormat( uint16_t buffer_size )
    : mBufferSize( buffer_size ), mEnd( 0 )
{}

WireFormat::~WireFormat()
{
    for ( auto i = mBuffers.begin() ; i != mBuffers.end() ; ++i ) {
	delete [] *i;
    }
}


