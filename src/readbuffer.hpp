#ifndef READ_BUFFER
#define READ_BUFFER

#include <vector>
#include <memory>
#include <arpa/inet.h>
#include "utils.hpp"

class ReadBuffer
{
private:
    PacketData mBuffer;
    unsigned int mPosition;

    template <typename Type>
    Type readUInt()
    {
	if ( mBuffer.size() - mPosition < sizeof(Type) )
	    throw std::runtime_error( "too few buffer remained" );
	
	Type v = *((Type *)( &mBuffer[0] + mPosition ) );
	mPosition += sizeof(Type);
	return v;
    }


public:
    ReadBuffer( const PacketData &buf = PacketData() );
    ReadBuffer( const uint8_t *begin, const uint8_t *end );
    ReadBuffer( const uint8_t *begin, unsigned int size );
    
    uint8_t  readUInt8()  { return readUInt<uint8_t>(); }
    uint16_t readUInt16() { return readUInt<uint16_t>(); }
    uint32_t readUInt32() { return readUInt<uint32_t>(); }
    uint64_t readUInt64() { return readUInt<uint64_t>(); }

    uint16_t readUInt16NtoH();
    uint32_t readUInt32NtoH();
    uint64_t readUInt64NtoH();
    
    unsigned int readBuffer( PacketData &, unsigned int );

    unsigned int getRemainedSize() const;
};

#endif
