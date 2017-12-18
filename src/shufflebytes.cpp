#include "shufflebytes.hpp"
#include "rrgenerator.hpp"

namespace dns
{
    void shuffle( const WireFormat &src, WireFormat &dst )
    {
	uint16_t src_size = src.size();
	dst.clear();
	int r = getRandom( 16 );
	switch( r ) {
	case 0: // insert data
	    {
		std::cerr << "insert data" << std::endl;
 
		uint32_t insert_position = getRandom( src_size );
		uint32_t insert_size     = getRandom( 1024 );
		if ( src_size + insert_size > 0xffff ) {
		    dst = src;
		    break;
		}
		uint32_t i = 0;
		for ( ; i < insert_position ; i++ )
		    dst.push_back( src[i] );
		for ( uint32_t j = 0 ; j < insert_size ; j++ )
		    dst.push_back( getRandom( 0xff ) );
		for ( ; i < src_size ; i++ )
		    dst.push_back( src[i] );
	    }
	    break;
	case 1: // repleace data
	    {
		std::cerr << "replace data" << std::endl;
		uint32_t begin_replace = getRandom( src_size );
		uint32_t end_replace   = getRandom( src_size - begin_replace );
		uint32_t insert_size   = getRandom( 1024 );
		if ( src_size - ( end_replace - begin_replace ) + insert_size > 0xffff ) {
		    dst = src;
		    break;
		}
		for ( uint32_t i = 0 ; i < begin_replace ; i++ )
		    dst.push_back( src[i] );
		for ( uint32_t i = 0 ; i < insert_size ; i++ )
		    dst.push_back( getRandom( 0xff ) );
		for ( uint32_t i = end_replace ; i < src_size ; i++ )
		    dst.push_back( src[i] );
	    }
	    break;
	case 2: // remove data
	    {
		std::cerr << "remove data" << std::endl;
		uint32_t begin_remove = getRandom( src_size );
		uint32_t end_remove   = getRandom( src_size - begin_remove );
		for ( uint32_t i = 0 ; i < begin_remove ; i++ )
		    dst.push_back( src[i] );
		for ( uint32_t i = end_remove ; i < src_size ; i++ )
		    dst.push_back( src[i] );
	    }
	    break;
	default: // not modify
	    {
		std::cerr << "not modified" << std::endl;
		dst = src;
	    }
	}
    }

}
