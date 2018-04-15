#include "utils.hpp"
#include <boost/scoped_array.hpp>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <sstream>

const int ERROR_BUFFER_SIZE = 256;

std::string getErrorMessage( const std::string &msg, int error_number )
{
    char  buff[ ERROR_BUFFER_SIZE ];
    char *err = strerror_r( error_number, buff, sizeof( buff ) );
    return msg + "(" + err + ")";
}


in_addr convertAddressStringToBinary( const std::string &str, int address_family )
{
    in_addr address;
    if ( inet_pton( address_family, str.c_str(), &address ) > 0 )
        return address;
    else
        throw InvalidAddressFormatError( str + " is invalid IPv4 address" );
}

std::string convertAddressBinaryToString( in_addr bin, int address_family )
{
    char address[ 16 ];
    if ( NULL == inet_ntop( address_family, &bin, address, sizeof( address ) ) ) {
        throw InvalidAddressFormatError( "cannot convert address from bin to text" );
    }
    return std::string( address );
}

union Base64Field {
    uint8_t array[ 3 ];
    struct {
        uint8_t b1 : 2;
        uint8_t a1 : 6;
        uint8_t c1 : 4;
        uint8_t b2 : 4;
        uint8_t d1 : 6;
        uint8_t c2 : 2;
    } base64;
    struct {
        uint8_t a : 6;
        uint8_t b : 6;
        uint8_t c : 6;
        uint8_t d : 6;
    } b;
};

//       0   1   2   3   4   5   6   7   8   9
// ---------------------------------------------
//  30:              !   "   #   $   %   &   ´
//  40:  (   )   *   +   ,   -   .   /   0   1
//  50:  2   3   4   5   6   7   8   9   :   ;
//  60:  <   =   >   ?   @   A   B   C   D   E
//  70:  F   G   H   I   J   K   L   M   N   O
//  80:  P   Q   R   S   T   U   V   W   X   Y
//  90:  Z   [   \   ]   ^   _   `   a   b   c
// 100:  d   e   f   g   h   i   j   k   l   m
// 110:  n   o   p   q   r   s   t   y   v   w
// 120:  x   y   z   {   |   }   ~
//

//
// 0x00    A    0x10    Q    0x20    g    0x30    w
// 0x01    B    0x11    R    0x21    h    0x31    x
// 0x02    C    0x12    S    0x22    i    0x32    y
// 0x03    D    0x13    T    0x23    j    0x33    z
// 0x04    E    0x14    U    0x24    k    0x34    0
// 0x05    F    0x15    V    0x25    l    0x35    1
// 0x06    G    0x16    W    0x26    m    0x36    2
// 0x07    H    0x17    X    0x27    n    0x37    3
// 0x08    I    0x18    Y    0x28    o    0x38    4
// 0x09    J    0x19    Z    0x29    p    0x39    5
// 0x0a    K    0x1a    a    0x2a    q    0x3a    6
// 0x0b    L    0x1b    b    0x2b    r    0x3b    7
// 0x0c    M    0x1c    c    0x2c    s    0x3c    8
// 0x0d    N    0x1d    d    0x2d    t    0x3d    9
// 0x0e    O    0x1e    e    0x2e    u    0x3e    +
// 0x0f    P    0x1f    f    0x2f    v    0x3f    /

static const char *to_base64     = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static uint8_t     from_base64[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 10
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 20
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 30
    0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, // 40 0 - 1
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, // 50 2 - 9
    0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, // 60 A - E
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // 70 F - O
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // 80 P - Y
    0x19, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b, 0x1c, // 90 Z a - c
    0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, // 100 d - m
    0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, // 110 n - w
    0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 120 x - z
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 130
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 140
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 150
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 160
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 170
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 180
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 190
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 200
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 210
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 220
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 230
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 240
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff                          // 250
};

static uint8_t convert_from_base64( char c )
{
    uint8_t d = from_base64[ (uint8_t)c ];
    if ( d == 0xff ) {
        std::ostringstream os;
        os << "invalid base64 data \"" << c << "\"";
        throw std::runtime_error( os.str() );
    }
    return d;
}

//   +--first octet--+-second octet--+--third octet--+
//   |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
//   +-----------+---+-------+-------+---+-----------+
//   |5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|5 4 3 2 1 0|
//   +--1.index--+--2.index--+--3.index--+--4.index--+

char *encodeToBase64( const uint8_t *begin, const uint8_t *end, char *output )
{
    const uint8_t *pos = begin;
    while ( pos + 2 < end ) {
        Base64Field field;
        field.array[ 0 ] = *pos++;
        field.array[ 1 ] = *pos++;
        field.array[ 2 ] = *pos++;

        *output++ = to_base64[ field.base64.a1 ];
        *output++ = to_base64[ ( field.base64.b1 << 4 ) + ( field.base64.b2 << 0 ) ];
        *output++ = to_base64[ ( field.base64.c1 << 2 ) + ( field.base64.c2 << 0 ) ];
        *output++ = to_base64[ field.base64.d1 ];
    }
    if ( pos + 1 == end ) {
        Base64Field field;
        field.array[ 0 ] = *pos++;
        field.array[ 1 ] = 0;
        field.array[ 2 ] = 0;

        *output++ = to_base64[ field.base64.a1 ];
        *output++ = to_base64[ ( field.base64.b1 << 4 ) + ( field.base64.b2 << 0 ) ];
        *output++ = '=';
        *output++ = '=';
    }
    if ( pos + 2 == end ) {
        Base64Field field;
        field.array[ 0 ] = *pos++;
        field.array[ 1 ] = *pos++;
        field.array[ 2 ] = 0;

        *output++ = to_base64[ field.base64.a1 ];
        *output++ = to_base64[ ( field.base64.b1 << 4 ) + ( field.base64.b2 << 0 ) ];
        *output++ = to_base64[ ( field.base64.c1 << 2 ) + ( field.base64.c2 << 0 ) ];
        *output++ = '=';
    }
    return output;
}

void encodeToBase64( const std::vector<uint8_t> &data, std::string &output )
{
    unsigned int encoded_size = encodeToBase64Size( &data[ 0 ], &data[ 0 ] + data.size() );
    if ( encoded_size == 0 ) {
        output = "";
        return;
    }

    boost::scoped_array<char> out( new char[ encoded_size ] );
    encodeToBase64( &data[ 0 ], &data[ 0 ] + data.size(), &out[ 0 ] );
    output.assign( out.get(), encoded_size );
}

uint8_t *decodeFromBase64( const char *data, uint8_t *output )
{
    return decodeFromBase64( data, data + std::strlen( data ), output );
}

uint8_t *decodeFromBase64( const char *begin, const char *end, uint8_t *output )
{
    if ( ( end - begin ) % 4 != 0 ) {
        throw std::runtime_error( "invalid base64 string length" );
    }
    if ( begin == end ) {
        return output;
    }

    const char *pos = begin;
    while ( pos + 4 < end ) {
        *output++ = ( convert_from_base64( *( pos + 0 ) ) << 2 ) + ( convert_from_base64( *( pos + 1 ) ) >> 4 );
        *output++ = ( convert_from_base64( *( pos + 1 ) ) << 4 ) + ( convert_from_base64( *( pos + 2 ) ) >> 2 );
        *output++ = ( convert_from_base64( *( pos + 2 ) ) << 6 ) + ( convert_from_base64( *( pos + 3 ) ) & 0x3f );
        pos += 4;
    }
    if ( *( end - 3 ) == '=' ) {
        throw std::runtime_error( "invalid base64 string" );
    } else if ( *( end - 2 ) == '=' ) {
        *output++ = ( convert_from_base64( *( pos + 0 ) ) << 2 ) + ( convert_from_base64( *( pos + 1 ) ) >> 4 );
    } else if ( *( end - 1 ) == '=' ) {
        *output++ = ( convert_from_base64( *( pos + 0 ) ) << 2 ) + ( convert_from_base64( *( pos + 1 ) ) >> 4 );
        *output++ = ( convert_from_base64( *( pos + 1 ) ) << 4 ) + ( convert_from_base64( *( pos + 2 ) ) >> 2 );
    } else {
        *output++ = ( convert_from_base64( *( pos + 0 ) ) << 2 ) + ( convert_from_base64( *( pos + 1 ) ) >> 4 );
        *output++ = ( convert_from_base64( *( pos + 1 ) ) << 4 ) + ( convert_from_base64( *( pos + 2 ) ) >> 2 );
        *output++ = ( convert_from_base64( *( pos + 2 ) ) << 6 ) + ( convert_from_base64( *( pos + 3 ) ) & 0x3f );
    }

    return output;
}

void decodeFromBase64( const std::string &data, std::vector<uint8_t> &output )
{
    unsigned int decoded_size = decodeFromBase64Size( &data[ 0 ], &data[ 0 ] + data.size() );
    output.resize( decoded_size );
    decodeFromBase64( &data[ 0 ], &data[ 0 ] + data.size(), &output[ 0 ] );
}

uint32_t encodeToBase64Size( const uint8_t *begin, const uint8_t *end )
{
    return ( end - begin + 2 ) / 3 * 4;
}

uint32_t decodeFromBase64Size( const char *begin, const char *end )
{
    if ( ( end - begin ) % 4 != 0 ) {
        throw std::range_error( "invalid base64 string length" );
    }
    if ( begin == end )
        return 0;
    if ( *( end - 2 ) == '=' ) {
        return ( end - begin - 4 ) / 4 * 3 + 1;
    }
    if ( *( end - 1 ) == '=' ) {
        return ( end - begin - 4 ) / 4 * 3 + 2;
    } else {
        return ( end - begin ) / 4 * 3;
    }
}


void encodeToHex( const std::vector<uint8_t> &src, std::string &dst )
{
    dst.clear();

    if ( src.empty() ) {
	dst = "00";
	return;
    }

    std::ostringstream os;
    for ( uint8_t v : src ) {
        os << std::setw( 2 ) << std::setfill( '0' ) << std::hex << std::noshowbase << std::uppercase;
	os << (unsigned int)v;
    }
    dst = os.str();
}

void decodeFromHex( const std::string &src, std::vector<uint8_t> &dst )
{
    dst.clear();
    if ( src.empty() ) {
	dst.push_back( 0 );
	return;
    }
    if ( src.size() % 2 == 1 ) {
	std::ostringstream os;
	os << "string length of \"" << src << "\" must be event.";
	throw std::runtime_error( os.str() );
    }
    
    std::string octet_str;

    for ( char digit : src ) {
	if ( '0' <= digit && digit <= '9' ||
	     'a' <= digit && digit <= 'f' ||
	     'A' <= digit && digit <= 'F' ) {

	    octet_str.push_back( digit );
	    if ( octet_str.size() == 2 ) {
		std::istringstream is( octet_str );
		uint16_t octet;

		is >> std::hex >> octet;
		dst.push_back( octet );
		octet_str.clear();
	    }
	}
	else {
	    std::ostringstream os;
	    os << "bad character \"" << digit << "\" in \"" << src << "\".";
	    throw std::runtime_error( os.str() );
	}
    }
}

std::string printPacketData( const PacketData &p )
{
    std::ostringstream os;
    os << std::hex << std::setw( 2 ) << std::setfill( '0' );
    for ( unsigned int i = 0; i < p.size(); i++ ) {
        os << (unsigned int)p[ i ] << ",";
    }

    return os.str();
}


//   +--first octet--+-second octet--+--third octet--+-fourth octet--+--fifth octet--+
//   |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
//   +---------+-----+---+---------+-+-------+-------+-+---------+---+-----+---------+
//   |4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|
//   +-1.index-+-2.index-+-3.index-+-4.index-+-5.index-+-6.index-+-7.index-+-8.index-|
//   +    a1   | b1  |b2 |    c1   |d1| d2   |  e1  |e2| f1      | g1| g2  |  h1     |
//   +---------+-----+---+---------+--+------+------+--+---------+---+-----+---------+

union Base32Field {
    Base32Field()
    {
        std::memset( array, sizeof(array), 0 );
    }
    uint8_t array[ 5 ];
    struct {
        uint8_t b1 : 3;
        uint8_t a1 : 5;
	uint8_t b2 : 2;
        uint8_t c1 : 5;
        uint8_t d1 : 1;
        uint8_t d2 : 4;
        uint8_t e1 : 4;
        uint8_t e2 : 1;
        uint8_t f1 : 5;
        uint8_t g1 : 2;
        uint8_t g2 : 3;
        uint8_t h1 : 5;
    } base32;
    struct {
        uint8_t a : 5;
        uint8_t b : 5;
        uint8_t c : 5;
        uint8_t d : 5;
        uint8_t e : 5;
        uint8_t f : 5;
        uint8_t g : 5;
        uint8_t h : 5;
    } b;
};

static const char to_base32_hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

static char convertToBase32Hex( uint8_t v )
{
    if ( v >= sizeof(to_base32_hex) ) {
        std::ostringstream os;
        os << "invalid base32 data \"" << (int)v << "\"";
        throw std::logic_error( os.str() );
    }

    return to_base32_hex[ v ];
}

void encodeToBase32Hex( const std::vector<uint8_t> &src, std::string &dst )
{
    dst.clear();

    const uint8_t *pos = &src[0];
    const uint8_t *end = &src[0] + src.size();
    
    while ( pos + 4 < end ) {
        uint8_t array[5];
        array[ 0 ] = *pos++;
        array[ 1 ] = *pos++;
        array[ 2 ] = *pos++;
        array[ 3 ] = *pos++;
        array[ 4 ] = *pos++;

        dst.push_back( convertToBase32Hex( ( array[0] >> 3 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x07 & array[0] ) << 2 ) + ( array[1] >> 6 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x3f & array[1] ) >> 1 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x01 & array[1] ) << 4 ) + ( array[2] >> 4 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x0f & array[2] ) << 1 ) + ( array[3] >> 7 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x7f & array[3] ) >> 2 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x03 & array[3] ) << 3 ) + ( array[4] >> 5 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x1f & array[4] ) >> 0 ) ) );
    }
    if ( pos + 4 == end ) {
        uint8_t array[5];
        array[ 0 ] = *pos++;
        array[ 1 ] = *pos++;
        array[ 2 ] = *pos++;
        array[ 3 ] = *pos++;
        array[ 4 ] = 0;

        dst.push_back( convertToBase32Hex( ( array[0] >> 3 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x07 & array[0] ) << 2 ) + ( array[1] >> 6 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x3f & array[1] ) >> 1 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x01 & array[1] ) << 4 ) + ( array[2] >> 4 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x0f & array[2] ) << 1 ) + ( array[3] >> 7 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x7f & array[3] ) >> 2 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x03 & array[3] ) << 3 ) + ( array[4] >> 5 ) ) );
    }
    if ( pos + 3 == end ) {   
        uint8_t array[4];
        array[ 0 ] = *pos++;
        array[ 1 ] = *pos++;
        array[ 2 ] = *pos++;
        array[ 3 ] = 0;

        dst.push_back( convertToBase32Hex( ( array[0] >> 3 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x07 & array[0] ) << 2 ) + ( array[1] >> 6 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x3f & array[1] ) >> 1 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x01 & array[1] ) << 4 ) + ( array[2] >> 4 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x0f & array[2] ) << 1 ) + ( array[3] >> 7 ) ) );
    }
    if ( pos + 2 == end ) {
        uint8_t array[3];
        array[ 0 ] = *pos++;
        array[ 1 ] = *pos++;
        array[ 2 ] = 0;

        dst.push_back( convertToBase32Hex( ( array[0] >> 3 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x07 & array[0] ) << 2 ) + ( array[1] >> 6 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x3f & array[1] ) >> 1 ) ) );
	dst.push_back( convertToBase32Hex( ( ( 0x01 & array[1] ) << 4 ) + ( array[2] >> 4 ) ) );
    }
    if ( pos + 1 == end ) {
        uint8_t array[2];
        array[ 0 ] = *pos++;
        array[ 1 ] = 0;

        dst.push_back( convertToBase32Hex( ( array[0] >> 3 ) ) );
        dst.push_back( convertToBase32Hex( ( ( 0x07 & array[0] ) << 2 ) + ( array[1] >> 6 ) ) );
    }
}

static uint8_t  from_base32_hex[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 0
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 10
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 20
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 30
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, // 40 0 - 1
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, // 50 2 - 9
    0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, // 60 A - E
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // 70 F - O
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, // 80 P - V
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 90
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 100
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 110
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 120
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 130
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 140
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 150
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 160
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 170
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 180
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 190
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 200
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 210
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 220
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 230
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // 240
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff                          // 250
};

static uint8_t convertFromBase32Hex( char c )
{
    uint8_t d = from_base32_hex[ (uint8_t)c ];
    if ( d == 0xff ) {
        std::ostringstream os;
        os << "invalid base32 data \'" << (uint32_t)c << "\'";
        throw std::runtime_error( os.str() );
    }
    return d;
}


void decodeFromBase32Hex( const std::string &src, std::vector<uint8_t> &dst )
{
    dst.clear();
    if ( src.size() == 0 ) {
        return;
    }
    
    const char *begin = src.c_str();
    const char *end   = begin + src.size();
    const char *pos   = begin;

    //   +--first octet--+-second octet--+--third octet--+-fourth octet--+--fifth octet--+
    //   |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
    //   +---------+-----+---+---------+-+-------+-------+-+---------+---+-----+---------+
    //   |4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|4 3 2 1 0|
    //   +-1.index-+-2.index-+-3.index-+-4.index-+-5.index-+-6.index-+-7.index-+-8.index-|
    //   +    a1   | b1  |b2 |    c1   |d1| d2   |  e1  |e2| f1      | g1| g2  |  h1     |
    //   +---------+-----+---+---------+--+------+------+--+---------+---+-----+---------+
    while ( pos + 7 < end ) {
        dst.push_back( ( convertFromBase32Hex( *( pos + 0 ) ) << 3 ) + ( convertFromBase32Hex( *( pos + 1 ) ) >> 2 ) );
        dst.push_back( ( convertFromBase32Hex( *( pos + 1 ) ) << 6 ) + ( convertFromBase32Hex( *( pos + 2 ) ) << 1 ) + ( convertFromBase32Hex( *( pos + 3 ) ) >> 4 ) );
        dst.push_back( ( convertFromBase32Hex( *( pos + 3 ) ) << 4 ) + ( convertFromBase32Hex( *( pos + 4 ) ) >> 1 ) );
        dst.push_back( ( convertFromBase32Hex( *( pos + 4 ) ) << 7 ) + ( convertFromBase32Hex( *( pos + 5 ) ) << 2 ) + ( convertFromBase32Hex( *( pos + 6 ) ) >> 3 ) );
        dst.push_back( ( convertFromBase32Hex( *( pos + 6 ) ) << 5 ) + ( convertFromBase32Hex( *( pos + 7 ) )      ) );
        pos += 8;
    }

    if ( pos + 2 <= end ) {
        dst.push_back( ( convertFromBase32Hex( *( pos + 0 ) ) << 3 ) + ( convertFromBase32Hex( *( pos + 1 ) ) >> 2 ) );
        pos += 1;
    }
    if ( pos + 3 <= end ) {
        dst.push_back( ( convertFromBase32Hex( *( pos + 0 ) ) << 6 ) + ( convertFromBase32Hex( *( pos + 1 ) ) << 1 ) + ( convertFromBase32Hex( *( pos + 2 ) ) >> 4 ) );
        pos += 2;
    }
    if ( pos + 2 <= end ) {
        dst.push_back( ( convertFromBase32Hex( *( pos + 0 ) ) << 4 ) + ( convertFromBase32Hex( *( pos + 1 ) ) >> 1 ) );
        pos += 1;
    }
    if ( pos + 3 <= end ) {
        dst.push_back( ( convertFromBase32Hex( *( pos + 0 ) ) << 7 ) + ( convertFromBase32Hex( *( pos + 1 ) ) << 2 ) + ( convertFromBase32Hex( *( pos + 2 ) ) >> 3 ) );
        pos += 3;
    }
}
