#include "utils.hpp"
#include "ipv4.hpp"
#include <boost/scoped_array.hpp>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <openssl/md5.h>
#include <sstream>

const int ERROR_BUFFER_SIZE = 256;

std::string get_error_message( const std::string &msg, int error_number )
{
    char  buff[ ERROR_BUFFER_SIZE ];
    char *err = strerror_r( error_number, buff, sizeof( buff ) );
    return msg + "(" + err + ")";
}

uint16_t compute_checksum( const uint8_t *data, size_t length )
{
    unsigned long sum = 0;
    uint16_t *    buf = (uint16_t *)data;

    while ( length > 1 ) {
        sum += *buf++;
        length -= 2;
    }
    if ( length )
        sum += *(u_int8_t *)buf;

    sum = ( sum & 0xffff ) + ( sum >> 16 );
    sum = ( sum & 0xffff ) + ( sum >> 16 );

    return ~sum;
}

in_addr convert_address_string_to_binary( const std::string &str, int address_family ) throw( InvalidAddressFormatError )
{
    in_addr address;
    if ( inet_pton( address_family, str.c_str(), &address ) > 0 )
        return address;
    else
        throw InvalidAddressFormatError( str + " is invalid IPv4 address" );
}

std::string convert_address_binary_to_string( in_addr bin, int address_family ) throw( InvalidAddressFormatError )
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
//  30:              !   "   #   $   %   &   卒
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

char *encode_to_base64( const uint8_t *begin, const uint8_t *end, char *output )
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

void encode_to_base64( const std::vector<uint8_t> &data, std::string &output )
{
    unsigned int encoded_size = encode_to_base64_size( &data[ 0 ], &data[ 0 ] + data.size() );
    if ( encoded_size == 0 ) {
        output = "";
        return;
    }

    boost::scoped_array<char> out( new char[ encoded_size ] );
    encode_to_base64( &data[ 0 ], &data[ 0 ] + data.size(), &out[ 0 ] );
    output.assign( out.get(), encoded_size );
}

uint8_t *decode_from_base64( const char *data, uint8_t *output )
{
    return decode_from_base64( data, data + std::strlen( data ), output );
}

uint8_t *decode_from_base64( const char *begin, const char *end, uint8_t *output )
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

void decode_from_base64( const std::string &data, std::vector<uint8_t> &output )
{
    unsigned int decoded_size = decode_from_base64_size( &data[ 0 ], &data[ 0 ] + data.size() );
    output.resize( decoded_size );
    decode_from_base64( &data[ 0 ], &data[ 0 ] + data.size(), &output[ 0 ] );
}

uint32_t encode_to_base64_size( const uint8_t *begin, const uint8_t *end )
{
    return ( end - begin + 2 ) / 3 * 4;
}

uint32_t decode_from_base64_size( const char *begin, const char *end )
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

//ラウンドごとのローテート量 sを指定する
static uint8_t ROTATE[] = {
    7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 5,  9,  14, 20, 5,  9,
    14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
    4,  11, 16, 23, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
};

//（Kを事前に計算して、テーブルとしておくこともできる）
static uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

// A、B、C、Dの初期値
const uint32_t A0 = 0x67452301;
const uint32_t B0 = 0xefcdab89;
const uint32_t C0 = 0x98badcfe;
const uint32_t D0 = 0x10325476;

static uint32_t left_rotate( uint32_t x, int c )
{
    return ( x << c ) | ( x >> ( 32 - c ) );
}

void md5( const uint8_t *d, uint32_t size, uint8_t result[ 16 ] )
{
    unsigned int new_size;
    if ( size % 512 <= 448 ) {
        new_size = size + ( 512 - size % 512 );
    } else {
        new_size = size + 512 + ( 512 - size % 512 );
    }
    uint32_t *data = new uint32_t[ new_size / 4 ];
    std::memcpy( data, d, size );
    uint8_t *padding_pos = reinterpret_cast<uint8_t *>( data ) + size;
    *padding_pos++       = 0x80;
    while ( padding_pos < reinterpret_cast<uint8_t *>( data ) + new_size - 64 ) {
        *padding_pos++ = 0;
    }
    *reinterpret_cast<uint64_t *>( padding_pos ) = (uint64_t)size;

    uint32_t a0 = A0;
    uint32_t b0 = B0;
    uint32_t c0 = C0;
    uint32_t d0 = D0;

    uint32_t chunk[ 16 ];
    for ( unsigned int j = 0; j < new_size; j += sizeof( chunk ) ) {
        std::memcpy( chunk, data + j, sizeof( chunk ) );

        //内部状態の初期化
        uint32_t a = a0;
        uint32_t b = b0;
        uint32_t c = c0;
        uint32_t d = d0;

        uint32_t f = 0;
        uint32_t g = 0;
        //メインループ
        for ( unsigned int i = 0; i < 64; i++ ) {
            if ( 0 <= 0 && i < 16 ) {
                f = ( b & c ) | ( ~b & d );
                g = i;
            } else if ( 16 <= i && i < 32 ) {
                f = ( d & b ) | ( ~d & c );
                g = ( 5 * i + 1 ) % 16;
            } else if ( 32 <= i && i < 48 ) {
                f = b ^ c ^ d;
                g = ( 3 * i + 5 ) % 16;
            } else if ( 48 <= i && i < 63 ) {
                f = b ^ ( b | ~d );
                g = ( 7 * i ) % 16;
            }

            uint32_t tmp = d;
            d            = c;
            c            = b;
            b            = b + left_rotate( ( a + f + K[ i ] + chunk[ g ] ), ROTATE[ i ] );
            d            = tmp;
        }

        //今までの結果にこのブロックの結果を足す
        a0 += a;
        b0 += b;
        c0 += c;
        d0 += d;
    }

    std::memcpy( result + 0, &a0, sizeof( a0 ) );
    std::memcpy( result + 4, &b0, sizeof( b0 ) );
    std::memcpy( result + 8, &c0, sizeof( c0 ) );
    std::memcpy( result + 12, &d0, sizeof( d0 ) );
}

static void generate_pad( uint8_t pad[ 64 ], uint8_t v )
{
    std::memset( pad, v, sizeof( pad ) / sizeof( uint8_t ) );
}

static void calc_md5( const uint8_t *data, unsigned int size, uint8_t hash[ 16 ] )
{
    MD5_CTX c;
    int     r = MD5_Init( &c );
    if ( r < 0 ) {
        std::runtime_error( "MD5 init error" );
    }

    r = MD5_Update( &c, data, size );
    if ( r < 0 ) {
        std::runtime_error( "MD5 update error" );
    }

    r = MD5_Final( hash, &c );
    if ( r < 0 ) {
        std::runtime_error( "MD5 final error" );
    }
}

void hmac_md5( const uint8_t *data,
               unsigned int   size,
               const uint8_t *k,
               unsigned int   ks,
               uint8_t        result[ 16 ],
               unsigned int   block_size = 64 )
{
    uint8_t ipad[ 64 ], opad[ 64 ];
    generate_pad( ipad, 0x36 );
    generate_pad( opad, 0x5C );

    unsigned int key_size;
    if ( ks % block_size == 0 )
        key_size = ks;
    else
        key_size = ks + ( block_size - ks % block_size );

    uint8_t *key = new uint8_t[ key_size ];
    std::memset( key, 0, size );
    std::memcpy( key, k, ks );

    uint8_t *ipad_key = new uint8_t[ key_size + size ];
    uint8_t *opad_key = new uint8_t[ key_size + 16 ];

    for ( unsigned int i = 0; i < key_size; i++ ) {
        ipad_key[ i ] = key[ i ] ^ ipad[ i ];
        opad_key[ i ] = key[ i ] ^ opad[ i ];
    }
    std::memcpy( ipad_key + key_size, data, size );
    uint8_t ipad_md5[ 16 ];
    calc_md5( ipad_key, size + key_size, ipad_md5 );

    std::memcpy( opad_key + key_size, ipad_md5, sizeof( ipad_md5 ) );
    calc_md5( opad_key, key_size + sizeof( ipad_md5 ), result );
}


void encodeToHex( const std::vector<uint8_t> &src, std::string &dst )
{
    dst.clear();

    if ( src.empty() ) {
	dst = "00";
	return;
    }

    std::ostringstream os;
    os << std::setw( 2 ) << std::setfill( '0' ) << std::hex << std::noshowbase << std::uppercase;
    for ( uint8_t v : src )
	os << (unsigned int)v;
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
