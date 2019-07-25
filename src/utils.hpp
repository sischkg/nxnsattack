#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>
#include <cerrno>
#include <stdexcept>
#include <vector>


namespace FD
{
    typedef unsigned int Event;
    const Event NONE     = 0;
    const Event READABLE = 1;
    const Event WRITABLE = 1<<1;
    const Event ERROR    = 1<<2;
}

typedef std::vector<uint8_t> PacketData;

/*!
 * IPアドレスのテキスト形式をバイナリ形式(in_addr)へ変換できない場合にthrowする例外
 */
class InvalidAddressFormatError : public std::runtime_error
{
public:
    InvalidAddressFormatError( const std::string &msg ) : std::runtime_error( msg )
    {
    }
};

/*!
 * ヘッダに記載されているpayloadの長さが、不正な場合にthrowする例外
 */
class InvalidPayloadLengthError : public std::runtime_error
{
private:
    int length;

public:
    InvalidPayloadLengthError( const std::string &msg, int len ) : std::runtime_error( msg ), length( len )
    {
    }

    int payload_length() const
    {
        return length;
    }
};

/*!
 * Socketの操作に失敗した場合にthrowする例外
 */
class SocketError : public std::runtime_error
{
public:
    SocketError( const std::string &msg ) : std::runtime_error( msg )
    {
    }
};

std::string getErrorMessage( const std::string &msg, int error_number );

in_addr convertAddressStringToBinary( const std::string &str, int address_family = AF_INET );
std::string convertAddressBinaryToString( in_addr bin, int address_family = AF_INET );

char *encodeToBase64( const uint8_t *begin, const uint8_t *end, char *output );
void encodeToBase64( const std::vector<uint8_t> &, std::string & );

uint8_t *decodeFromBase64( const char *begin, const char *end, uint8_t *output );
uint8_t *decodeFromBase64( const char *data, uint8_t *output );
void decodeFromBase64( const std::string &, std::vector<uint8_t> & );

void encodeToBase32Hex( const std::vector<uint8_t> &, std::string & );
void decodeFromBase32Hex( const std::string &, std::vector<uint8_t> & );

uint32_t encodeToBase64Size( const uint8_t *begin, const uint8_t *end );
uint32_t decodeFromBase64Size( const char *begin, const char *end );

void encodeToHex( const std::vector<uint8_t> &src, std::string &dst );
void decodeFromHex( const std::string &src, std::vector<uint8_t> &dst );

std::string printPacketData( const PacketData &p );


void wait_msec( unsigned int msec );

#endif
