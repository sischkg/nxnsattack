#ifndef UTILS_HPP
#define UTILS_HPP

#include <arpa/inet.h>
#include <vector>
#include <stdexcept>
#include <boost/cstdint.hpp>
#include <boost/shared_array.hpp>

typedef std::vector<uint8_t> PacketData;

/*!
 * IPアドレスのテキスト形式をバイナリ形式(in_addr)へ変換できない場合にthrowする例外
 */
class InvalidAddressFormatError : public std::runtime_error
{
public:
    InvalidAddressFormatError( const std::string &msg )
	: std::runtime_error( msg )
    {}
};

/*!
 * ヘッダに記載されているpayloadの長さが、不正な場合にthrowする例外
 */
class InvalidPayloadLengthError : public std::runtime_error
{
private:
    int length;

public:
    InvalidPayloadLengthError( const std::string &msg, int len )
	: std::runtime_error( msg ), length( len )
    {}

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
    SocketError( const std::string &msg )
	: std::runtime_error( msg )
    {}
};


std::string get_error_message( const std::string &msg, int error_number );

uint16_t compute_checksum( const uint8_t *data, size_t length );

in_addr convert_address_string_to_binary( const std::string &str ) throw ( InvalidAddressFormatError );
std::string convert_address_binary_to_string( in_addr bin ) throw ( InvalidAddressFormatError );

#endif
