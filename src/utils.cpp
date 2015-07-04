#include "utils.hpp"
#include "ipv4.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>

const int ERROR_BUFFER_SIZE = 256;

std::string get_error_message( const std::string &msg, int error_number )
{
    char buff[ERROR_BUFFER_SIZE];
    char *err = strerror_r( error_number, buff, sizeof(buff) );
    return msg + "(" + err + ")";
}


uint16_t compute_checksum( const uint8_t *data, size_t length )
{
    unsigned long sum = 0;
    uint16_t *buf = (uint16_t *)data;

    while (length > 1) {
	sum += *buf++;
	length -= 2;
    }
    if (length)
	sum += *(u_int8_t *)buf;

    sum  = (sum & 0xffff) + (sum >> 16);
    sum  = (sum & 0xffff) + (sum >> 16);
	
    return ~sum;
}

in_addr convert_address_string_to_binary( const std::string &str ) throw ( InvalidAddressFormatError )
{
    in_addr address;
    if ( inet_pton( AF_INET, str.c_str(), &address ) > 0 )
	return address;
    else
	throw InvalidAddressFormatError( str + " is invalid IPv4 address" );
}


std::string convert_address_binary_to_string( in_addr bin ) throw ( InvalidAddressFormatError )
{
    char address[16];
    if ( NULL == inet_ntop( AF_INET, &bin, address, sizeof( address ) ) ) {
	throw InvalidAddressFormatError( "cannot convert address from bin to text" );	
    }
    return std::string( address );
}

