#ifndef UTILS_HPP
#define UTILS_HPP

#include <boost/shared_array.hpp>

boost::shared_array<uint8_t> compute_checksum( const uint8_t *data, size_t length );

#endif
