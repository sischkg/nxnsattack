#include "dns.hpp"
#include "udpv4client.hpp"
#include "tcpv4client.hpp"
#include "rrgenerator.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <boost/program_options.hpp>
#include <cstring>
#include <iostream>
#include <time.h>

namespace po = boost::program_options;


int main( int argc, char **argv )
{
    try {
        std::vector<uint8_t> message;
        while ( ! std::cin.eof() ) {
            char c;
            std::cin.get( c );
            message.push_back( c );
        }
    
        dns::PacketInfo msg = dns::parseDNSMessage( &message[0], &message[0] + message.size() );

        std::cout << msg << std::endl;
    }
    catch ( std::runtime_error &e ) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
