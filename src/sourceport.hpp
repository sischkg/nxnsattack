#ifndef SOURCEPORt_HPP
#define SOURCEPORT_HPP

#include <boost/random.hpp>

namespace dns
{
    class SourcePortGenerator
    {
    private:
        uint16_t                                  fixed_port;
        boost::random::mt19937                    generator;
        boost::random::uniform_int_distribution<> distributor;

    public:
        SourcePortGenerator( uint16_t sp = 0 ) : fixed_port( sp ), distributor( 1024, 65535 )
        {
        }

        uint16_t get();
    };
}

#endif
