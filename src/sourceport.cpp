#include "sourceport.hpp"

namespace dns
{

    uint16_t SourcePortGenerator::get()
    {
        if ( fixed_port == 0 ) {
            return distributor( generator );
        }
        return fixed_port;
    }

}
