#ifndef DOMAINNAME_HPP
#define DOMAINNAME_HPP

#include "wireformat.hpp"
#include <deque>
#include <iostream>
#include <stdexcept>

namespace dns
{
    typedef uint16_t Offset;
    const Offset     NO_COMPRESSION = 0xffff;

    /*!
     * DNS Packetのフォーマットエラーを検知した場合にthrowする例外
     */
    class FormatError : public std::runtime_error
    {
    public:
        FormatError( const std::string &msg ) : std::runtime_error( msg )
        {
        }
    };

    /*!
     * Domainnameの処理に違反した場合にthrowする例外
     */
    class DomainnameError : public std::logic_error
    {
    public:
        DomainnameError( const std::string &msg )
            : std::logic_error( msg )
        {
        }
    };


    class Domainname
    {
    private:
        std::deque<std::string> labels;

    public:
        Domainname( const std::deque<std::string> &l = std::deque<std::string>() ) : labels( l )
        {}

        Domainname( const std::string &name );
        Domainname( const char *name );

        std::string toString() const;

        PacketData getPacket( uint16_t offset = NO_COMPRESSION ) const;
        void outputWireFormat( PacketData &, Offset offset = NO_COMPRESSION ) const;
        void outputWireFormat( WireFormat &, Offset offset = NO_COMPRESSION ) const;

        PacketData getWireFormat( Offset offset = NO_COMPRESSION ) const
        {
            return getPacket( offset );
        }

        PacketData   getCanonicalWireFormat() const;
        void         outputCanonicalWireFormat( PacketData & ) const;
        void         outputCanonicalWireFormat( WireFormat & ) const;

        unsigned int size( Offset offset = NO_COMPRESSION ) const;

        const std::deque<std::string> &getLabels() const
        {
            return labels;
        }

        Domainname  operator+( const Domainname & ) const;
        Domainname &operator+=( const Domainname & );

        void addSubdomain( const std::string & );
        void addSuffix( const std::string & );
	bool isSubDomain( const Domainname &child ) const;	
        Domainname getRelativeDomainname( const Domainname &child ) const;

        Domainname getCanonicalDomainname() const;

        static const uint8_t *parsePacket( Domainname &   ref_domainname,
                                           const uint8_t *packet,
                                           const uint8_t *begin,
                                           int            recur = 0 ) throw( FormatError );
    };

    std::ostream &operator<<( const Domainname &name, std::ostream &os );
    std::ostream &operator<<( std::ostream &os, const Domainname &name );
    bool operator==( const Domainname &lhs, const Domainname &rhs );
    bool operator!=( const Domainname &lhs, const Domainname &rhs );
    bool operator<( const Domainname &lhs, const Domainname &rhs );
}

#endif
