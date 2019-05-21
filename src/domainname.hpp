#ifndef DOMAINNAME_HPP
#define DOMAINNAME_HPP

#include "wireformat.hpp"
#include <deque>
#include <map>
#include <iostream>
#include <stdexcept>
#include <boost/operators.hpp>

namespace dns
{
    class OffsetDB;

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



    class Domainname : public boost::less_than_comparable<Domainname>
    {
    private:
        std::deque<std::string> labels;
        std::deque<std::string> canonical_labels;

    public:
        Domainname( const std::deque<std::string> &l = std::deque<std::string>() );
        explicit Domainname( const std::string &name );
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
        const std::deque<std::string> &getCanonicalLabels() const
        {
            return canonical_labels;
        }
        const uint32_t getLabelCount() const
        {
            return labels.size();
        }

        Domainname  operator+( const Domainname & ) const;
        Domainname &operator+=( const Domainname & );

        void addSubdomain( const std::string & );
        void addSuffix( const std::string & );
        void pushSubdomain( const std::string &label ) { addSubdomain( label ); }
        void pushSuffix( const std::string &label ) { addSuffix( label ); }
	bool isSubDomain( const Domainname &child ) const;	
        Domainname getRelativeDomainname( const Domainname &child ) const;

        void popSubdomain();
        void popSuffix();

        Domainname getCanonicalDomainname() const;

        static const uint8_t *parsePacket( Domainname &   ref_domainname,
                                           const uint8_t *packet_begin,
                                           const uint8_t *packet_end,
                                           const uint8_t *begin,
                                           int            recur = 0 );

        bool operator==( const Domainname &rhs ) const;
        bool operator!=( const Domainname &rhs ) const;
        bool operator<( const Domainname &rhs ) const;

    };

    std::ostream &operator<<( const Domainname &name, std::ostream &os );
    std::ostream &operator<<( std::ostream &os, const Domainname &name );

    bool operator==( const std::string &lhs, const Domainname &rhs );
    bool operator!=( const std::string &lhs, const Domainname &rhs );
    bool operator<( const std::string &lhs, const Domainname &rhs );

    class OffsetDB
    {
    private:
        typedef std::map<Domainname,uint16_t>   OffsetContainer;
        typedef OffsetContainer::const_iterator OffsetContainerIterator;

        OffsetContainer mOffsets;

        uint16_t findDomainname( const Domainname &name ) const;
        void add( const Domainname &name, uint32_t offset );
    public:
        const uint32_t NOT_FOUND = 0xffff;

        uint32_t outputWireFormat( const Domainname &, WireFormat & );
        uint32_t getOutputWireFormatSize( const Domainname &, uint32_t begin );
    };


}

#endif
