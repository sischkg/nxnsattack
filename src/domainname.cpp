#include "domainname.hpp"
#include <cstring>

namespace dns
{
    static uint8_t toLower( uint8_t c )
    {
        if ( 'A' <= c && c <= 'Z' ) {
            return 'a' + c - 'A';
        }
        return c;
    }

    static std::string toLowerLabel( const std::string &label )
    {
        std::string lower_label;
        for ( unsigned int i = 0; i < label.size(); i++ )
            lower_label.push_back( toLower( label[i] ) );
        return lower_label;
    }

    static void stringToLabels( const char *name, std::deque<std::string> &labels )
    {
        labels.clear();

        if ( name == NULL || name[ 0 ] == 0 )
            return;

        unsigned int name_length = std::strlen( name );
        std::string  label;
        for ( unsigned int i = 0; i < name_length; i++ ) {
            if ( name[ i ] == '.' ) {
                labels.push_back( label );
                label = "";
            } else {
                label.push_back( name[ i ] );
            }
        }
        if ( label != "" )
            labels.push_back( label );
    }

    static void canonicalizeLabels( const std::deque<std::string> &from,
                                    std::deque<std::string> &to )
    {
        to.clear();
        for ( unsigned int i = 0; i < from.size(); i++ ) {
            if ( from[ i ].size() == 0 )
                break;
            to.push_back( toLowerLabel( from[i] ) );
        }
    }


    static void outputWireFormat( const std::deque<std::string> labels,
                                  PacketData &message, Offset offset )
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( labels[ i ][ j ] );
        }

        if ( offset == NO_COMPRESSION ) {
            message.push_back( 0 );
        } else {
            message.push_back( 0xC0 | ( uint8_t )( offset >> 8 ) );
            message.push_back( 0xff & (uint8_t)offset );
        }
    }


    static void outputWireFormat( const std::deque<std::string> labels,
                                  WireFormat &message, Offset offset )
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( labels[ i ][ j ] );
        }

        if ( offset == NO_COMPRESSION ) {
            message.push_back( 0 );
        } else {
            message.push_back( 0xC0 | ( uint8_t )( offset >> 8 ) );
            message.push_back( 0xff & (uint8_t)offset );
        }
    }

    Domainname::Domainname( const std::deque<std::string> &l )
        : labels( l )
    {
        canonicalizeLabels( labels, canonical_labels );
    }
    
    Domainname::Domainname( const char *name )
    {
        stringToLabels( name, labels );
        canonicalizeLabels( labels, canonical_labels );
    }

    Domainname::Domainname( const std::string &name )
    {
        stringToLabels( name.c_str(), labels );
        canonicalizeLabels( labels, canonical_labels );
    }

    std::string Domainname::toString() const
    {
        std::string result;
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            result += labels[ i ];
            result += ".";
        }
        return result;
    }

    PacketData Domainname::getPacket( Offset offset ) const
    {
        PacketData bin;
        dns::outputWireFormat( labels, bin, offset );
        return bin;
    }

    void Domainname::outputWireFormat( PacketData &message, Offset offset ) const
    {
        dns::outputWireFormat( labels, message, offset );
    }

    void Domainname::outputWireFormat( WireFormat &message, Offset offset ) const
    {
        dns::outputWireFormat( labels, message, offset );
    }

    PacketData Domainname::getCanonicalWireFormat() const
    {
        PacketData bin;
        dns::outputWireFormat( canonical_labels, bin, NO_COMPRESSION );
        return bin;
    }

    void Domainname::outputCanonicalWireFormat( PacketData &message ) const
    {
        dns::outputWireFormat( canonical_labels, message, NO_COMPRESSION );
    }

    void Domainname::outputCanonicalWireFormat( WireFormat &message ) const
    {
        dns::outputWireFormat( canonical_labels, message, NO_COMPRESSION );
    }

    
    const uint8_t *Domainname::parsePacket( Domainname &   ref_domainname,
                                            const uint8_t *packet_begin,
                                            const uint8_t *packet_end,
                                            const uint8_t *begin,
                                            int            recur )
    {
        if ( recur > 100 ) {
            throw FormatError( "detected domainname decompress loop" );
        }
        if ( packet_begin == packet_end ) {
            throw FormatError( "cannot parse empty data as a domainname" );
        }

        std::string    label;
        const uint8_t *p = begin;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                if ( packet_end - p < 2 ) {
                    throw FormatError( "domainname size is too short for decopression" );
                }
                int offset = ntohs( *( reinterpret_cast<const uint16_t *>( p ) ) ) & 0x0bff;
                if ( packet_begin + offset > p - 2 ) {
                    throw FormatError( "detected forword reference of domainname decompress..." );
                }

                parsePacket( ref_domainname, packet_begin, packet_end, packet_begin + offset, recur + 1 );
                return p + 2;
            }

            if ( packet_end - p < 1 )
                throw FormatError( "domainname size is too short(truncated ?)" );
            uint8_t label_length = *p;
            p++;

            if ( packet_end - p < label_length )
                throw FormatError( "domainname size is too short(truncated ?)" );
            for ( uint8_t i = 0; i < label_length; i++, p++ ) {
                label.push_back( *p );
            }
            ref_domainname.addSuffix( label );
            label = "";
        }

        if ( packet_end - p < 1 )
            throw FormatError( "domainname size is too short(truncated ?)" );
        p++;
        return p;
    }

    unsigned int Domainname::size( Offset offset ) const
    {
	unsigned int size = 0;
	for ( auto &label : labels ) {
	    size += ( 1 + label.size() );
	}
	if ( offset == NO_COMPRESSION )
	    return size + 1;
	else
	    return size + 2;
    }

    Domainname Domainname::operator+( const Domainname &rhs ) const
    {
        Domainname new_domainname = *this;
        new_domainname += rhs;
        return new_domainname;
    }

    Domainname &Domainname::operator+=( const Domainname &rhs )
    {
        labels.insert( labels.end(), rhs.getLabels().begin(), rhs.getLabels().end() );
        canonical_labels.insert( canonical_labels.end(),
                                 rhs.getCanonicalLabels().begin(),
                                 rhs.getCanonicalLabels().end() ); 
       return *this;
    }

    Domainname Domainname::getCanonicalDomainname() const
    {
        return Domainname( getCanonicalLabels() );
    }

    void Domainname::addSubdomain( const std::string &label )
    {
        labels.push_front( label );
        canonical_labels.push_front( toLowerLabel( label ) );
    }

    void Domainname::addSuffix( const std::string &label )
    {
        labels.push_back( label );
        canonical_labels.push_back( toLowerLabel( label ) );
    }


    void Domainname::popSubdomain()
    {
        labels.pop_front();
        canonical_labels.pop_front();
    }

    void Domainname::popSuffix()
    {
        labels.pop_back();
        canonical_labels.pop_back();
    }

    bool Domainname::isSubDomain( const Domainname &child ) const
    {
	auto parent_labels = getCanonicalLabels();
	auto child_labels  = child.getCanonicalLabels();
	if ( child_labels.size() < labels.size() )
	    return false;

	auto parent_label = parent_labels.rbegin();
	auto child_label  = child_labels.rbegin();
	for ( ; parent_label != parent_labels.rend() ; parent_label++, child_label++ ) {
	    if ( *parent_label != *child_label )
		return false;
	}
	return true;
    }

    Domainname Domainname::getRelativeDomainname( const Domainname &child ) const
    {
        if ( ! isSubDomain( child ) )
            throw DomainnameError( child.toString() + "is not sub-domaine of " + toString() + "." );

        Domainname relative;
        unsigned int label_count = child.getLabels().size() - getLabels().size();
        for ( unsigned int i = 0 ; i < label_count ; i++ ) {
            relative.addSuffix( child.getLabels().at( i ) );
        }

        return relative;
    }
    
    std::ostream &operator<<( const Domainname &name, std::ostream &os )
    {
        return os << name.toString();
    }

    std::ostream &operator<<( std::ostream &os, const Domainname &name )
    {
        return os << name.toString();
    }

    bool operator==( const Domainname &lhs, const Domainname &rhs )
    {
        if ( lhs.getCanonicalLabels().size() != rhs.getCanonicalLabels().size() )
            return false;

        for ( unsigned int i = 0; i < lhs.getCanonicalLabels().size(); i++ ) {
	    if ( lhs.getCanonicalLabels().at( i ) != rhs.getCanonicalLabels().at( i ) )
		return false;
        }
        return true;
    }

    bool operator!=( const Domainname &lhs, const Domainname &rhs )
    {
        return !( lhs == rhs );
    }

    bool operator<( const Domainname &lhs, const Domainname &rhs )
    {
	if ( lhs == rhs )
	    return false;

	auto llabel = lhs.getCanonicalLabels().rbegin();
	auto rlabel = rhs.getCanonicalLabels().rbegin();

	for ( ; true ; llabel++, rlabel++ ) {
	    if ( llabel == lhs.getCanonicalLabels().rend() )
		return true;
	    if ( rlabel == rhs.getCanonicalLabels().rend() )
		return false;
	    if ( *llabel == *rlabel )
		continue;
	    return *llabel < *rlabel;
	}
    }

}
