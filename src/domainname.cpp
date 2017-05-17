#include "domainname.hpp"
#include <cstring>

namespace dns
{

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

    static uint8_t toLower( uint8_t c )
    {
        if ( 'A' <= c && c <= 'Z' ) {
            return 'a' + c - 'A';
        }
        return c;
    }

    static bool equalLabel( const std::string &lhs, const std::string &rhs )
    {
	if ( lhs.size() != rhs.size() )
	    return false;

	auto l = lhs.begin();
	auto r = rhs.begin();
	for ( ; l != lhs.end() ; ++l, ++r )
	    if ( toLower( *l ) != toLower( *r ) )
		return false;
	return true;
    }
    
    Domainname::Domainname( const char *name )
    {
        stringToLabels( name, labels );
    }

    Domainname::Domainname( const std::string &name )
    {
        stringToLabels( name.c_str(), labels );
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

        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            bin.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                bin.push_back( labels[ i ][ j ] );
        }

        if ( offset == NO_COMPRESSION ) {
            bin.push_back( 0 );
            return bin;
        } else {
            bin.push_back( 0xC0 | ( uint8_t )( offset >> 8 ) );
            bin.push_back( 0xff & (uint8_t)offset );
        }

        return bin;
    }

    void Domainname::outputWireFormat( PacketData &message, Offset offset ) const
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

    void Domainname::outputWireFormat( WireFormat &message, Offset offset ) const
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

    PacketData Domainname::getCanonicalWireFormat() const
    {
        PacketData bin;

        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            bin.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                bin.push_back( toLower( labels[ i ][ j ] ) );
        }
        bin.push_back( 0 );

        return bin;
    }

    void Domainname::outputCanonicalWireFormat( PacketData &message ) const
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( toLower( labels[ i ][ j ] ) );
        }
        message.push_back( 0 );
    }

    void Domainname::outputCanonicalWireFormat( WireFormat &message ) const
    {
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            message.push_back( labels[ i ].size() );
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                message.push_back( toLower( labels[ i ][ j ] ) );
        }
        message.push_back( 0 );
    }

    
    const uint8_t *Domainname::parsePacket( Domainname &   ref_domainname,
                                            const uint8_t *packet,
                                            const uint8_t *begin,
                                            int            recur ) throw( FormatError )
    {
        if ( recur > 100 ) {
            throw FormatError( "detected domainname decompress loop" );
        }

        std::string    label;
        const uint8_t *p = begin;
        while ( *p != 0 ) {
            // メッセージ圧縮を行っている場合
            if ( *p & 0xC0 ) {
                int offset = ntohs( *( reinterpret_cast<const uint16_t *>( p ) ) ) & 0x0bff;
                if ( packet + offset > begin - 2 ) {
                    throw FormatError( "detected forword reference of domainname decompress..." );
                }

                parsePacket( ref_domainname, packet, packet + offset, recur + 1 );
                return p + 2;
            }

            uint8_t label_length = *p;
            p++;
            for ( uint8_t i = 0; i < label_length; i++, p++ ) {
                label.push_back( *p );
            }
            ref_domainname.addSuffix( label );
            label = "";
        }

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
        return *this;
    }

    Domainname Domainname::getCanonicalDomainname() const
    {
        Domainname canonical( "." );
        for ( unsigned int i = 0; i < labels.size(); i++ ) {
            if ( labels[ i ].size() == 0 )
                break;
            std::string label;
            for ( unsigned int j = 0; j < labels[ i ].size(); j++ )
                label.push_back( toLower( labels[ i ][ j ] ) );
            canonical.addSuffix( label );
        }        
        return canonical;
    }

    void Domainname::addSubdomain( const std::string &label )
    {
        labels.push_front( label );
    }

    void Domainname::addSuffix( const std::string &label )
    {
        labels.push_back( label );
    }

    bool Domainname::isSubDomain( const Domainname &child ) const
    {
	auto parent_labels = getLabels();
	auto child_labels  = child.getLabels();
	if ( child_labels.size() < labels.size() )
	    return false;

	auto parent_label = parent_labels.rbegin();
	auto child_label  = child_labels.rbegin();
	for ( ; parent_label != parent_labels.rend() ; parent_label++, child_label++ ) {
	    if ( ! equalLabel( *parent_label, *child_label ) )
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
        if ( lhs.getLabels().size() != rhs.getLabels().size() )
            return false;

        for ( unsigned int i = 0; i < lhs.getLabels().size(); i++ ) {
	    if ( ! equalLabel( lhs.getLabels().at( i ), rhs.getLabels().at( i ) ) )
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

	auto lname = lhs.getCanonicalDomainname();
	auto rname = rhs.getCanonicalDomainname();

	auto llabel = lname.getLabels().rbegin();
	auto rlabel = rname.getLabels().rbegin();

	while ( true ) {
	    if ( llabel == lname.getLabels().rend() )
		return true;
	    if ( rlabel == rname.getLabels().rend() )
		return false;
	    if ( *llabel == *rlabel )
		continue;
	    return *llabel < *rlabel;
	}
    }

}
