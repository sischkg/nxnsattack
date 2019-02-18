#include "logger.hpp"
#include <stdexcept>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/utility/setup/console.hpp>

namespace dns
{
    namespace logger
    {
	Level toLevel( const std::string &level )
	{
	    if ( level == "trace" )
		return TRACE;
	    if ( level == "debug" )
		return DEBUG;
	    if ( level == "info" )
		return INFO;
	    if ( level == "warning" )
		return WARNING;
	    if ( level == "error" )
		return ERROR;
	    if ( level == "fatal" )
		return FATAL;

	    throw std::runtime_error( "Unknown log level " + level + "." );
	}
	
	void initialize( Level level )
	{
	    boost::log::core::get()->set_filter( boost::log::trivial::severity >= level );
	    boost::log::add_common_attributes();
	    boost::log::add_console_log();
	}

    	void initialize( const std::string &level )
	{
	    initialize( toLevel( level ) );
	}
    }
}


