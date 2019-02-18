#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <boost/log/expressions.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>

namespace dns
{
    namespace logger
    {
	typedef boost::log::trivial::severity_level Level;
	const Level TRACE   = boost::log::trivial::trace;
	const Level DEBUG   = boost::log::trivial::debug;
	const Level INFO    = boost::log::trivial::info;
	const Level WARNING = boost::log::trivial::warning;
	const Level ERROR   = boost::log::trivial::error;
	const Level FATAL   = boost::log::trivial::fatal;
	
	void initialize( Level level = FATAL );
	void initialize( const std::string &level );
    }
}

#endif
