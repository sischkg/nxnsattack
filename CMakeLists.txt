cmake_minimum_required(VERSION 2.6)
project(cache-poisoning-tool)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(Boost_ADDITIONAL_VERSIONS "1.55" )
find_package( Boost 1.55 )
find_package( OpenSSL )
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

add_definitions("-Wall -std=c++11 -g")

add_subdirectory( src )

if(NOT without-test)
  include_directories ("${PROJECT_SOURCE_DIR}/src")
  enable_testing()
  add_subdirectory(tests)
endif()

