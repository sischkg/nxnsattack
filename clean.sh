#!/bin/sh

rm -rf CMakeCache.txt CMakeFiles cmake_install.cmake
find src -name '*.dir' -exec rm -rf {} \; 

