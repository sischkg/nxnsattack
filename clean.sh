#!/bin/sh

rm -f bin/* lib/*
rm -rf CMakeCache.txt CMakeFiles cmake_install.cmake
find src -name '*.dir' -exec rm -rf {} \; 

