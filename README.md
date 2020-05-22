# nxnsattack

## Overview

NXNSAttack PoC

## Quick Start

Install CentOS 7.4.

Install packages for compiling dns-fuzz-server.

```
# yum install epel-release
# yum install gcc-c++ boost-devel gtest-devel wget perl yaml-cpp-devel bind-utils bind

# wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.sh
# sh cmake-3.10.0-Linux-x86_64.sh --skip-license --prefix=/usr/local

# wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz
# tar xzf openssl-1.1.0g.tar.gz
# cd openssl-1.1.0g
# ./config
# make
# make install
# echo /usr/local/lib64 > /etc/ld.so.conf.d/local.conf
# ldconfig
```

Compile nxnsattack

```
$ tar xzf /path/to/nxnsattack-x.x.x.tar.gz
$ cd nxnsattack
$ cmake .
$ make
```


```
$ ./bin/nxnsattack -p 10053
```

## Requirement softwares

* gcc-c++ ( support c++11 )
* boost
* openssl 1.1.0
* yaml-cpp 6 (https://github.com/jbeder/yaml-cpp )
* cmake >= 3.8


