# dns-fuzz-server

## 概要

dns-fuzz-serverは、フルリゾルバのバグ・脆弱性を探すためのファジングツールです。
dns-fuzz-serverはDNS権威サーバとして振る舞い、フルリゾルバへ特殊な応答を返し
フルリゾルバの異常終了(assert failure, segmentation fault, kill by OOM)を発生させます。


### Quick Start

Centos 7.4をインストールします。

コンパイルに必要なソフトウェアをインストールします。

```
# yum install epel-release
# yum install gcc-c++ boost-devel wget perl yaml-cpp-devel bind-utils bind

# wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.sh
# sh cmake-3.10.0-Linux-x86_64.sh --skip-license --prefix=/usr/local
# wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz

# tar xzf openssl-1.1.0g.tar.gz
# cd openssl-1.1.0g
# ./config
# maket
# make install
```

dns-fuzz-serverをコンパイルします。

```
$ tar xzf dns-fuzz-server-x.x.x.tar.gz
$ cd dns-fuzz-server
$ OPENSSL_ROOT_DIR=/usr/local/ssl cmake .
$ make
```

ドメインexample.comのゾーンファイルとKSK, ZSKを用意します。

```
$ named-checkzone -s full -o example.com.zone.full example.com example.com.zone
zone example.com/IN: loaded serial 20170531
OK
```

ファジングサーバを開始します。

```
 ./bin/fuzz_server -z example.com -f data/example.com.zone.full -K data/example.com.ksk.yaml -Z data/example.com.zsk.yaml
```

フルリゾルバへクエリを送信します。

```
./fuzz_client -s <full_resolver_ip_address> -b example.com
```

## 必要なソフトウェア

* gcc-c++ ( support c++11 )
* boost
* openssl 1.1.0
* yaml-cpp 6 (https://github.com/jbeder/yaml-cpp )
* cmake >= 3.8

## コンパイル手順(CentOS 7.4)

コンパイルに必要なパッケージをインストールします。

```
# yum install epel-release
# yum install gcc-c++ boost-devel wget perl yaml-cpp-devel bind-utils bind
```

cmakeをインストールします。

```
# wget https://cmake.org/files/v3.10/cmake-3.10.0-Linux-x86_64.sh
# sh cmake-3.10.0-Linux-x86_64.sh --skip-license --prefix=/usr/local
```

OpenSSLをインストールします。

```
# wget https://www.openssl.org/source/openssl-1.1.0g.tar.gz
# tar xzf openssl-1.1.0g.tar.gz
# cd openssl-1.1.0g
# ./config
# maket
# make install
```

dns-fuzz-serverをコンパイルします。

```
$ tar xzf dns-fuzz-server-x.x.x.tar.gz
$ cd dns-fuzz-server
$ OPENSSL_ROOT_DIR=/usr/local/ssl cmake .
$ make
```


## 利用可能な実行ファイル

* ./bin/fuzz_server: ファジング用権威サーバ
* ./bin/fuzz_client: フルリゾルバへ再起問い合わせを送信するDNSクライアント
* ./data/keygen.sh: KSK, ZSKの鍵を生成する簡易スクリプト

## fuzz_serverの使用方法

dns-fuzz-serverはDNS権威サーバとして振る舞い、フルリゾルバへ特殊な応答を返す。

### コマンドの引数

```
fuzz server [ -b <address> ] [ -p <port> ] -z <zone> -f <zone.file> -K <ksk.yaml> -Z <zsk.yaml> [ -d ]
```

* `-h [ --help ]`: help mesage
* `-b / --bind <address>`: Bind IP address
* `-p / --port <port>`: Bind UDP/TCP port
* `-z / --zone <zone>`: ゾーン名
* `-f / --file <zone.file>`: ゾーンファイル名(ゾーンファイルについては、"ゾーンファイル形式"を参照)
* `-K / --ksk  <ksk.yaml>`: KSKの設定ファイル
* `-Z / --zsk  <zsk.yaml>`: ZSKの設定ファイル
* `-d / --debug`: debug mode

### 実行例

```
 ./fuzz_server -z example.com -f data/example.com.zone.full -K data/example.com.ksk.yaml -Z data/example.com.zsk.yaml
```

### ゾーンファイル形式

fuzz_serverは一般的な形式(RFC1035)のゾーンファイルを利用できない。RFC1035形式のゾーンファイルを
コマンド`named-checkzone -s full`にてファイル形式を変更してから利用します。

#### ゾーンファイル作成例

RFC1035形式のゾーンファイル

```
$ cat example.com.zone

$TTL 3600
example.com. 3600       IN SOA  ns01.example.co. hostmaster.example.com.  (
                                        20170531        ; serial
                                        3600    ; refresh
                                        1800    ; retry
                                        8640000 ; expire
                                        3600 )  ; minimum
        3600 IN NS      ns01
        3600 IN NS      ns02
        3600 IN MX 10   mail


ns01    86400 IN A      192.168.33.11
ns02    86400 IN A      192.168.33.12
www     3600  IN A      192.168.33.101
www     3600  IN A      192.168.33.102
mail    3600  IN A      192.168.33.111
```

形式の変換

```
$ named-checkzone  -s full -o example.com.zone.full example.com example.com.zone
zone example.com/IN: loaded serial 20170531
OK
```

変換後のゾーンファイル

```
$ cat example.com.zone.full
example.com.                                  3600 IN SOA       ns01.example.co. hostmaster.example.com. 20170531 3600 1800 8640000 3600
example.com.                                  3600 IN NS        ns01.example.com.
example.com.                                  3600 IN NS        ns02.example.com.
example.com.                                  3600 IN MX        10 mail.example.com.
mail.example.com.                             3600 IN A         192.168.33.111
ns01.example.com.                             86400 IN A        192.168.33.11
ns02.example.com.                             86400 IN A        192.168.33.12
www.example.com.                              3600 IN A         192.168.33.101
www.example.com.                              3600 IN A         192.168.33.102
```

### KSK, ZSK設定ファイルの形式

KSK,ZSK設定ファイルは次のようなYAML形式になります。これらのファイルは、秘密鍵とともに後述の`keygen.sh`にて作成することができます。

```
---
- domain: <domain_0>
  type: <ksk_or_zsk_0>
  algorithm: <algorithm_0>
  not_before: <not_before_epoch_0>
  not_after: <not_after_epoch_0>
  key_file: <path_to_private_key_0>
- domain: <domain_1>
  type: <ksk_or_zsk_1>
  algorithm: <algorithm_1>
  not_before: <not_before_epoch_1>
  not_after: <not_after_epoch_1>
  key_file: <path_to_private_key_1>
- domain: <domain_2>
  type: <ksk_or_zsk_2>
  algorithm: <algorithm_2>
  not_before: <not_before_epoch_2>
  not_after: <not_after_epoch_2>
  key_file: <path_to_private_key_2>
```

* <domain_n>: KSK, ZSKのドメイン名
* <ksk_or_zsk_N>: KSKの鍵の場合は`ksk`, ZSKの場合は`zsk`
* <algorithm_N>: `RSASHA256`
* <not_before_epoch_N>
* <not_after_epoch_N>
* <path_to_private_key_N>


#### KSK設定例

```
---
- domain: example.com
  type: ksk
  algorithm: RSASHA256
  not_before: 1523457711
  not_after: 1524321711
  key_file: /dns/data/keys/example.com.ksk.0.key
```

#### ZSK設定例

```
---
- domain: example.com
  type: zsk
  algorithm: RSASHA256
  not_before: 1523457711
  not_after: 1524321711
  key_file: /dns/data/keys/example.com.zsk.0.key
```


### 秘密鍵の作成

KSK/ZSKの秘密鍵はopensslにて作成します。

コマンド例

```
$ openssl genrsa -out /dns/data/keys/example.com.zsk.0.key
$ openssl ecparam -genkey -name prime256v1 -out /dns/data/keys/example.com.ksk.0.key
```


## fuzz_clientの使用方法

fuzz_clientは、ファジングのためにフルリゾルバへDNSクエリを定期的に送信するコマンドです。
`-b`オプションにてクエリのQNAMEのサフィックスを指定することができます。クエリのQTYPE, QCLASSは乱数から生成します。

例: `-b example.com`を指定すると、以下のようにQNAMEを生成します。
* example.com
* www.example.com
* yyy.example.com
* www.yyy.example.com
...

### コマンドの引数

```
fuzz_client -s <server> [ -p <port> ] -b <base> [-i <interval> ]
```

* `-h/--help`: print this message
* `-s/--server <server>`: DNSクエリの送信先IPアドレス
* `-p/--port <port>`: target server port
* `-b/--base <base>`: QNAMEのサフィックス
* `-i/--interval <interval>`: DNSクエリの間隔( msec )

## keygen.shの使用方法

`keygen.sh`にてKSK,ZSKとその設定ファイルを作成することができます。

### コマンドの引数

```
keygen.sh <domain> <algorithm>
```

* <domain>: ドメイン名
* <algorithm>: KSK,ZSKのアルゴリズム`RSASHA1`, `RSASHA256`, `ECDSAP256SHA256`

### 実行例

```
./fuzz_client -s 192.168.33.102 -b example.com
```

