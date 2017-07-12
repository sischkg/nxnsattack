
base=`dirname $0`
keys=$base/keys
zone=example.com

mkdir -p $keys
dnssec-keygen -f KSK -K $keys -a RSASHA256 -b 4096 -r /dev/urandom -n zone $zone
dnssec-keygen        -K $keys -a RSASHA256 -b 2048 -r /dev/urandom -n zone $zone


