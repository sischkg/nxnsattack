#!/bin/sh

ZONE=child.siskrn.co
KEY_LENGTH=2048

base=`dirname $0`
key=$base/$ZONE.key

rm -f $key
echo "" | openssl genrsa -out $key $KEY_LENGTH


