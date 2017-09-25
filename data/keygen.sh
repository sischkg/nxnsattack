
OPENSSL=/usr/bin/openssl

base=`dirname $0`
keys=$base
zone=example.com

key_filename()
{
    domain=$1
    type=$2
    index=$3

    echo "$keys/$domain.$type.$index.key"
}

config_filename()
{
    domain=$1
    type=$2

    echo "$base/$domain.$type.yaml"
}

generate_config()
{
    domain=$1
    type=$2
    period_sec=$3
    algo=$4
    count=$5

    not_before=`date +%s`
    not_after=`expr $not_before \+ $period_sec`

    config_file=`config_filename $domain $type`

    echo --- > $config_file

    i=0
    while [ $i -lt $count ]
    do
        key_file=`key_filename $domain $type $i`
        cat <<-END_TEMPLATE >> $config_file
	- domain: $domain
	  type: $type
	  algorithm: $algo
	  not_before: $not_before
	  not_after: $not_after
	  key_file: $key_file
END_TEMPLATE
        i=`expr $i + 1`
    done
}

generate_private_key()
{
    domain=$1
    type=$2
    algo=$3
    count=$4
    
    i=0
    while [ $i -lt $count ]
    do
        key_file=`key_filename $domain $type $i`

        if [ x$algo = xECDSAP256SHA256 ]
        then
            $OPENSSL ecparam -genkey -name prime256v1 -out $key_file
        else
            key_length=1024
            if [ x$type = x"ksk" ]
            then
                key_length=2048
            fi
            rm -f $key_file
            $OPENSSL genrsa -out $key_file $key_length
        fi
        i=`expr $i + 1`
    done
}


generate_keys()
{
    domain=$1
    algo=$2
    count=$3
    generate_config $domain ksk 86400 $algo $count
    generate_config $domain zsk 86400 $algo $count
    generate_private_key $domain ksk $algo  $count
    generate_private_key $domain zsk $algo  $count
}

mkdir -p $keys

generate_keys child.siskrn.co RSASHA1 100
generate_keys ecdsa.siskrn.co ECDSAP256SHA256 100

