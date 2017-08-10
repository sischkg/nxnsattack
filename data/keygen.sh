
OPENSSL=/usr/bin/openssl

base=`dirname $0`
keys=$base/keys
zone=example.com

key_filename()
{
    domain=$1
    type=$2

    echo "$keys/$domain.$type.key"
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

    not_before=`date +%s`
    not_after=`expr $not_before \+ $period_sec`

    tag=`expr $not_before \% 65535`
    key_file=`key_filename $domain $type`
    config_file=`config_filename $domain $type`

    cat <<-END_TEMPLATE > $config_file
	---
	domain: $domain
	type: $type
	tag: $tag
	not_before: $not_before
	not_after: $not_after
	key_file: $key_file
END_TEMPLATE

}

generate_private_key()
{
    domain=$1
    type=$2
    key_file=`key_filename $domain $type`

    key_length=1024
    if [ x$type = x"ksk" ]
    then
        key_length=2048
    fi
    
    rm -f $key_file
    $OPENSSL genrsa -out $key_file $key_length
}


generate_keys()
{
    domain=$1
    generate_config $domain ksk 86400
    generate_config $domain zsk 86400
    generate_private_key $domain ksk 
    generate_private_key $domain zsk 
}

mkdir -p $keys

generate_keys child.siskrn.co

