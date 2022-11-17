#!/bin/bash
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

#export LD_LIBRARY_PATH=/usr/local/lib
#export TOXCORE_LIBS=/mnt/linuxPen19/var/local/src/c-toxcore/_build
export TOXCORE_LIBS=/mnt/o/var/local/src/tox_profile/libs
export PYTHONPATH=/mnt/o/var/local/src/toxygen_wrapper.git/ 
export https_proxy=
export http_proxy=
SOCKS_HOST=127.0.0.1
SOCKS_PORT=9050

NMAP_ARGS="-Pn --script ssl-enum-ciphers --proxies socks4://${SOCKS_HOST}:$SOCKS_PORT --reason"
CURL_ARGS="-vvvvv --cacert /etc/ssl/cacert-testforge.pem"
CURL_ARGS="$CURL_ARGS -x socks5h://${SOCKS_HOST}:$SOCKS_PORT"
CURL_ARGS="$CURL_ARGS --interface lo --dns-interface lo"

[ -f /usr/local/bin/usr_local_tput.bash ] && \
    . /usr/local/bin/usr_local_tput.bash || {
	DBUG() { echo DEBUG $* ; }
	INFO() { echo INFO $* ; }
	WARN() { echo WARN $* ; }
	ERROR() { echo ERROR $* ; }
    }

if true; then
HOST=irc.oftc.net
IRC_PORT=6667
IRCS_PORT=6697
ONION=oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion
NICK=SyniTox
TLS=3
PEM=$HOME/.config/ssl/$HOST/SyniTox.pem
CRT=$HOME/.config/ssl/$HOST/SyniTox.crt
KEY=$HOME/.config/ssl/$HOST/SyniTox.key
FP=$HOME/.config/ssl/$HOST/SyniTox.fp
else
HOST=libera.chat
IRC_PORT=
IRCS_PORT=6697
ONION=libera75jm6of4wxpxt4aynol3xjmbtxgfyjpu34ss4d7r7q2v5zrpyd.onion
NICK=SyniTox
PEM=$HOME/.config/ssl/$HOST/SyniTox.pem
KEY=$HOME/.config/ssl/$HOST/SyniTox.key
CRT=$HOME/.config/ssl/$HOST/SyniTox.crt
FP=$HOME/.config/ssl/$HOST/SyniTox.fp
TLS=3
fi

function check_nmap() {
    local retval=$1
    local hfile=$2
    local tag=$3
    INFO $retval $hfile $tag
    if ! grep /tcp $hfile ; then
	ERROR check_nmap no /tcp in $hfile
	return 1
	# whats filtered?
    elif grep '/tcp *filtered' $hfile ; then
	WARN check_nmap filtered $hfile
	return 2
	# whats filtered?
    elif grep '/tcp *open' $hfile ; then
	return 0
    fi
    return 0
}

function check_curl() {
    local retval=$1
    local hfile=$2
    local tag=$3
    
    # curl: (1) Received HTTP/0.9 when not allowed    
    if grep "SSL_ERROR_SYSCALL" $hfile ; then
	ERROR curl $tag SSL_ERROR_SYSCALL $hfile
	return 2
    elif ! grep "SSL connection using TLSv1" $hfile ; then
	WARN check_curl curl $tag no ciphers $hfile
    elif ! grep "SSL connection using TLSv1.[3$TLS]" $hfile ; then
	WARN check_curl curl $tag no TLS connection in $hfile
    elif [ $TLS -eq 3 ] && grep "SSL connection using TLSv1.[2]" $hfile ; then
	WARN check_curl protocol downgrade attack '?' no TLSv1.3 ciphers from $HOST
    elif [ $retval -gt 1 ] ; then
	grep "$IRCS_PORT/" $hfile	
	WARN check_curl curl $tag not OK $retval $hfile
    else
	INFO curl $tag OK $hfile
	return 0
    fi
    return 1
}
a=`openssl ciphers -s -v|grep -c v1.3`
if [ "$a" -lt 3 ] ; then
    WARN no SSL TLSv1.3 ciphers available to the client.
    TLS=2
fi
[ $TLS = 2 ] && CURL_ARGS="$CURL_ARGS --tlsv1.2"
[ $TLS = 3 ] && CURL_ARGS="$CURL_ARGS --tlsv1.3"

NICK=emdee
if [ "$TLS" -ne 0 ] ; then
    SD=$HOME/.config/ssl/$HOST
    [ -d $SD ] || mkdir -p $SD || exit 2
    if [ ! -s $SD/$NICK.key ] ; then
	# ed25519
	openssl req -x509 -nodes -newkey rsa:2048 \
		-keyout $SD/$NICK.key \
		-days 3650 -out $SD/$NICK.crt || exit 3	
	chmod 400 $SD/$NICK.key
    fi
    if [ ! -s $SD/$NICK.fp ] ; then
	openssl x509 -noout -fingerprint -SHA1 -text \
	    < $SD/$NICK.crt  > $SD/$NICK.fp || exit 4
    fi
    if [ ! -s $SD/$NICK.pem ] ; then
	cat $SD/$NICK.crt $SD/$NICK.key > $SD/$NICK.pem
	chmod 400 $SD/$NICK.pem || exit 5
    fi
    ls -l -s $SD/$NICK.pem 
fi

declare -a RARGS
if [ "$DEBUG" = 1 ] ; then
    RARGS=(
	--log_level 10
    )
else
    RARGS=(
	--log_level 20
    )
fi
[ -n "$socks_proxy" ] && \
  RARGS+=(
       --proxy_type 2
       --proxy_port 9050
       --proxy_host ${SOCKS_HOST}
       --trace_enabled True
)
declare -a LARGS
LARGS=(
       --irc_host $HOST
       --irc_port $IRC_PORT
       --irc_ssl ""
       --irc_ident SyniTox
       --irc_name SyniTox
       --irc_nick $NICK
       )

if [ $# -eq 0 -o "$1" = 1 ] && [ -n "$IRC_PORT" ] ; then
    INFO No SSL
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}"
    DBUG $?
fi

CIPHER_DOWNGRADE_OVER_TOR_LIBERA="Other addresses for libera.chat (not scanned): (null)
rDNS record for 130.239.18.116: solenoid.acc.umu.se

PORT     STATE SERVICE
6697/tcp open  ircs-u
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 2048) - A
|     compressors: 
|     cipher preference: indeterminate
|     cipher preference error: Too few ciphers supported
|_  least strength: A
'
"

CIPHER_DOWNGRADE_OVER_TOR_OFTC="

Nmap scan report for $HOST (130.239.18.116)
Host is up (0.26s latency).
Other addresses for $HOST (not scanned): (null)
rDNS record for 130.239.18.116: solenoid.acc.umu.se

PORT     STATE SERVICE
$IRCS_PORT/tcp open  ircs-u
| ssl-enum-ciphers: 
|   TLSv1.0: 
|     ciphers: 
|       TLS_DHE_RSA_WITH_AES_128_CBC_SHA (dh 2048) - A
|     compressors: 
|     cipher preference: indeterminate
|     cipher preference error: Too few ciphers supported
|_  least strength: A
"
 # I know that site does v1.3 3 ciphers
LARGS=(
	--irc_host $HOST
	--irc_port $IRCS_PORT
	--irc_ssl tlsv1.$TLS
	--irc_ident SyniTox
	--irc_name SyniTox
	--irc_nick SyniTox
	--irc_pass password
	--irc_crt "$CRT"
	--irc_key "$KEY"
	# E178E7B9BD9E540278118193AD2C84DEF9B35E85
	--irc_fp "$FP"
	--irc_cafile /usr/local/etc/ssl/cacert-testforge.pem
    )

ip=`tor-resolve -4 $ONION`
if  [ -n "$ip" ] ; then
    curl $CURL_ARGS \
	  --connect-to $ip:$IRCS_PORT \
	 https://$HOST:$IRCS_PORT \
	 > /tmp/TIS$$.curl 2>&1
    check_curl $? /tmp/TIS$$.curl ""
else
    ERROR tor-resolve failed
    exit 6
fi

if [ $# -eq 0 -o "$1" = 2 -a  $HOST = libera.chat ] ; then
   ERROR $HOST rejects tor
elif [ $# -eq 0 -o "$1" = 2 ] ; then
    INFO SSL v1.$TLS
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}"
    DBUG $?
fi

if  [ -n "$ip" ] ; then
    [ -n "$PEM" -a  -f "$PEM" ] || { ERROR NO $PEM ; exit 7 ; }
    ls -l $PEM || exit 7
    INFO curl  $CURL_ARGS \
	  --cert-type PEM \
	  --cert $PEM \
	  --connect-to $ip:$IRCS_PORT \
	  https://$HOST:$IRCS_PORT
    curl  $CURL_ARGS \
	  --cert-type PEM \
	  --cert $PEM \
	  --connect-to $ip:$IRCS_PORT \
	  https://$HOST:$IRCS_PORT \
	  > /tmp/TIS$$.cert 2>&1
    check_curl $? /tmp/TIS$$.cert "--connect-to"
else
    ERROR tor-resolve failed
    exit 8
fi

if [ $# -eq 0 -o "$1" = 3 ] ; then
    [ -n "$PEM" -a  -f "$PEM" ] || { ERROR NO $PEM ; exit 7 ; }
    
    nmap $NMAP_ARGS -p $IRCS_PORT $ip > /tmp/TIS$$.nmap 2>&1
    check_nmap $? /tmp/TIS$$.nmap $1
    
    INFO Onion v1.$TLS
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ONION "${RARGS[@]}"
    DBUG $?
fi

if [ $? -eq 0 ] && [ $# -eq 0 -o "$1" = 4 ] ; then
    [ -n "$PEM" -a  -f "$PEM" ] || { ERROR NO $PEM ; exit 7 ; }

    nmap $NMAP_ARGS -p $IRCS_PORT $ip > /tmp/TIS$$.nmap 2>&1
    check_nmap $? /tmp/TIS$$.nmap $1

    INFO Onion v1.$TLS IP $ip
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ip "${RARGS[@]}"
    DBUG $?
fi
