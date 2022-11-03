#!/bin/bash
# -*- mode: sh; fill-column: 75; tab-width: 8; coding: utf-8-unix -*-

#export LD_LIBRARY_PATH=/usr/local/lib
#export TOXCORE_LIBS=/mnt/linuxPen19/var/local/src/c-toxcore/_build
export TOXCORE_LIBS=/mnt/o/var/local/src/tox_profile/libs
export PYTHONPATH=/mnt/o/var/local/src/toxygen_wrapper.git/ 

[ -f /usr/local/bin/usr_local_tput.bash ] && \
    . /usr/local/bin/usr_local_tput.bash || {
	DBUG() { echo DEBUG $* ; }
	INFO() { echo INFO $* ; }
	WARN() { echo WARN $* ; }
	ERROR() { echo ERROR $* ; }
    }

HOST=irc.oftc.net
IRC_PORT=6667
IRCS_PORT=6697
ONION=oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion

TLS=0
a=`openssl ciphers -s -v|grep -c v1.3`
if [ "$a" -lt 3 ] ; then
    WARN no SSSL TLSv1.3 ciphers available to the client.
    TLS=2
elif nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p $IRCS_PORT $HOST | grep -q 'TLSv1.3:' ; then
    TLS=3
else
    TLS=2
fi
TLS=3

if [ "$TLS" -ne 0 ] ; then
    SD=$HOME/.config/ssl/$HOST
    [ -d $SD ] || mkdir -p $SD || exit 2
    if [ ! -s $SD/$nick.key ] ; then
	# ed25519
	openssl req -x509 -nodes -newkey rsa:2048 \
		-keyout $SD/$nick.key \
		-days 3650 -out $SD/$nick.crt || exit 3	
	chmod 400 $SD/$nick.key
    fi
    if [ ! -s $SD/$nick.fp ] ; then
	openssl x509 -noout -fingerprint -SHA1 -text \
	    < $SD/$nick.crt  > $SD/$nick.fp || exit 4
    fi
    if [ ! -s $SD/$nick.pem ] ; then
	cat $SD/$nick.crt $SD/$nick.key > $SD/$nick.pem
	chmod 400 $SD/$nick.pem || exit 5
    fi
    ls -l -s $SD/$nick.pem 
fi

curl -vvvvv --cacert /etc/ssl/cacert-testforge.pem \
     --cert ~/.config/ssl/$HOST/SyniTox.pem \
     https://$HOST:$IRCS_PORT \
    2>&1| grep "SSL connection using TLSv1.$TLS"
    [ $? -gt 0 ] && WARN curl not OK
    
declare -a RARGS
RARGS=(
    --log_level 10
)
[ -n "$socks_proxy" ] && \
RARGS+=(
       --proxy_type 2
       --proxy_port 9050
       --proxy_host 127.0.0.1
)
declare -a LARGS
LARGS=(
       --irc_host $HOST
       --irc_port $IRC_PORT
       --irc_ssl ""
       --irc_ident SyniTox
       --irc_name SyniTox
       --irc_nick SyniTox
       )
DBUG $?

if [ $# -eq 0 -o "$1" = 1 ] ; then
    INFO No SSL
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}" "$@"
    DBUG $?
fi

CIPHER_DOWNGRADE_OVER_TOR="

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
	--irc_pem $HOME/.config/ssl/$HOST/SyniTox.pem
	# E178E7B9BD9E540278118193AD2C84DEF9B35E85
	--irc_fp $HOME/.config/ssl/$HOST/SyniTox.fp
	--irc_cafile /usr/local/etc/ssl/cacert-testforge.pem
    )

if [ $# -eq 0 -o "$1" = 2 ] ; then
    INFO SSL v1.$TLS
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}" "$@"
    DBUG $?
fi

ip=$ONION
if [ $# -eq 0 -o "$1" = 3 ] ; then
    nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p $IRCS_PORT $ip
    INFO Onion v1.$TLS
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ip "${RARGS[@]}" "$@"
    DBUG $?
fi

ip=`tor-resolve -4 $ONION`
if [ $? -eq 0 -a -n "$ip" ] && [ $# -eq 0 -o "$1" = 4 ] ; then
    curl  -vvvvv --cacert /etc/ssl/cacert-testforge.pem \
      --cert ~/.config/ssl/$HOST/SyniTox.pem \
      --connect-to $ip:$IRCS_PORT \
      https://$HOST:$IRCS_PORT \
      2>&1| grep "SSL connection using TLSv1.$TLS"
    
    [ $? -gt 0 ] && WARN curl not OK
    nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p $IRCS_PORT $ip
    INFO IP $ip
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ip "${RARGS[@]}" "$@"
    DBUG $?
fi
