#!/bin/bash

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

TLS=2
a=`openssl ciphers -s -v|grep -c v1.3`
if [ "$a" -lt 3 ] ; then
    WARN no SSSL TLSv1.3 ciphers available to the client.
    TLS=2
fi

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
       --irc_host irc.oftc.net
       --irc_port 7000
       --irc_ssl ""
       --irc_ident SyniTox
       --irc_name SyniTox
       --irc_nick SyniTox
       --irc_pass password
       )
DBUG $?

if [ $# -eq 0 -o "$1" = 1 ] ; then
    INFO No SSL
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}" "$@"
    DBUG $?
fi

CIPHER_DOWNGRADE_OVER_TOR="

Nmap scan report for irc.oftc.net (130.239.18.116)
Host is up (0.26s latency).
Other addresses for irc.oftc.net (not scanned): (null)
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
"
 # I know that site does v1.3 3 ciphers
if [ $# -eq 0 -o "$1" = 2 ] ; then
    nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p 6697 irc.oftc.net

    # oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion
    # irc.oftc.net
    LARGS=(
	--irc_host irc.oftc.net
	--irc_port 6697
	--irc_ssl tlsv1.$TLS
	--irc_ident SyniTox
	--irc_name SyniTox
	--irc_nick SyniTox
	--irc_pass password
	--irc_pem $HOME/.config/ssl/irc.oftc.net/SyniTox.pem
	# E178E7B9BD9E540278118193AD2C84DEF9B35E85
	--irc_fp $HOME/.config/ssl/irc.oftc.net/SyniTox.fp
	--irc_cadir '/etc/ssl/certs'
	--irc_cafile /etc/ssl/cacert.pem
    )
    DBUG $?
fi

if [ $# -eq 0 -o "$1" = 2 ] ; then
    INFO SSL
    python3 tox-irc-sync.py "${LARGS[@]}" "${RARGS[@]}" "$@"
fi

ip=oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion
if [ $# -eq 0 -o "$1" = 3 ] ; then
    nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p 6697 $ip
    INFO Onion
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ip "${RARGS[@]}" "$@"
    DBUG $?
fi

ip=`tor-resolve -4 $ip`
if [ $? -eq 0 -a -n "$ip" ] && [ $# -eq 0 -o "$1" = 4 ] ; then
    nmap --script ssl-enum-ciphers --proxies socks4://127.0.0.1:9050 -p 6697 $ip
    INFO IP $ip
    python3 tox-irc-sync.py "${LARGS[@]}" --irc_connect $ip "${RARGS[@]}" "$@"
    DBUG $?
fi
