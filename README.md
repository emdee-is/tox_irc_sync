# Tox-Sync

A bot that sync messages between IRC and Tox NGC group chat.

## Hard Forked

Hard forked from <https://github.com/aitjcize/tox-irc-sync>
and changed to use the Python wrapping from
<https://git.macaw.me/emdee/toxygen_wrapper>.
Just clone that repo and put the resulting directory on your
```PYTHONPATH```.

## Usage

Run: ```tox-irc-sync.py --help``` for command line arguments.

```
python3 tox-irc-sync.py \
        [-h] [--proxy_host PROXY_HOST]
             [--proxy_port PROXY_PORT]
	     [--proxy_type {0,1,2}]
             [--udp_enabled {True,False}]
             [--ipv6_enabled {True,False}]
             [--download_nodes_list {True,False}]
             [--nodes_json NODES_JSON]
             [--download_nodes_url DOWNLOAD_NODES_URL]
             [--logfile LOGFILE]
	     [--loglevel LOGLEVEL]
             [--tcp_port TCP_PORT]
	     [--mode MODE]
             [--sleep {qt,gevent,time}]
	     [--irc_host IRC_HOST]
             [--irc_port IRC_PORT]
	     [--irc_chan IRC_CHAN]
             [--irc_ssl {,tls1.2,tls1.3}]
	     [--irc_ca IRC_CA]
             [--irc_pem IRC_PEM]
	     [--irc_fp IRC_FP]
             [--irc_nick IRC_NICK]
	     [--irc_name IRC_NAME]
	     [--irc_ident IRC_IDENT]
	     [--irc_pass IRC_PASS]
             [--irc_email IRC_EMAIL]
             [--group_pass GROUP_PASS]
             [--group_name GROUP_NAME]
             [--group_nick GROUP_NICK]
             [--group_invite GROUP_INVITE]
             [--group_moderator GROUP_MODERATOR]
             [--group_ignore GROUP_IGNORE]
             [profile]
```

### Positional arguments
```
  profile               Path to Tox profile - new groups will be saved there
```

### Optional Arguments:

```
  -h, --help            show this help message and exit
  
  --proxy_host PROXY_HOST, --proxy-host PROXY_HOST
                        proxy host
  --proxy_port PROXY_PORT, --proxy-port PROXY_PORT
                        proxy port
  --proxy_type {0,1,2}, --proxy-type {0,1,2}
                        proxy type 1=http, 2=socks
			
  --udp_enabled {True,False}
                        En/Disable udp
  --ipv6_enabled {False,False}
                        En/Disable ipv6 - default False
			
  --tcp_port TCP_PORT, --tcp-port TCP_PORT for serving as a Tox relay
  
  --mode MODE           Mode: 0=chat 1=chat+audio 2=chat+audio+video default:0
			
  --nodes_json NODES_JSON  --network {old,main,local}
  --download_nodes_url DOWNLOAD_NODES_URL
  --download_nodes_list {True,False}
                        Download nodes list
			
  --logfile LOGFILE     Filename for logging
  --loglevel LOGLEVEL   Threshold for logging (lower is more) default: 20
  
  --irc_host IRC_HOST   irc.libera.chat will not work over Tor
  --irc_port IRC_PORT   default 6667, but may be 6697 with SSL
  --irc_chan IRC_CHAN   IRC channel to join - include the #
  
  --irc_ssl {,tls1.2,tls1.3} TLS version; empty is no SSL
  --irc_ca IRC_CA       Certificate Authority file or directory
  --irc_pem IRC_PEM     Certificate and key as pem; use
                        openssl req -x509 -nodes -newkey rsa:2048
  --irc_fp IRC_FP       fingerprint of the pem added with CERT ADD; use
                        openssl x509 -noout -fingerprint -SHA1 -text
  --irc_nick IRC_NICK   IRC Nickname
  --irc_ident IRC_IDENT First field in USER
  --irc_name IRC_NAME   Third field in USER
  --irc_pass IRC_PASS   password for INDENTIFY or REGISTER
  --irc_email IRC_EMAIL Use email to REGISTER with _pass

  --group_pass GROUP_PASS password for the group
  --group_name GROUP_NAME name for the group
  --group_nick GROUP_NICK Nickname of the group founder
  --group_invite GROUP_INVITE A PK to invite to the group
  --group_moderator GROUP_MODERATOR A PK to invite to the group as moderator
  --group_ignore GROUP_IGNORE A PK to ignore by the group
```

### Examples

The general idea here is to use this to create a profile,
and that profile will have one user, and one group to start with.
That profile will contain the founders keypair for the group,
so protect the profile as it contains the group's secret key.

Then you use this profile to invite yourself to be a moderator,
by providing the your public key of the device you want to use to
moderate the group with the ```---group_moderator``` cmdline arg.

For the ```#tox``` group on ```libera.chat```:
```
python3 tox-irc-sync.py \
	--nodes_json $HOME/.config/tox/DHTnodes.json \
	--irc_chan "#tox" --irc_host irc.libera.net --irc_port 6667 \
	profile_that_will_get_the_group_key.tox
```

Libera will not work over Tor, but ```irc.oftc.net#tor``` will:
```
python3 tox-irc-sync.py \
	--nodes_json $HOME/.config/tox/DHTnodes.json \
	--irc_chan "#tor" --irc_host irc.oftc.net --irc_port 6667 \
	--proxy_type 2 --proxy_host 127.0.0.1 --proxy_port 9050 \
	profile_that_will_get_the_group_key.tox
```

* OFTC has an Onion address:
  ```ircs://oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion:6697```
* Libera has an Onion address:
 ```libera75jm6of4wxpxt4aynol3xjmbtxgfyjpu34ss4d7r7q2v5zrpyd.onion```


## ChangeLog

* changed to use the Python wrapping from <https://git.macaw.me/emdee/toxygen_wrapper>
* ```tox_irc_sync``` does  SSL now.

### Future Directions

1. It's intended as a IRC->Tox NGC gateway but it could work the other way round.
2. It could be a plugin under  <https://git.macaw.me/emdee/toxygen>
   which would broaden the range of callbacks that could be supported.
3. It could be a gateway to an existing NGC group with an invite bot.

