#Tox-Sync

A bot that sync messages between IRC and Tox group chat.

## Hard forked

Hard forked to use https://git.macaw.me/emdee/toxygen_wrapper
Just clone that repo and put the resulting directory on your
```PYTHONPATH```.

Run: ```tox-irc-sync.py --help`` for command line arguments.

For the ```#tox``` group on ```libera.chat```:
For example```irc.libera.net#tox```:
```
python3 tox-irc-sync.py \
	--nodes_json $HOME/.config/tox/DHTnodes.json \
	--irc_chan "#tor" --irc_host irc.libera.net --irc_port 6667 \
```

Libera will not work over Tor, but ```irc.oftc.net#tor``` will:
```
python3 tox-irc-sync.py \
	--nodes_json $HOME/.config/tox/DHTnodes.json \
	--irc_chan "#tor" --irc_host irc.oftc.net --irc_port 6667 \
	--proxy_type 2 --proxy_host 127.0.0.1 --proxy_port 9050
```
