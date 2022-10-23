import sys
import os
import socket
import string
import select
import re
import pickle
import logging
import readline
import ctypes

from time import sleep
from os.path import exists
from threading import Thread
from random import shuffle

import wrapper
from wrapper.tox import Tox
from wrapper.toxav import ToxAV
import wrapper.toxcore_enums_and_consts as enums
from wrapper.toxcore_enums_and_consts import \
    TOX_CONNECTION, TOX_USER_STATUS, TOX_MESSAGE_TYPE, \
    TOX_SECRET_KEY_SIZE, TOX_FILE_CONTROL, TOX_ADDRESS_SIZE, \
    TOX_GROUP_PRIVACY_STATE, TOX_GROUP_ROLE

try:
    import support_testing as ts
except ImportError:
    import wrapper_tests.support_testing as ts

global LOG
LOG = logging.getLogger('app.'+'ts')

PWD = ''

NAME = NICK = IDENT = REALNAME = 'SyniTox'

class AV(ToxAV):
    def __init__(self, core):
        self.core = core
        self.cs = None
        self.call_type = None

    def on_invite(self, idx):
        self.cs = self.get_peer_csettings(idx, 0)
        self.call_type = self.cs['call_type']

        LOG.info('Incoming %s call from %d:%s ...' % (
                'video' if self.call_type == self.TypeVideo else 'audio', idx,
                self.core.get_name(self.get_peer_id(idx, 0))))

        self.answer(idx, self.call_type)
        LOG.info('Answered, in call...')

    def on_start(self, idx):
        self.change_settings(idx, {'max_video_width': 1920,
                                   'max_video_height': 1080})
        self.prepare_transmission(idx, self.jbufdc * 2, self.VADd,
                True if self.call_type == self.TypeVideo else False)

    def on_end(self, idx):
        self.kill_transmission()

        LOG.info('Call ended')

    def on_peer_timeout(self, idx):
        self.stop_call()

    def on_audio_data(self, idx, size, data):
        sys.stdout.write('.')
        sys.stdout.flush()
        self.send_audio(idx, size, data)

    def on_video_data(self, idx, width, height, data):
        sys.stdout.write('*')
        sys.stdout.flush()
        self.send_video(idx, width, height, data)

bot_toxname = 'SyniTox'

class SyniTox(Tox):
    
    def __init__(self, opts,
                 sChannel='#tor',
                 sIRC_HOST='irc.oftc.net',
                 iIRC_PORT=6667,
                 GROUP_BOT_PK = '',
                 sMEMORY_DB = ''
                 ):
        Tox.__init__(self, tox_options=opts)
        self._address = self.self_get_address()
        self._opts = opts
        self._app = None
        self._settings = {}
        self._sChannel = sChannel
        self.sIRC_HOST = sIRC_HOST
        self.iIRC_PORT = iIRC_PORT
        self.sGROUP_BOT_PK = GROUP_BOT_PK
        self.sMEMORY_DB = sMEMORY_DB
        
        global     oTOX_OARGS
        self._oArgs = oTOX_OARGS
        data = self._oArgs.profile
        if data and os.path.exists(data):
            self.load_from_file(data)

        self.av = self.AV
        self.irc = None
        self.bid = -1
        self._bRouted  = None
        
    def start(self):
        
        self.self_set_name(bot_toxname)
        self.self_set_status_message("Send me a message with the word 'invite'")
        LOG.info('Our ToxID: %s' % self.self_get_toxid())

        self.readbuffer = b''
        
        self.tox_group_id = None
        self.group_init()
        
        self.memory = {}
        if os.path.exists(self.sMEMORY_DB):
            with open(self.sMEMORY_DB, 'r') as f:
                self.memory = pickle.load(f)
                
        self.irc_init()
        b = self.test_net()
        if b:
            self.dht_init()

    def bRouted(self):
        if self._oArgs.network not in ['local', 'localnew', 'newlocal']:
            b = ts.bAreWeConnected()
            if b is None:
                i = os.system('ip route|grep ^def')
                if i > 0:
                    b = False
                else:
                    b = True
            if not b:
                LOG.warn("No default route for network " +self._oArgs.network)
                return False
            return b
        return True
    
    def test_net(self, lElts=None, oThread=None, iMax=4):
        # bootstrap
        lNodes = ts.generate_nodes(oArgs=self._oArgs,
                                   ipv='ipv4',
                                   udp_not_tcp=True)
        self._settings['current_nodes_udp'] = lNodes.copy()
        if not lNodes:
            LOG.warn('empty generate_nodes udp')
        else:
            LOG.debug(f'Called generate_nodes: udp {len(lNodes)}')

        lNodes = ts.generate_nodes(oArgs=self._oArgs,
                                   ipv='ipv4',
                                   udp_not_tcp=False)
        self._settings['current_nodes_tcp'] = lNodes
        if not lNodes:
            LOG.warn('empty generate_nodes tcp')
        else:
            LOG.debug(f'Called generate_nodes: tcp {len(lNodes)}')
            
        # if oThread and oThread._stop_thread: return
        LOG.debug("test_net network=" +self._oArgs.network +' iMax=' +str(iMax))
        return True
    
    def group_init(self):
        LOG.debug(f"group_init proxy={self._oArgs.proxy_type}")
        group_name = bot_toxname +' Test ' +self._sChannel
        if not self.sGROUP_BOT_PK:
            privacy_state = TOX_GROUP_PRIVACY_STATE['PUBLIC']
            nick = bot_toxname +self._sChannel
            status = TOX_USER_STATUS['NONE']
            num = self.group_new(privacy_state, group_name, nick, status)
            assert num >= 0, num

            pk = self.group_self_get_public_key(num)
            assert pk, pk
            self.sGROUP_BOT_PK = pk
            self.sGROUP_NUM = num

        self.group_set_topic(num, bot_toxname +" IRC")
        LOG.info(f"group_init GROUP_BOT_PK={self.sGROUP_BOT_PK}")
        #? self.tox_group_id = self.bid
        self.group_send_message(num, TOX_MESSAGE_TYPE['NORMAL'], "hi")
        # TOX_GROUP_ROLE['FOUNDER']
        self.init_callbacks()
        
    def init_callbacks(self):
        def gi_wrapped(iTox, friendid, invite_data, invite_len, *args):
            invite_data = str(invite_data, 'UTF-8')
            self.on_group_invite(friendid, invite_data)
        self.callback_group_invite(gi_wrapped, 0)
        def scs_wrapped(iTox, friendid, *args):
            self.on_connection_status(self, scs_wrapped)
        self.callback_self_connection_status(scs_wrapped)
        def gm_wrapped(iTox, groupnumber, peer_id, type_, message, mlen, *args):
            message = str(message, 'UTF-8')
            self.on_group_message(groupnumber, peer_id, message)
        self.callback_group_message(gm_wrapped, 0)
        def ga_wrapped(iTox, groupnumber, peer_id, type_, action, mlen, *args):
            self.on_group_action(groupnumber, peer_id, action)
        #? self.callback_group_action(ga_wrapped, 0)
        def fr_wrapped(iTox, pk, message, mlen, *args):
            message = str(message, 'UTF-8')
            self.on_friend_request(self, pk, message)
        self.callback_friend_request(fr_wrapped)
        def fm_wrapped(iTox, peer_id, message, mlen, *args):
            message = str(message, 'UTF-8')
            self.on_friend_request(self, peer_id, message)
        self.callback_friend_request(fm_wrapped)

    def del_callbacks(self):
        self.callback_group_invite(None, 0)
        self.callback_self_connection_status(None)
        self.callback_group_message(None, 0)
        # self.callback_group_action(None, 0)
        self.callback_friend_request(None)
        self.callback_friend_request(None)

    def irc_init(self):
        if not self.bRouted(): return
        
        LOG.info(f"irc_init proxy={self._oArgs.proxy_type}")
        if self._oArgs.proxy_type == 2:
            from wrapper_tests import socks
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                                  self._oArgs.proxy_host,
                                  self._oArgs.proxy_port)
            irc = socks.socksocket()
        else:
            irc = socket.socket()
        try:
            irc.connect((self.sIRC_HOST, self.iIRC_PORT))
            irc.send(bytes('NICK ' + NICK + '\r\n', 'UTF-8' ))
            irc.send(bytes('USER %s %s bla :%s\r\n' % (IDENT, self.sIRC_HOST, REALNAME),
                                'UTF-8'))
        except Exception as e:
            LOG.warn(f'IRC error {e}')
        else:
            LOG.info('IRC connected ' +'NICK =' + NICK)
            self.irc = irc

    def dht_init(self):
        if not self.bRouted(): return
        if 'current_nodes_udp' not in self._settings:
            self.test_net()
        lNodes = self._settings['current_nodes_udp']
        shuffle(lNodes)
        if self._oArgs.proxy_type == 0:
            ts.bootstrap_good(lNodes[:4], [self])
        else:
            if self._bRouted == None:
                LOG.info(f'DHT bootstapping 1')
                ts.bootstrap_good([lNodes[0]], [self])
            if 'current_nodes_tcp' not in self._settings:
                self.test_net()
            lNodes = self._settings['current_nodes_tcp']
            shuffle(lNodes)
            ts.bootstrap_tcp(lNodes[:4], [self])

    def ensure_exe(self, func, *args):
        count = 0
        THRESHOLD = 50

        while True:
            try:
                return func(*args)
            except:
                assert count < THRESHOLD
                count += 1
                self.do()

    def do(self, n=50):
        interval = self.iteration_interval()
        for i in range(n):
            self.iterate()
            sleep(interval / 1000.0 *10)

    def unroute(self):
        if self.irc:
            try: irc.close()
            except: pass
            self.irc = None

    def irc_check(self, lines):
        if b'NOTICE AUTH' in lines[0]:
            for line in lines[:99]:
                if b'NOTICE AUTH' not in line: return
                line = str(line, 'UTF-8').strip()
                print(line)
        else:
            for line in lines[:5]:
                line = str(line, 'UTF-8').strip().lower()
                if 'banned' in line:
                    raise RuntimeError(line)
                if 'error' in line and 'closing' in line:
                    raise RuntimeError(line)
                
    def iLoop(self):
        checked = False
        self.joined = False
        self.request = False
        count = 0

        try:
            count = count + 1
            while True:
                b = self.bRouted()
                if not b:
                    self.unroute()
                    checked = False
                    if self._bRouted is None or self._bRouted != b:
                        self._bRouted = b
                        if count % 6 == 1:
                            LOG.info(f'Not routed {count}')
                    sleep(10)
                    continue
                else:
                    if self._bRouted is None:
                        self._bRouted = True
                        self.irc_send('.')
                    if self._bRouted is None or self._bRouted != b:
                        self._bRouted = b
                        LOG.debug(f'Routed {count}')

                status = self.self_get_connection_status()
                if not status:
                    if count % 6 == 1:
                        LOG.info(f'Not connected {count}')
                        self.dht_init()

                if b and not checked and status:
                    LOG.info('Connected to DHT.')
                    checked = True
                    try:
                        self.bid = self.friend_by_public_key(self.sGROUP_BOT_PK)
                        LOG.info(f'Connected to group {self.bid}')
                    except ctypes.ArgumentError as e:
                        self.bid = None
                        
                    if self.bid == None:
                        self.ensure_exe(self.friend_add_norequest, self.sGROUP_BOT_PK)
                        LOG.info(f'friend_add_n to group {self.sGROUP_BOT_PK[:8]}')
                        self.bid = self.friend_by_public_key(self.sGROUP_BOT_PK)
                        LOG.info(f'Added to group {self.bid}')
                        num = self.sGROUP_NUM
                        my_pk = self.group_self_get_public_key(num)
                        LOG.info(f'Connected to group as {my_pk[:8]}')

                if b and checked and not status:
                    LOG.info('Disconnected from DHT.')
                    self.dht_init()
                    checked = False
                    
                if not self.irc:
                    LOG.info('Disconnected from IRC.')
                    self.irc_init()                    
                    if not self.irc:
                        sleep(10)
                        continue
                
                LOG.info('Waiting on IRC.')
                readable, _, _ = select.select([self.irc], [], [], 0.1)

                if not readable:
                    LOG.info('Waited on IRC but nothing to read.')
                else:
                    self.readbuffer += self.irc.recv(4096)
                    lines = self.readbuffer.split(b'\n')
                    self.irc_check(lines)
                    LOG.info(f'Waited on IRC and got {len(lines)} lines.')
                    self.readbuffer = lines.pop()
                    for line in lines:
                        line = str(line, 'UTF-8')
                        i = line.find(' ')
                        print(line[i+1:])
                        l = line.rstrip().split()
                        rx = re.match(r':(.*?)!.*? PRIVMSG %s :(.*?)\r' %
                                self._sChannel, line, re.S)
                        if rx:
                            print('IRC> %s: %s' % rx.groups())
                            msg = '[%s]: %s' % rx.groups()
                            content = rx.group(2)

                            if content[1:].startswith('ACTION '):
                                action = '[%s]: %s' % (rx.group(1),
                                        rx.group(2)[8:-1])
                                self.ensure_exe(self.group_action_send,
                                        self.tox_group_id, action)
                            elif self.tox_group_id != None:
                                self.ensure_exe(self.group_message_send,
                                                self.tox_group_id, msg)

                            if content.startswith('^'):
                                self.handle_command(content)

                        elif l[0] == 'PING':
                           self.irc_send('PONG %s\r\n' % l[1])
                        elif l[1] == '376':
                            # :End of /MOTD command
                            self.irc.send(bytes('PRIVMSG NickServ :IDENTIFY %s %s\r\n'
                                               % (NICK, PWD,), 'UTF-8'))
                            self.irc.send(bytes('JOIN %s\r\n' % self._sChannel, 'UTF-8'))
                        elif l[1] == '421':
                            # 421 SyniTox .PRIVMSG :Unknown command
                            pass
                        elif l[1] == '477':
                            #477 SyniTox #tor :Cannot join channel (Need to be  identified and verified to join this channel, '/msg NickServ help' to learn how to register and verify.)
                            self.irc.send(bytes('HELP \r\n', 'UTF-8'))
                            self.irc.send(bytes('MSG NickServ help\r\n', 'UTF-8'))
                            
                            pass


                self.do()
        except KeyboardInterrupt:
            ret = 0
        except Exception as e:
            LOG.exception(f'Error running program:\n{e}', exc_info=True)
            ret = 1
        else:
            ret = 0            
        self.quit()
        return ret
    
    def quit(self):
        self.del_callbacks()
        self.save_to_file()

    def save_to_file(self):
        pass

    def irc_send(self, msg):
        success = False
        while not success:
            try:
                self.irc.send(bytes(msg, 'UTF-8'))
                success = True
                break
            except socket.error:
                self.irc_init()
                sleep(1)

    def on_connection_status(self, friendId, status):
        if not self.request and not self.joined \
                and friendId == self.bid and status:
            LOG.info('Groupbot online, trying to join group chat.')
            self.request = True
            self.ensure_exe(self.send_message, self.bid, 'invite')

    def on_group_invite(self, friendid, invite_data, user_data):
        if not self.joined:
            self.joined = True
            self.tox_group_id = self.join_groupchat(friendid, data)
            LOG.info('Joined groupchat.')

    def on_group_message(self, groupnumber, peer_id, message):
        name = self.group_peername(groupnumber, peer_id)
        if len(name) and name != NAME:
            print('TOX> %s: %s' % (name, message))
            if message.startswith('>'):
                message = '\x0309%s\x03' % message

            self.irc_send(b'PRIVMSG %s :[%s]: %s\r\n' %
                          (self._sChannel, name, message))
            if message.startswith('^'):
                self.handle_command(message)

    def on_group_action(self, groupnumber, peer_id, action):
        """old? message type action?"""
        name = self.group_peername(groupnumber, peer_id)
        if len(name) and name != NAME:
            print('TOX> %s: %s' % (name, action))
            if action.startswith('>'):
                action = '\x0309%s\x03' % action
            self.irc_send('PRIVMSG %s :\x01ACTION [%s]: %s\x01\r\n' %
                    (self._sChannel, name, action))

    def on_friend_request(self, pk, message):
        LOG.info('Friend request from %s: %s' % (pk, message))
        self.add_friend_norequest(pk)
        LOG.info('Accepted.')

    def on_friend_message(self, friendid, message):
        if message == 'invite':
            if not self.tox_group_id is None:
                LOG.info('Inviting %s' % self.get_name(friendid))
                self.invite_friend(friendid, self.tox_group_id)
                return
            else:
                message = 'Waiting for GroupBot, please try again in 1 min.'

        self.ensure_exe(self.send_message, friendid, message)

    def send_both(self, content):
        self.ensure_exe(self.group_message_send, self.tox_group_id, content)
        self.irc_send('PRIVMSG %s :%s\r\n' % (self._sChannel, content))

    def handle_command(self, cmd):
        cmd = cmd[1:]
        if cmd in ['syncbot', 'echobot']:
            self.send_both(self.get_address())
        elif cmd == 'resync':
            sys.exit(0)
        elif cmd.startswith('remember '):
            args = cmd[9:].split(' ')
            subject = args[0]
            desc = ' '.join(args[1:])
            self.memory[subject] = desc
            if self.sMEMORY_DB:
                with open(self.sMEMORY_DB, 'w') as f:
                    pickle.dump(self.memory, f)
            self.send_both('Remembering ^%s: %s' % (subject, desc))
        elif self.memory.has_key(cmd):
            self.send_both(self.memory[cmd])


def iMain(oArgs):
    assert oTOX_OPTIONS
    assert oTOX_OARGS
    
    sChannel  = oArgs.irc_chan
    sIRC_HOST = oArgs.irc_host
    iIRC_PORT = oArgs.irc_port

    o = SyniTox(oTOX_OPTIONS, sChannel, sIRC_HOST, iIRC_PORT)
    o.start()
    ret = o.iLoop()
    return ret

def oToxygenToxOptions(oArgs):
    data = None
    tox_options = wrapper.tox.Tox.options_new()
    if oArgs.proxy_type:
        tox_options.contents.proxy_type = int(oArgs.proxy_type)
        tox_options.contents.proxy_host = bytes(oArgs.proxy_host, 'UTF-8')
        tox_options.contents.proxy_port = int(oArgs.proxy_port)
        tox_options.contents.udp_enabled = False
    else:
        tox_options.contents.udp_enabled = oArgs.udp_enabled
    if not os.path.exists('/proc/sys/net/ipv6'):
        oArgs.ipv6_enabled = False

    tox_options.contents.tcp_port = int(oArgs.tcp_port)

    # overrides
    tox_options.contents.local_discovery_enabled = False
    tox_options.contents.dht_announcements_enabled = True
    tox_options.contents.hole_punching_enabled = False
    tox_options.contents.experimental_thread_safety = False
    # REQUIRED!!
    if oArgs.ipv6_enabled and not os.path.exists('/proc/sys/net/ipv6'):
        LOG.warn('Disabling IPV6 because /proc/sys/net/ipv6 does not exist' + repr(oArgs.ipv6_enabled))
        tox_options.contents.ipv6_enabled = False
    else:
        tox_options.contents.ipv6_enabled = bool(oArgs.ipv6_enabled)

    if data:  # load existing profile
        tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['TOX_SAVE']
        tox_options.contents.savedata_data = c_char_p(data)
        tox_options.contents.savedata_length = len(data)
    else:  # create new profile
        tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['NONE']
        tox_options.contents.savedata_data = None
        tox_options.contents.savedata_length = 0

    #? tox_options.contents.log_callback = LOG
    if tox_options._options_pointer:
        # LOG.debug("Adding logging to tox_options._options_pointer ")
        ts.vAddLoggerCallback(tox_options, ts.on_log)
    else:
        LOG.warn("No tox_options._options_pointer " +repr(tox_options._options_pointer))

    return tox_options

def oArgparse(lArgv):
    parser = ts.oMainArgparser()
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile')
    # irc.libera.net #tox will not work over Tor
    parser.add_argument('--irc_host', type=str, default='irc.oftc.net')
    parser.add_argument('--irc_port', type=int, default=6667)
    parser.add_argument('--irc_chan', type=str, default='#tor')
    oArgs = parser.parse_args(lArgv)

    for key in ts.lBOOLEANS:
        if key not in oArgs: continue
        val = getattr(oArgs, key)
        setattr(oArgs, key, bool(val))

    if hasattr(oArgs, 'sleep'):
        if oArgs.sleep == 'qt':
            pass # broken or gevent.sleep(idle_period)
        elif oArgs.sleep == 'gevent':
            pass # broken or gevent.sleep(idle_period)
        else:
            oArgs.sleep = 'time'

    return oArgs

def main(lArgs=None):
    global     oTOX_OARGS
    
    if lArgs is None: lArgs = []
    oArgs = oArgparse(lArgs)
    oTOX_OARGS = oArgs
    global oTOX_OPTIONS
    oTOX_OPTIONS = oToxygenToxOptions(oArgs)
    ts.vSetupLogging(oArgs)
#    ts.setup_logging(oArgs)
    
    return iMain(oArgs)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

# Ran 34 tests in 86.589s OK (skipped=12)
