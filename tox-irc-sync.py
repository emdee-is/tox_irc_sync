# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import sys
import os
import socket
import select
import re
import pickle
import logging
import ctypes

from time import sleep
from threading import Thread
from random import shuffle
from OpenSSL import SSL

import wrapper
from wrapper.tox import Tox
from wrapper.toxav import ToxAV
import wrapper.toxcore_enums_and_consts as enums
from wrapper.toxcore_enums_and_consts import \
    TOX_CONNECTION, TOX_USER_STATUS, TOX_MESSAGE_TYPE, \
    TOX_SECRET_KEY_SIZE, TOX_FILE_CONTROL, TOX_ADDRESS_SIZE, \
    TOX_GROUP_PRIVACY_STATE, TOX_GROUP_ROLE
from wrapper_tests import socks

try:
    import support_testing as ts
except ImportError:
    import wrapper_tests.support_testing as ts
import wrapper.toxencryptsave as tox_encrypt_save


global LOG
LOG = logging.getLogger('app.'+'ts')


NAME = 'SyniTox'
# possible CA locations picks the first one
lCAs = ['/etc/ssl/cacert.pem']

bot_toxname = 'SyniTox'

# tox.py can be called by callbacks
def LOG_ERROR(a): print('EROR> '+a)
def LOG_WARN(a): print('WARN> '+a)
def LOG_INFO(a):
    bVERBOSE = hasattr(__builtins__, 'app') and app.oArgs.loglevel <= 20
    if bVERBOSE: print('INFO> '+a)
def LOG_DEBUG(a):
    bVERBOSE = hasattr(__builtins__, 'app') and app.oArgs.loglevel <= 10-1
    if bVERBOSE: print('DBUG> '+a)
def LOG_TRACE(a):
    bVERBOSE = hasattr(__builtins__, 'app') and app.oArgs.loglevel < 10
    if bVERBOSE: print('TRAC> '+a)

# https://wiki.python.org/moin/SSL
def ssl_verify_cb(HOST):
    # wrapps host
    def ssl_verify(*args):
        """
        callback for certificate validation
        should return true if verification passes and false otherwise
        """
        LOG.debug(f"ssl_verify {len(args)} {args}")
        ssl_conn, x509, error_num, depth, return_code = args
        if error_num != 0:
            return False
        if depth != 0:
            # don't validate names of root certificates
            return True

        if x509.get_subject().commonName == HOST:
            return True

        LOG.warn(f"ssl_verify {x509.get_subject().commonName} {HOST}")
        # allow matching subdomains
        have , want = x509.get_subject().commonName, HOST
        if len(have.split('.')) == len(want.split('.')) and len(want.split('.')) > 2:
            if have.split('.')[1:] == want.split('.')[1:]:
                return True

        return False

    return ssl_verify

class SyniTox(Tox):

    def __init__(self,
                 oArgs,
                 oOpts,
                 GROUP_BOT_PK = '',
                 sMEMORY_DB = ''
                 ):

        opts = oTOX_OPTIONS
        self._opts = opts
        self._oArgs = oArgs

        # self._oArgs.profile
        self.load_profile(self._opts,  self._oArgs, self._oArgs.password)
        Tox.__init__(self, tox_options=self._opts)

        self._address = self.self_get_address()
        self._app = None
        self._settings = {}
        
        self.av = self.AV
        self.irc = None
        self.bid = -1
        self._bRouted  = None
        self._ssl_context = None
        self._irc_id = ''
        self._toxes = None
        self.joined = None
        self.request = None
        self.memory = {}
        self.readbuffer = b''
        #? tox_group_id
        self._peers = []
        self._groups = {}
        
        self.sMEMORY_DB = sMEMORY_DB
        self.sGROUP_BOT_PK = GROUP_BOT_PK
        self.sGROUP_BOT_NUM = -1

    def load_profile(self, tox_options, oArgs, password=''):
        if oArgs.profile and os.path.exists(oArgs.profile):
            data = open(oArgs.profile, 'rb').read()

        else:
            data = None
        if data and self.has_password():
            data = self.pass_decrypt(data)
        if data:  # load existing profile
            tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['TOX_SAVE']
            tox_options.contents.savedata_data = ctypes.c_char_p(data)
            tox_options.contents.savedata_length = len(data)
        else:  # create new profile
            tox_options.contents.savedata_type = enums.TOX_SAVEDATA_TYPE['NONE']
            tox_options.contents.savedata_data = None
            tox_options.contents.savedata_length = 0

    def _save_profile(self, data=None):
        LOG.debug("_save_profile")
        data = data or self.get_savedata()
        if self.has_password():
            data = self.pass_encrypt(data)
        try:
            suf = f"{os.getpid()}"
            with open(self._oArgs.profile+suf, 'wb') as fl:
                fl.write(data)
            stat = os.stat(self._oArgs.profile+suf)
            if hasattr(stat, 'st_blocks'):
                assert stat.st_blocks > 0, f"Zero length file {self._oArgs.profile+suf}"
            os.rename(self._oArgs.profile+suf, self._oArgs.profile)
            LOG.info('Profile saved successfully to' +self._oArgs.profile)
        except Exception as e:
            LOG.warn(f"Profile save failed to {self._oArgs.profile}\n{e}")

    def start(self):
        self._tox = self
        self._toxes = tox_encrypt_save.ToxEncryptSave()
        self.self_set_name(self._oArgs.bot_name)
        self.self_set_status_message("Send me a message with the word 'invite'")
        LOG.info('Our ToxID: %s' % self.self_get_toxid())

        self.tox_group_id = None
        self.init_callbacks()

        if os.path.exists(self.sMEMORY_DB):
            with open(self.sMEMORY_DB, 'r') as f:
                self.memory = pickle.load(f)

        if self._oArgs.irc_ssl != '':
            self.start_ssl(self._oArgs.irc_host)

    def start_ssl(self, HOST):
        if not self._ssl_context:
            # TLSv1_3_METHOD does not exist
            context = SSL.Context(SSL.TLSv1_2_METHOD)
            context.set_options(SSL.OP_NO_SSLv2|SSL.OP_NO_SSLv3|SSL.OP_NO_TLSv1)
            if self._oArgs.irc_pem:
                val = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
                LOG.info('Using keyfile: %s' % self._oArgs.irc_pem)
                context.use_privatekey_file(self._oArgs.irc_pem)
            else:
                val = SSL.VERIFY_PEER
            context.set_verify(val, ssl_verify_cb(self._oArgs.irc_host))

            assert os.path.exists(self._oArgs.irc_ca), self._oArgs.irc_ca
            if os.path.isdir(self._oArgs.irc_ca):
                context.load_verify_locations(capath=self._oArgs.irc_ca)
            else:
                context.load_verify_locations(cafile=self._oArgs.irc_ca)
            if self._oArgs.irc_ssl == 'tls1.2':
                context.set_min_proto_version(SSL.TLS1_2_VERSION)
            elif self._oArgs.irc_ssl == 'tls1.3':
                context.set_min_proto_version(SSL.TLS1_3_VERSION)
            self._ssl_context = context
            
        return self._ssl_context

    def bRouted(self):
        if self._oArgs.network in ['local']:
            return True
        b = ts.bAreWeConnected()
        if b is None:
            i = os.system('ip route|grep ^def')
            if i > 0:
                b = False
            else:
                b = True
        self._bRouted = b
        return b

    def test_net(self, lElts=None, oThread=None, iMax=4):
        LOG.debug("test_net network=" +self._oArgs.network )
        # bootstrap
        lNodes = ts.generate_nodes(oArgs=self._oArgs,
                                   ipv='ipv4',
                                   udp_not_tcp=True)
        self._settings['current_nodes_udp'] = ts.sDNSClean(lNodes)
        if not lNodes:
            LOG.warn('empty generate_nodes udp')
        else:
            LOG.info(f'Called generate_nodes: udp {len(lNodes)}')

        lNodes = ts.generate_nodes(oArgs=self._oArgs,
                                   ipv='ipv4',
                                   udp_not_tcp=False)
        self._settings['current_nodes_tcp'] = ts.sDNSClean(lNodes)
        if not lNodes:
            LOG.warn('empty generate_nodes tcp')
        else:
            LOG.info(f'Called generate_nodes: tcp {len(lNodes)}')

        # if oThread and oThread._stop_thread: return
        return True

    def add_friend(self, pk):
        self.friend_add_norequest(pk)
        assert self.friend_exists(pk)
        assert pk in self.self_get_friend_list()
        friend_number = self.friend_by_public_key(pk)
        return friend_number

    def start_groups(self):
        if not self.bRouted(): return False
        if not self.group_is_connected(self.sGROUP_BOT_NUM):
                self.group_reconnect(self.sGROUP_BOT_NUM)
        if not self.group_is_connected(self.sGROUP_BOT_NUM):
             return False
        assert self.sGROUP_BOT_NUM
        num = self.sGROUP_BOT_NUM
        self.group_self_set_status(num, TOX_USER_STATUS['NONE'])

        # add myself as a peer in the group or am I in as founder?
        self.group_send_message(num, TOX_MESSAGE_TYPE['NORMAL'], "hi")
        
        # The code in tests_wrapper need extending and then
        # wiring up to here.
        #
        if self._oArgs.group_invite:
            pk = self._oArgs.group_invite
            if pk not in self.self_get_friend_list():
                friend_number = self.add_friend(pk)
            else:
                friend_number = self.friend_by_public_key(pk)
            b = self.group_invite_friend(num, friend_number)
            LOG.info(f"A PK to invite to the group {b}")
            return True

        if self._oArgs.group_moderator:
            pk = self._oArgs.group_moderator
            if pk not in self.self_get_friend_list():
                friend_number = self.add_friend(pk)
            else:
                friend_number = self.friend_by_public_key(pk)
            role = TOX_GROUP_ROLE['MODERATOR']
            # dunno
            peer_id = friend_number
            b = self.group_mod_set_role(num, peer_id, role)
            LOG.info("A PK to invite to the group as moderator {b}")
            return True
        
        if self._oArgs.group_ignore:
            pk = self._oArgs.group_ignore
            if pk not in self.self_get_friend_list():
                friend_number = self.add_friend(pk)
            else:
                friend_number = self.friend_by_public_key(pk)
            # dunno
            peer_id = friend_number
            b = self.group_toggle_set_ignore(num, peer_id, True)
            LOG.info("A PK to ignore in the group {b}")
            return True

        return None

    def create_group(self):
        privacy_state = TOX_GROUP_PRIVACY_STATE[self._oArgs.group_state.upper()]
        nick = self._oArgs.group_nick
        group_name = self._oArgs.group_name
        if not group_name:
            group_name = self._oArgs.bot_name +self._oArgs.irc_chan
            self._oArgs.group_name = group_name
        status = TOX_USER_STATUS['NONE']
        num = self.group_new(privacy_state, group_name, nick, status)
        assert num >= 0, num
        self.group_set_topic(num, f"{group_name}  IRC on {self._oArgs.irc_host}" )
        # self.tox_group_id = self.group_invite_accept(b'', friendid, nick)

        chat_id = self.group_get_chat_id(num)
        if self._oArgs.profile and os.path.exists(os.path.dirname(self._oArgs.profile)):
            f = os.path.splitext(self._oArgs.profile)[0] +'.chatid'
            open(f, 'rt').write(chat_id)
            LOG.info(f"Chat Id: {chat_id} written to {f}")
        else:
            LOG.info(f"Chat Id: {chat_id}")
        # dunno
        if self.self_get_friend_list():
            friendid = self.self_get_friend_list()[0]
            i = on_group_invite(friendid, b'', 0)
            assert i
            self.tox_group_id = i
        return num

    def join_group(self):
        password = self._oArgs.group_pass
        nick = self._oArgs.group_nick
        # is the chat_id the pk?
        chat_id = self._oArgs.group_chatid
        num = self.group_join(chat_id, password, nick, status='')
        self.sGROUP_BOT_NUM = num
        self.group_self_set_status(num, TOX_USER_STATUS['NONE'])
        return num

    def init_groups(self):
        LOG.debug(f"init_groups proxy={self._oArgs.proxy_type}")
        group_name = self._oArgs.bot_name +' Test ' +self._oArgs.irc_chan
        if self.sGROUP_BOT_NUM < 0:
            # ToDo: look for the first group of the profile
            i = self.group_get_number_groups()
            if i == 0:
                if not self.bRouted(): return False
                num = self.create_group()
                self.sGROUP_BOT_NUM = num
            elif i > 1:
                LOG.error('There are more than one groups in this profile')
                for ig in range(i):
                    LOG.warn(f"group #{ig} {self.group_self_get_name(ig)}")
                raise RuntimeError("select one of the groups at the cmdline")
            else:
                if not self.bRouted(): return False
                num = self.join_group()

        LOG.info(f"init_groups GROUP_BOT_PK={self.sGROUP_BOT_PK}")

        if self.bRouted():
            try:
                self.start_groups()
            except Exception as e:
                LOG.warn(f"init_groups self.start_groups {e}")
                return False
        # TOX_GROUP_ROLE['FOUNDER']
        return True

    def init_callbacks(self):
        # wraps self with
        LOG.info("Adding Tox init_callbacks")
        def gi_wrapped(iTox, friendid, invite_data, invite_len, *args):
            invite_data = str(invite_data, 'UTF-8')
            LOG.debug(f'on_group_invite {friendid} {invite_data}')
            self.on_group_invite(friendid, invite_data, 0)
        self.callback_group_invite(gi_wrapped, 0)
        
        def scs_wrapped(iTox, friendid, status, *args):
            LOG.debug(f'on_connection_status {friendId} {status}.')
            self.on_connection_status(friendid, status)
        self.callback_self_connection_status(scs_wrapped)
        
        def gm_wrapped(iTox, groupnumber, peer_id, type_, message, mlen, *args):
            message = str(message, 'UTF-8')
            LOG.debug(f'on_group_message {groupnumber} {peer_id} {message}')
            self.on_group_message(groupnumber, peer_id, message)
        self.callback_group_message(gm_wrapped, 0)
        
        def ga_wrapped(iTox, groupnumber, peer_id, type_, action, mlen, *args):
            LOG.debug(f'on_group_action(groupnumber, peer_id, action)')
            self.on_group_action(groupnumber, peer_id, action)
            
        #? self.callback_group_action(ga_wrapped, 0)
        def fr_wrapped(iTox, pk, message, mlen, *args):
            message = str(message, 'UTF-8')
            LOG.debug(f'on_friend_request(pk, message)')
            self.on_friend_request(pk, message)
        self.callback_friend_request(fr_wrapped)
        
        def fm_wrapped(iTox, peer_id, message, mlen, *args):
            message = str(message, 'UTF-8')
            LOG.debug(f'on_friend_request(peer_id, message)')
            self.on_friend_request(peer_id, message)
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
        nick = self._oArgs.irc_nick
        realname = self._oArgs.irc_name
        ident = self._oArgs.irc_ident

        LOG.info(f"irc_init proxy={self._oArgs.proxy_type}")
        try:
            if self._oArgs.proxy_type == 2:
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                                      self._oArgs.proxy_host,
                                      self._oArgs.proxy_port)
                irc = socks.socksocket()
            elif self._oArgs.proxy_type == 1:
                socks.setdefaultproxy(socks.PROXY_TYPE_HTTP,
                                      self._oArgs.proxy_host,
                                      self._oArgs.proxy_port)
                irc = socks.socksocket()
            else:
                irc = socket.socket()
            if self._oArgs.irc_ssl:
                if not self._ssl_context:
                    self.start_ssl(self._oArgs.irc_host)
                irc = SSL.Connection(self._ssl_context, irc)
                irc.connect((self._oArgs.irc_host, self._oArgs.irc_port))
                irc.do_handshake()
                LOG.info('IRC SSL connected ')
            else:
                irc.connect((self._oArgs.irc_host, self._oArgs.irc_port))
                LOG.info('IRC connected ')
                
        except ( SSL.Error, ) as e:
            LOG.warn(f"SSL error: {e.args}")
            return
        except (SSL.SysCallError,  ) as e:
            LOG.warn(f"SSL error: {e.args}")
            return
        except Exception as e:
            LOG.warn(f"Error: {e}")
            return

        self.irc = irc
        self.irc.send(bytes('NICK ' + nick + '\r\n', 'UTF-8' ))
        self.irc.send(bytes('USER %s %s bla :%s\r\n' % (
            ident, self._oArgs.irc_host, realname), 'UTF-8'))

    def dht_init(self):
        if not self.bRouted(): return
        if 'current_nodes_udp' not in self._settings:
            self.test_net()
        lNodes = self._settings['current_nodes_udp']
        shuffle(lNodes)
        if self._oArgs.proxy_type == 0:
            ts.bootstrap_udp(lNodes[:6], [self])
        else:
            if self._bRouted is None:
                LOG.info(f'UDP bootstapping 1')
                ts.bootstrap_udp([lNodes[0]], [self])
            if 'current_nodes_tcp' not in self._settings:
                self.test_net()
            lNodes = self._settings['current_nodes_tcp']
            shuffle(lNodes)
            LOG.info(f'TCP bootstapping 6')
            ts.bootstrap_tcp(lNodes[:6], [self])

    def get_all_groups(self):
        try:
            group_numbers = range(self._tox.group_get_number_groups())
        except Exception as e:
            return None
        groups = map(lambda n: self.get_group_by_number(n), group_numbers)

        return list(groups)

    def get_group_by_number(self, group_number):
        try:
            public_key = self._tox.group_get_chat_id(group_number)
#                LOG.info(f"group_get_chat_id {group_number} {public_key}")
            return self.get_group_by_public_key(public_key)
        except Exception as e:
            LOG.warn(f"group_get_chat_id {group_number} {e}")
            return None

    def get_group_by_public_key(self, public_key, group):
        self._groups[public_key] = group

    # -----------------------------------------------------------------------------------------------------------------
    # Group peers
    # -----------------------------------------------------------------------------------------------------------------

    def get_all_group_peers(self):
        return list()

    def get_group_peer_by_public_key(self, group, public_key):
        peer = group.get_peer_by_public_key(public_key)

        return self._get_group_peer(group, peer)

    def get_peer_by_id(self, peer_id):
        peers = list(filter(lambda p: p.id == peer_id, self._peers))
        if peers:
            return peers[0]
        else:
            LOG_WARN(f"get_peer_by_id empty peers for {peer_id}")
            return []

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
            try: self.irc.close()
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

    def irc_readlines(self):
        nick = self._oArgs.irc_nick
        pwd = self._oArgs.irc_pass
        fp = self._oArgs.irc_fp
        email = self._oArgs.irc_email

        self.readbuffer += self.irc.recv(4096)
        lines = self.readbuffer.split(b'\n')
        self.irc_check(lines)
        LOG.debug(f'Waited on IRC and got {len(lines)} lines.')
        self.readbuffer = lines.pop()
        for line in lines:
            line = str(line, 'UTF-8')
            l = line.rstrip().split()
            if len(l) < 2:
                print(line)
            elif l[1] not in ['372']:
                i = line.find(' ')
                print(line[i+1:])

            rx = re.match(r':(.*?)!.*? PRIVMSG %s :(.*?)\r' %
                    self._oArgs.irc_chan, line, re.S)
            if rx:
                self.relay_message(rx)
            elif l[0] == 'PING':
               self.irc_send('PONG %s\r\n' % l[1])
            elif len(l) < 2:
                pass
            elif l[1] == '376':
                # :End of /MOTD command
                if email == '':
                    self.irc.send(bytes('PRIVMSG NickServ IDENTIFY %s %s\r\n'
                            % (nick, pwd,), 'UTF-8'))
                else:
                    self.irc.send(bytes('PRIVMSG NickServ REGISTER %s %s\r\n'
                            % (pwd, email,), 'UTF-8'))
                if False and fp:
                    LOG.info(f"PRIVMSG NickServ CERT ADD")
#                               self.irc.send(bytes(f'PRIVMSG NickServ CERT ADD {fp}\r\n', 'UTF-8'))
                #
                self.irc.send(bytes('JOIN %s\r\n' % self._oArgs.irc_chan, 'UTF-8'))
                # put off init_groups until you have joined IRC
                self.init_groups()
                # Make sure we are in

            elif l[1] == '042':
                # 042 SyniTox 8VQAADOD0 :your unique ID
                self._irc_id = line.replace(' :your unique ID',''). \
                    replace('042 '+nick +' ', '')

            elif l[1] == '421':
                # 421 SyniTox .PRIVMSG :Unknown command
                pass
            elif l[1] == '477':
                #477 SyniTox #tor :Cannot join channel (Need to be  identified and verified to join this channel, '/msg NickServ help' to learn how to register and verify.)
                LOG.info(f"PRIVMSG NickServ STATUS {nick}")
                i = line.find("'/msg NickServ help'")
                if i > 0:
                    line = line[:i]
                raise RuntimeError(line)

    def relay_message(self, rx):
        print('IRC> %s: %s' % rx.groups())
        msg = '[%s]: %s' % rx.groups()
        content = rx.group(2)

        if self.sGROUP_BOT_NUM >= 0:
            if content[1:].startswith('ACTION '):
                action = '[%s]: %s' % (rx.group(1),
                        rx.group(2)[8:-1])
                type_ = TOX_MESSAGE_TYPE['ACTION']
                self.ensure_exe(self.group_send_message,
                        self.sGROUP_BOT_NUM, type_, action)
            else:
                type_ = TOX_MESSAGE_TYPE['NORMAL']
                self.ensure_exe(self.group_send_message,
                                self.sGROUP_BOT_NUM, type_, msg)

        if content.startswith('^'):
            self.handle_command(content)

    def spin(self, n=20):
        readable = False
        waiti = 0
        while not readable:
            waiti += 1
            readable, _, _ = select.select([self.irc], [], [], n/1000.0 )
            self.do(n)
            if waiti > 100: break
        return readable

    def iLoop(self):
        group_connected = False
        routed = None
        self.joined = False
        self.request = False
        iCount = 0
        iDelay = 10
        
        nick = self._oArgs.irc_nick
        pwd = self._oArgs.irc_pass
        email = self._oArgs.irc_email
        LOG.info(f"Looping for Tox and IRC connections")
        if iCount < self._oArgs.max_sleep:
            while True:
                iCount += 1
#                LOG.debug(f"Looping {iCount}")
                b = self.bRouted()
                if not b:
                    self.unroute()
                    group_connected = False
                    iDelay = iDelay + iDelay // 10
                    if routed != b:
                        if iCount % 10 == 1:
                            LOG.info(f'Not routed {iCount} sleeping {iDelay} seconds')
                    sleep(iDelay)
                    continue
                elif b != routed or routed is None:
                    LOG.debug(f'Routed {iCount} - resetting count')
                    iDelay = 10
                routed = b

                dht_conneted = self.self_get_connection_status()
                if not dht_conneted:
                    self.dht_init()
                    LOG.info(f'Not DHT connected {iCount} iterating {10 + iDelay} seconds')
                    self.do(10 + iDelay)
                    #drop through

                if not group_connected and dht_conneted:
                    LOG.info('Connected to DHT.')
                    group_connected = True
                    try:
                        #? self.bid = self.friend_by_public_key(self.sGROUP_BOT_PK)
                        r = self.group_reconnect(self.sGROUP_BOT_NUM)
                        LOG.info(f'Connected to group {r}')
                    except ctypes.ArgumentError as e:
                        self.bid = None

                    if self.bid == None:
                        self.ensure_exe(self.friend_add_norequest, self.sGROUP_BOT_PK)
                        LOG.info(f'friend_add_n to group {self.sGROUP_BOT_PK[:8]}')
                        self.bid = self.friend_by_public_key(self.sGROUP_BOT_PK)
                        LOG.info(f'Added to group {self.bid}')
                        num = self.sGROUP_BOT_NUM
                        my_pk = self.group_self_get_public_key(num)
                        LOG.info(f'Connected to group as {my_pk[:8]}')

                if group_connected and not dht_conneted:
                    LOG.info('Disconnected from DHT.')
                    self.dht_init()
                    group_connected = False

                if not self.irc:
                    LOG.info('Disconnected from IRC.')
                    self.irc_init()
                    if not self.irc:
                        self.do(20)
                        continue

                LOG.info('Waiting on IRC.')
                iDelay = 10

                readable = self.spin(20)
                if not readable:
                    LOG.info('Waited on IRC but nothing to read.')
                    continue
                try:
                    self.irc_readlines()
                except Exception as e:
                    LOG.exception(f'IRC Error during read: {e}')
                    # close irc?
                    try: self.irc.close()
                    except: pass
                    self.irc = None
                    self.irc_init()
                    continue
                
        return 0

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
        # scs_wrapped
        if not self.request and not self.joined \
                and friendId == self.bid and status:
            LOG.info('Groupbot online, trying to get invited to group chat.')
            self.request = True
            type_ = TOX_MESSAGE_TYPE['NORMAL']
            # the bot is sending a message to myself self.bid
            self.ensure_exe(self.friend_send_message, self.bid, type_, 'invite')

    # gi_wrapped
    def on_group_invite(self, friendid, invite_data, user_data):
        if not self.joined:
            self.joined = True
            nick = self._oArgs.group_nick
            self.tox_group_id = self.group_invite_accept(invite_data, friendid, nick)
            LOG.info('Joined groupchat.')

    def group_peername(self, groupnumber, peer_id):
        #dunno
        return ''

    def on_group_message(self, groupnumber, peer_id, message):
        name = self.group_peername(groupnumber, peer_id)
        if len(name) and name != NAME:
            print('TOX> %s: %s' % (name, message))
            if message.startswith('>'):
                message = '\x0309%s\x03' % message

            self.irc_send(b'PRIVMSG %s :[%s]: %s\r\n' %
                          (self._oArgs.irc_chan, name, message))
            if message.startswith('^'):
                self.handle_command(message)

    def on_group_action(self, groupnumber, peer_id, action):
        """old? message type action?"""
        name = self.group_peername(groupnumber, peer_id)
        if name and name != NAME:
            print('TOX> %s: %s' % (name, action))
            if action.startswith('>'):
                action = '\x0309%s\x03' % action
            self.irc_send('PRIVMSG %s :\x01ACTION [%s]: %s\x01\r\n' %
                    (self._oArgs.irc_chan, name, action))

    def on_friend_request(self, pk, message):
        LOG.info('Friend request from %s: %s' % (pk, message))
        self.friend_add_norequest(pk)
        LOG.info('Accepted.')

    def on_friend_message(self, friendid, message):
        if message.startswith('invite'):
            if not self.tox_group_id is None:
                LOG.info('Inviting %s' % self.friend_get_name(friendid))
                self.group_invite_friend(self.sGROUP_BOT_NUM, friendid)
                return
            else:
                message = 'Waiting for GroupBot, please try again in 1 min.'

        type_ = TOX_MESSAGE_TYPE['NORMAL']
        self.ensure_exe(self.friend_send_message, friendid, type_, message)

    def send_both(self, content):
        type_ = TOX_MESSAGE_TYPE['NORMAL']
        self.ensure_exe(self.group_send_message, self.sGROUP_BOT_NUM, type_, content)
        self.irc_send('PRIVMSG %s :%s\r\n' % (self._oArgs.irc_chan, content))

    def handle_command(self, cmd):
        cmd = cmd[1:]
        if cmd in ['syncbot', 'echobot']:
            self.send_both(self.self_get_address())
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

    def is_data_encrypted(self, data):
        return len(data) > 0 and self._toxes.is_data_encrypted(data)

    def pass_encrypt(self, data):
        return self._toxes.pass_encrypt(data, self._oArgs.password)

    def has_password(self):
        return self._oArgs.password

    def pass_decrypt(self, data):
        return self._toxes.pass_decrypt(data, self._oArgs.password)


def iMain(oArgs, oOpts):
    assert oTOX_OPTIONS
    assert oTOX_OARGS

    try:
        o = SyniTox(oArgs, oOpts)
        __builtins__.app = o
        o.start()
        ret = o.iLoop()
    except KeyboardInterrupt:
        ret = 0
    except ( SSL.Error, ) as e:
        LOG.error(f"SSL error: {e.args}")
        ret = 1
    except (SSL.SysCallError,  ) as e:
        # OpenSSL.SSL.SysCallError: (9, 'EBADF')
        LOG.error(f"SSL error: {e.args}")
        ret = 1
    except Exception as e:
        LOG.exception(f'Error running program:\n{e}')
        ret = 2
    else:
        ret = 0
    o.quit()
    return ret

def oToxygenToxOptions(oArgs):
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

    #? tox_options.contents.log_callback = LOG
    if oArgs.trace_enabled and tox_options._options_pointer:
        # LOG.debug("Adding logging to tox_options._options_pointer ")
        ts.vAddLoggerCallback(tox_options, ts.on_log)
    else:
        LOG.warn("No tox_options._options_pointer " +repr(tox_options._options_pointer))

    return tox_options

def oArgparse(lArgv):
    parser = ts.oMainArgparser()
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile - new groups will be saved there')

    CAcs = []
    for elt in lCAs:
        if os.path.exists(elt):
            CAcs.append(elt)
            break

    parser.add_argument('--bot_name', type=str, default=bot_toxname)
    parser.add_argument('--max_sleep', type=int, default=3600,
                        help="max time to sleep waiting for routing before exiting")

    parser.add_argument('--password', type=str, default='',
                        help="password for the profile if encrypted")
#        parser.add_argument('--irc_type', type=str, default='',
#                            choices=['', 'startls', 'direct')
    # does host == connect ?
    parser.add_argument('--irc_host', type=str, default='irc.oftc.net',
                        help="irc.libera.chat will not work over Tor")
    parser.add_argument('--irc_port', type=int, default=6667,
                        help="default 6667, but may be 6697 with SSL")
    parser.add_argument('--irc_chan', type=str, default='#tor',
                        help="IRC channel to join - include the #")
    #
    parser.add_argument('--irc_ssl', type=str, default='',
                        help="TLS version; empty is no SSL",
                        choices=['', 'tls1.2', 'tls1.3'])
    parser.add_argument('--irc_ca', type=str,
                        help="Certificate Authority file or directory",
                        default=CAcs[0])
    parser.add_argument('--irc_pem', type=str, default='',
                        help="Certificate and key as pem; use openssl req -x509 -nodes -newkey rsa:2048")
    parser.add_argument('--irc_fp', type=str, default='',
                        help="fingerprint of the pem added with CERT ADD; use openssl x509 -noout -fingerprint -SHA1 -text")
    parser.add_argument('--irc_nick', type=str, default='',
                        help="IRC Nickname")
    parser.add_argument('--irc_name', type=str, default='',
                        help="Third field in USER")
    parser.add_argument('--irc_ident', type=str, default='',
                        help="First field in USER")
    parser.add_argument('--irc_pass', type=str, default='',
                        help="password for INDENTIFY or REGISTER")
    parser.add_argument('--irc_email', type=str, default='',
                        help="Use email to REGISTER with _pass")
    #
    parser.add_argument('--group_pass', type=str, default='',
                        help="password for the group - optional")
    parser.add_argument('--group_state', type=str, default='public',
                        choices=['public','private'],
                        help="state for the group - default public")
    parser.add_argument('--group_chatid', type=str, default='',
                        help="chat_id of the group - will be created on first use")
    parser.add_argument('--group_name', type=str, default='',
                        help="name for the group")
    parser.add_argument('--group_nick', type=str, default='',
                        help="Nickname of the group founder")
    parser.add_argument('--group_invite', type=str, default='',
                        help="A PK to invite to the group")
    parser.add_argument('--group_moderator', type=str, default='',
                        help="A PK to invite to the group as moderator")
    parser.add_argument('--group_ignore', type=str, default='',
                        help="A PK to ignore by the group")

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

    if lArgs is None: lArgs = []
    global     oTOX_OARGS
    oTOX_OARGS = oArgparse(lArgs)
    global oTOX_OPTIONS
    oTOX_OPTIONS = oToxygenToxOptions(oTOX_OARGS)
    ts.vSetupLogging(oTOX_OARGS)
#    ts.setup_logging(oArgs)

    return iMain(oTOX_OARGS, oTOX_OPTIONS)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

# Ran 34 tests in 86.589s OK (skipped=12)
