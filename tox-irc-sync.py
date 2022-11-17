# -*- mode: python; indent-tabs-mode: nil; py-indent-offset: 4; coding: utf-8 -*-

import ctypes
import logging
import os
import pickle
import re
import select
import socket
import sys
import traceback
from errno import errorcode
from random import shuffle
from time import sleep

from OpenSSL import SSL

import wrapper
import wrapper.toxcore_enums_and_consts as enums
import wrapper_tests
from wrapper.tox import Tox
from wrapper.toxav import ToxAV
from wrapper.toxcore_enums_and_consts import (TOX_ADDRESS_SIZE, TOX_CONNECTION,
                                              TOX_FILE_CONTROL,
                                              TOX_GROUP_PRIVACY_STATE,
                                              TOX_GROUP_ROLE, TOX_MESSAGE_TYPE,
                                              TOX_SECRET_KEY_SIZE,
                                              TOX_USER_STATUS)
from wrapper_tests import socks

try:
    import support_testing as ts
except ImportError:
    import wrapper_tests.support_testing as ts

import wrapper.toxencryptsave as tox_encrypt_save

global LOG
LOG = logging.getLogger('app.'+'ts')
import warnings

warnings.filterwarnings('ignore')

class SyniToxError(BaseException): pass

NAME = 'SyniTox'
sMSG = 'MSG'
sMSG = 'PRIVMSG'
SSL_TOR_RANGE = '172.'
# possible CA locations picks the first one
lCAs = [# debian and gentoo
        '/etc/ssl/certs/',
    ]
lCAfs = SSL._CERTIFICATE_FILE_LOCATIONS
# openssl ciphers -s -v|grep 1.3 > /tmp/v1.3
lOPENSSL_13_CIPHERS = ['TLS_AES_256_GCM_SHA384',
                       'TLS_CHACHA20_POLY1305_SHA256',
                       'TLS_AES_128_GCM_SHA256']
lOPENSSL_12_CIPHERS = ['ECDHE-ECDSA-AES256-GCM-SHA384',
                       'ECDHE-RSA-AES256-GCM-SHA384',
                       'DHE-RSA-AES256-GCM-SHA384',
                       'ECDHE-ECDSA-CHACHA20-POLY1305',
                       'ECDHE-RSA-CHACHA20-POLY1305',
                       'DHE-RSA-CHACHA20-POLY1305',
                       'ECDHE-ECDSA-AES128-GCM-SHA256',
                       'ECDHE-RSA-AES128-GCM-SHA256',
                       'DHE-RSA-AES128-GCM-SHA256',
                       'ECDHE-ECDSA-AES256-SHA384',
                       'ECDHE-RSA-AES256-SHA384',
                       'DHE-RSA-AES256-SHA256',
                       'ECDHE-ECDSA-AES128-SHA256',
                       'ECDHE-RSA-AES128-SHA256',
                       'DHE-RSA-AES128-SHA256',
                       'AES256-GCM-SHA384',
                       'AES128-GCM-SHA256',
                       'AES256-SHA256',
                       'AES128-SHA256'
                       ]
bot_toxname = 'SyniTox'
iSocks5ErrorMax = 5
iSocks5Error = 0

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
def ssl_verify_cb(host, override=False):
    assert host
    # wrapps host
    def ssl_verify(*args):
        """
        callback for certificate validation
        should return true if verification passes and false otherwise
        """
        LOG.debug(f"ssl_verify {len(args)} {args}")

        # app.ts WARNING SSL error: ([('SSL routines', 'tls_process_server_certificate', 'certificate verify failed')],)                                              # on .onion - fair enough    
        if override: return True
        
        ssl_conn, x509, error_num, depth, return_code = args
        if error_num != 0:
            LOG.warn(f"ssl_verify error_num={error_num} {errorcode.get(error_num)}")
            return False
        if depth != 0:
            # don't validate names of root certificates
            return True

        if x509.get_subject().commonName == host:
            return True

        # allow matching subdomains
        have , want = x509.get_subject().commonName, host
        if len(have.split('.')) == len(want.split('.')) and len(want.split('.')) > 2:
            if have.split('.')[1:] == want.split('.')[1:]:
                LOG.warn(f"ssl_verify accepting {x509.get_subject().commonName} for {host}")
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
        self._oargs = oArgs

        # self._oargs.profile
        self.load_profile(self._opts,  self._oargs, self._oargs.password)
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
            with open(self._oargs.profile+suf, 'wb') as fl:
                fl.write(data)
            stat = os.stat(self._oargs.profile+suf)
            if hasattr(stat, 'st_blocks'):
                assert stat.st_blocks > 0, f"Zero length file {self._oargs.profile+suf}"
            os.rename(self._oargs.profile+suf, self._oargs.profile)
            LOG.info('Profile saved successfully to' +self._oargs.profile)
        except Exception as e:
            LOG.warn(f"Profile save failed to {self._oargs.profile}\n{e}")

    def start(self):
        self._tox = self
        self._toxes = tox_encrypt_save.ToxEncryptSave()
        self.self_set_name(self._oargs.bot_name)
        self.self_set_status_message("Send me a message with the word 'invite'")
        LOG.info('Our ToxID: %s' % self.self_get_toxid())

        self.tox_group_id = None
        self.init_callbacks()

        if os.path.exists(self.sMEMORY_DB):
            with open(self.sMEMORY_DB, 'r') as f:
                self.memory = pickle.load(f)

    def start_ssl(self, HOST):
        if not self._ssl_context:
            try:
                OP_NO_TLSv1_3 = SSL._lib.SSL_OP_NO_TLSv1_3
            except AttributeError:
                if self._oargs.irc_ssl == 'tlsv1.3':
                    LOG.warning("SSL._lib.SSL_OP_NO_TLSv1_3 is not supported")
                    LOG.warning("Downgrading SSL to tlsv1.2 ")
                    self._oargs.irc_ssl = 'tlsv1.2'
                else:
                    LOG.debug("SSL._lib.SSL_OP_NO_TLSv1_3 is not supported")
            else:
                LOG.debug("SSL._lib.SSL_OP_NO_TLSv1_3 is supported")
                    
            if self._oargs.irc_connect.endswith('.onion') or \
                self._oargs.irc_connect.startswith(SSL_TOR_RANGE):
                override = True
            else:
                override = False
            # TLSv1_3_METHOD does not exist
            context = SSL.Context(SSL.TLS_CLIENT_METHOD) # TLSv1_2_METHOD
            # SSL.OP_NO_TLSv1_1 is allowed
            context.set_options(SSL.OP_NO_SSLv2|SSL.OP_NO_SSLv3|SSL.OP_NO_TLSv1)
            
            if self._oargs.irc_crt and self._oargs.irc_key:
                val = SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT
                if True: # required!
                    key = self._oargs.irc_crt
                    assert os.path.exists(key), key
                    LOG.info('Using keyfile: %s' % key)
                    context.use_certificate_file(key, filetype=SSL.FILETYPE_PEM)
                if True: # required!
                    key = self._oargs.irc_key
                    assert os.path.exists(key), key
                    LOG.info('Using keyfile: %s' % key)
                    context.use_privatekey_file(key, filetype=SSL.FILETYPE_PEM)
                #? load_client_ca
                def SSL_hands_cb(oConn,iLine,iRet):
                    # where in the SSL handshake the function was called, and
                    # the return code from a internal function call
                    print(f"iLine={iLine}, iRet={iRet}")
                context.set_info_callback(SSL_hands_cb)
                def keylog_callback(oConn,s):
                    print(s)
                # context.set_keylog_callback(keylog_callback)
            else:
                val = SSL.VERIFY_PEER
            context.set_verify(val, ssl_verify_cb(HOST, override))

            if self._oargs.irc_cafile:
                # context.load_verify_locations(capath=self._oargs.irc_ca)
                context.load_verify_locations(self._oargs.irc_cafile, capath=self._oargs.irc_cadir)
            elif self._oargs.irc_cadir:
                context.load_verify_locations(None, capath=self._oargs.irc_cadir)
            if self._oargs.irc_ssl == 'tlsv1.1':
                context.set_min_proto_version(SSL.TLS1_1_VERSION)
            elif self._oargs.irc_ssl == 'tlsv1.2':
                context.set_cipher_list(bytes(':'.join(['DEFAULT@SECLEVEL=1']+lOPENSSL_12_CIPHERS), 'UTF-8'))
                context.set_min_proto_version(SSL.TLS1_2_VERSION)
            elif self._oargs.irc_ssl == 'tlsv1.3':
                context.set_cipher_list(bytes(':'.join(['DEFAULT@SECLEVEL=1']+lOPENSSL_13_CIPHERS), 'UTF-8'))                
                context.set_min_proto_version(SSL.TLS1_3_VERSION)
            self._ssl_context = context
            
        return self._ssl_context

    def bRouted(self):
        if self._oargs.network in ['local']:
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
        LOG.debug("test_net network=" +self._oargs.network )
        # bootstrap
        lNodes = ts.generate_nodes(oArgs=self._oargs,
                                   ipv='ipv4',
                                   udp_not_tcp=True)
        self._settings['current_nodes_udp'] = ts.lDNSClean(lNodes)
        if not lNodes:
            LOG.warn('empty generate_nodes udp')
        else:
            LOG.info(f'Called generate_nodes: udp {len(lNodes)}')

        lNodes = ts.generate_nodes(oArgs=self._oargs,
                                   ipv='ipv4',
                                   udp_not_tcp=False)
        self._settings['current_nodes_tcp'] = ts.lDNSClean(lNodes)
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
        if self._oargs.group_invite:
            pk = self._oargs.group_invite
            if pk not in self.self_get_friend_list():
                friend_number = self.add_friend(pk)
            else:
                friend_number = self.friend_by_public_key(pk)
            b = self.group_invite_friend(num, friend_number)
            LOG.info(f"A PK to invite to the group {b}")
            return True

        if self._oargs.group_moderator:
            pk = self._oargs.group_moderator
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
        
        if self._oargs.group_ignore:
            pk = self._oargs.group_ignore
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
        privacy_state = TOX_GROUP_PRIVACY_STATE[self._oargs.group_state.upper()]
        nick = self._oargs.group_nick
        status = TOX_USER_STATUS['NONE']
        group_name = self._oargs.group_name
        num = self.group_new(privacy_state, group_name, nick, status)
        assert num >= 0, num
        self.group_set_topic(num, f"{group_name}  IRC on {self._oargs.irc_host}" )
        # self.tox_group_id = self.group_invite_accept(b'', friendid, nick)

        chat_id = self.group_get_chat_id(num)
        if self._oargs.profile and os.path.exists(os.path.dirname(self._oargs.profile)):
            f = os.path.splitext(self._oargs.profile)[0] +'.chatid'
            open(f, 'rt').write(chat_id)
            LOG.info(f"Chat Id: {chat_id} written to {f}")
        else:
            LOG.info(f"Chat Id: {chat_id}")
        # dunno
        if self.self_get_friend_list():
            friendid = self.self_get_friend_list()[0]
            i = self.on_group_invite(friendid, b'', 0)
            assert i
            self.tox_group_id = i
        return num

    def join_group(self):
        password = self._oargs.group_pass
        nick = self._oargs.group_nick
        # is the chat_id the pk?
        chat_id = self._oargs.group_chatid
        if not chat_id: return -1
        num = self.group_join(chat_id, password, nick, status='')
        self.sGROUP_BOT_NUM = num
        self.group_self_set_status(num, TOX_USER_STATUS['NONE'])
        return num

    def init_groups(self):
        LOG.debug(f"init_groups proxy={self._oargs.proxy_type}")
        if not self.bRouted(): return
        try:
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
        
            self.start_groups()
        except Exception as e:
            LOG.warn(f"init_groups self.start_groups {e}")
            return False
        # TOX_GROUP_ROLE['FOUNDER']
        return True

    def init_callbacks(self):
        return
        # wraps self with
        LOG.info("Adding Tox init_callbacks")
        def gi_wrapped(iTox, friendid, invite_data, invite_len, *args):
            invite_data = str(invite_data, 'UTF-8')
            LOG.debug(f'on_group_invite {friendid} {invite_data}')
            self.on_group_invite(friendid, invite_data, 0)
        self.callback_group_invite(gi_wrapped, 0)
        
        def scs_wrapped(iTox, friendid, status, *args):
            LOG.debug(f'on_connection_status {friendid} {status}.')
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

    def diagnose_ciphers(self, irc):
        cipher_name = irc.get_cipher_name()
        LOG.info(f"diagnose_ciphers cipher_name={irc.get_cipher_name()}")
        LOG.debug(f"diagnose_ciphers get_cipher_list={irc.get_cipher_list()}")
        cipher_list=irc.get_cipher_list()
        for ci in lOPENSSL_13_CIPHERS:
            if ci in cipher_list: LOG.debug(f"server supports v1.3 cipher {ci}")
        for cert in irc.get_peer_cert_chain():
            # x509 objects - just want the /CN
            LOG.debug(f"{cert.get_subject().CN} {cert.get_issuer()}")

        cipher_name = irc.get_cipher_name()
        if self._oargs.irc_ssl == 'tlsv1.2':
            assert cipher_name in lOPENSSL_12_CIPHERS or \
                 cipher_name in lOPENSSL_13_CIPHERS, cipher_name
        elif self._oargs.irc_ssl == 'tlsv1.3':
            assert cipher_name in lOPENSSL_13_CIPHERS, cipher_name

        got = irc.get_protocol_version_name().lower()
        if got > self._oargs.irc_ssl:
            LOG.debug(f"Got: {irc.get_protocol_version_name().lower()} asked for {self._oargs.irc_ssl}")
        elif got < self._oargs.irc_ssl:
            LOG.warn(f"Got: {irc.get_protocol_version_name().lower()} asked for {self._oargs.irc_ssl}")
        LOG.info(f"diagnose_ciphers {str(irc.get_state_string(), 'UTF-8')}")
        
    def irc_init(self):
        global iSocks5Error
        
        if not self.bRouted(): return
        nick = self._oargs.irc_nick
        realname = self._oargs.irc_name
        ident = self._oargs.irc_ident
        LOG.info(f"irc_init proxy={self._oargs.proxy_type} SSL={self._oargs.irc_ssl}")
        try:
            if self._oargs.proxy_type == 2:
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                                      self._oargs.proxy_host,
                                      self._oargs.proxy_port)
                irc = socks.socksocket()
                iTIMEOUT = 15
            elif self._oargs.proxy_type == 1:
                socks.setdefaultproxy(socks.PROXY_TYPE_HTTP,
                                      self._oargs.proxy_host,
                                      self._oargs.proxy_port)
                irc = socks.socksocket()
                iTIMEOUT = 15
            else:
                irc = socket.socket()
                iTIMEOUT = 10
            try:
                ip = ts.sDNSLookup(self._oargs.irc_connect)
            except Exception as e:
                LOG.warn(f"{self._oargs.irc_host} errored in resolve {e}")
                ip = self._oargs.irc_connect
            else:
                if not ip:
                    LOG.warn(f"{self._oargs.irc_host} did not resolve.")
                    ip = self._oargs.irc_connect
            # https://github.com/pyca/pyopenssl/issues/168
            if self._oargs.irc_ssl:
                if not self._ssl_context:
                    self.start_ssl(self._oargs.irc_connect)
                irc = SSL.Connection(self._ssl_context, irc)
                irc.connect((ip, self._oargs.irc_port))
                irc.set_tlsext_host_name(bytes(self._oargs.irc_host, 'UTF-8'))
                while True:
                    try:
                        irc.do_handshake()
                    except SSL.WantReadError:
                        rd,_,_ = select.select([irc], [], [], irc.gettimeout())
                        if not rd:
                            raise socket.timeout('timeout')
                        continue
                    except SSL.Error as e: # noqa
                        raise
                    break
                self.diagnose_ciphers(irc)
            else:
                irc.connect((ip, self._oargs.irc_port))
            LOG.info(f"IRC SSL={self._oargs.irc_ssl} connected ")

        except (wrapper_tests.socks.GeneralProxyError, wrapper_tests.socks.Socks5Error) as e: # noqa
            iSocks5Error += 1
            if iSocks5Error >= iSocks5ErrorMax:
                raise SyniToxError(f"{e.args}")
            if len(e.args[0]) == 2:
                if e.args[0][0] == 2:
                    LOG.warn(f"Socks5Error: do you have Tor SafeSocks set? {e.args[0]}")
                elif e.args[0][0] == 5:
                    # (5, 'Connection refused')
                    LOG.warn(f"Socks5Error: do you have Tor running? {e.args[0]}")
                    raise SyniToxError(f"{e.args}")
                elif e.args[0][0] in [1, 6, 0]:
                    # (0, "connection closed unexpectedly")
                    # (6, 'TTL expired'),
                    # 1, ('general SOCKS server failure')
                    # Missing mapping for virtual address '172.17.140.117'. Refusing.
                    LOG.warn(f"Socks5Error: {e.args[0]}")
                    return
            else:
                LOG.error(f"Socks5Error: {e.args}")
                raise SyniToxError(f"{e.args}")
        except socket.timeout as e:
            LOG.warn(f"socket error: {e.args}")
            return
        except ( ConnectionRefusedError) as e:
            raise SyniToxError(f"{e.args}")
        except ( SSL.Error, ) as e:
            iSocks5Error += 1
            if iSocks5Error >= iSocks5ErrorMax:
                raise SyniToxError(f"{e.args}")
            LOG.warn(f"SSL error: {e.args}")
            return
        except (SSL.SysCallError,  ) as e:
            LOG.warn(f"SSLSyscall error: {e.args}")
            LOG.warn(traceback.format_exc())
            return
        except Exception as e:
            LOG.warn(f"Error: {e}")
            LOG.warn(traceback.format_exc())
            return

        self.irc = irc
        self.irc.send(bytes('CAP ' + 'LS' + '\r\n', 'UTF-8' ))
        self.irc.send(bytes('CAP ' + 'REQ :multi-prefix' + '\r\n', 'UTF-8'))
        self.irc.send(bytes('CAP ' + 'END' + '\r\n', 'UTF-8' ))
        # withh or without  self._oargs.irc_pem:
        LOG.info("Sent CAP sending NICK and USER")
        self.irc.send(bytes('NICK ' + nick + '\r\n', 'UTF-8' ))
        self.irc.send(bytes('USER %s %s bla :%s\r\n' % (
                      self._oargs.irc_ident,
                      self._oargs.irc_host,
                      self._oargs.irc_name), 'UTF-8'))

         # OSError: [Errno 9] Bad file descriptor
         
    def dht_init(self):
        if not self.bRouted(): return
        if 'current_nodes_udp' not in self._settings:
            self.test_net()
        lNodes = self._settings['current_nodes_udp']
        shuffle(lNodes)
        if self._oargs.proxy_type == 0:
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
        except Exception as e: # noqa
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
                lines = str(line, 'UTF-8').strip().split()
                print(' '.join(lines[1:]))
        else:
            for line in lines[:5]:
                line = str(line, 'UTF-8').strip().lower()
                if 'banned' in line:
                    raise SyniToxError(line)
                if 'error' in line and 'closing' in line:
                    raise SyniToxError(line)

    def irc_readlines(self):
        nick = self._oargs.irc_nick
        pwd = self._oargs.irc_pass
        fp = self._oargs.irc_fp
        email = self._oargs.irc_email

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
            elif l[1] in ['PING']:
                print(line)
            elif l[1] in ['372']:
                LOG.info('MOTD')
            elif l[1] not in ['372', '353']:
                i = line.find(' ')
                print(line[i+1:])
            
            rx = re.match(r':(.*?)!.*? PRIVMSG %s :(.*?)\r' %
                    self._oargs.irc_chan, line, re.S)
            if l[0] == 'QUIT':
                LOG.info('QUIT')
                return
            if len(l) == 1:
               self.irc_send('PING %s\r\n' % '#tor')
            elif l[0] == 'PING':
               self.irc_send('PONG %s\r\n' % l[1])
            elif rx:
                self.relay_message(rx)
            elif len(l) < 2:
                pass
            elif l[1] in ['461', '431']:
                pass
            elif l[1] in ['433']:
                # maybe should be an outright fail
                if self._oargs.irc_ssl:
                    LOG.warn("Maybe the certificate was not received")
                #? raise SyniToxError(line)
                # sometimes but not always:
                # 433 * SyniTox :Nickname is already in use.
                # app.ts ERROR SSL error: (32, 'EPIPE')
                # or instead
                # 451 *  :Register first.
                # error :closing link: 185.38.175.131 (registration timed out)
                # or instead: just
                # app.ts ERROR SSL error: (32, 'EPIPE')
                pass
            elif l[1] in ['451', '462', '477']:
                if self._oargs.irc_crt and self._oargs.irc_key:
                    LOG.warn("Maybe the certificate was not received")
                raise SyniToxError(line)
            elif l[1] in ['376']:
                # :End of /MOTD command
                if self._oargs.irc_crt and self._oargs.irc_key:
                    LOG.info(bytes(sMSG+' NickServ IDENTIFY %s %s\r\n'
                            % (nick, pwd,), 'UTF-8'))
                elif email == '' and pwd:
                    LOG.info(bytes(sMSG+' NickServ IDENTIFY %s %s\r\n'
                            % (nick, pwd,), 'UTF-8'))
                    self.irc.send(bytes(sMSG+' NickServ IDENTIFY %s %s\r\n'
                                        % (pwd,nick, ), 'UTF-8'))
                elif email != '' and pwd:
                    LOG.info(bytes(sMSG+' NickServ REGISTER %s %s\r\n'
                                   % (pwd, email,), 'UTF-8'))
                    self.irc.send(bytes(sMSG+' NickServ REGISTER %s %s\r\n'
                            % (pwd, email,), 'UTF-8'))
                else:
                    LOG.error("you must provide a password to register")
                    raise RuntimeError("you must provide a password to register")
                try:                
                    self.irc.send(bytes(sMSG+' NickServ set cloak on\r\n', 'UTF-8'))
                    if self._oargs.irc_chan:
                        self.irc.send(bytes('JOIN %s\r\n' % self._oargs.irc_chan, 'UTF-8'))
                except BrokenPipeError:
                    raise SyniToxError('BrokenPipeError')
                    
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

    def spin(self, n=20, iMax=1000):
        readable = False
        waiti = 0
        while not readable:
            waiti += 1
            readable, _, _ = select.select([self.irc], [], [], n/100.0 )
            if readable and len(readable) and readable[0]: return readable
            self.do(n)
            if waiti > iMax: break
        return readable

    def iLoop(self):
        group_connected = False
        routed = None
        self.joined = False
        self.request = False
        iCount = 0
        iDelay = 10
        
        nick = self._oargs.irc_nick
        realname = self._oargs.irc_name
        ident = self._oargs.irc_ident
        pwd = self._oargs.irc_pass
        email = self._oargs.irc_email
        LOG.info(f"Looping for Tox and IRC connections")
        if iCount < self._oargs.max_sleep:
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
                    LOG.info(f'Not DHT connected {iCount} iterating {iDelay} seconds')
                    iDelay = iDelay + iDelay // 10
                    self.do(iDelay)
                    #drop through

                if not group_connected and dht_conneted:
                    LOG.info('Connected to DHT.')
                    group_connected = True
                    try:
                        #? self.bid = self.friend_by_public_key(self.sGROUP_BOT_PK)
                        r = self.group_reconnect(self.sGROUP_BOT_NUM)
                        LOG.info(f'Connected to group {r}')
                    except ctypes.ArgumentError as e: # noqa
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
                    self.irc_init()
                    if not self.irc:
                        self.do(20)
                        continue

 
                LOG.info(f'Waiting on IRC to {self._oargs.irc_host} on {self._oargs.irc_port}')

                readable = self.spin(20)
                if not readable or not readable[0]:
                    LOG.info('Waited on IRC but nothing to read.')
                    iDelay = iDelay + iDelay // 10
                    continue
                try:
                    pass
                except Exception as e:
                    if len(e.args) > 1 and e.args[0] == 32:
                        raise
                    elif f"{e}" != "2":
                        LOG.warn(f'IRC Error during read: {e}')
                        # close irc?
                        try: 
                            self.irc.close()
                            self.irc = None
                        except: pass
                        continue
                    else:
                        iDelay = 10
                else:
                    iDelay = 10

                self.irc_readlines()
                self.do(iDelay)
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
            nick = self._oargs.group_nick
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
            self.irc_send(sMSG+' %s :[%s]: %s\r\n' %
                          (self._oargs.irc_chan, name, message))
            if message.startswith('^'):
                self.handle_command(message)

    def on_group_action(self, groupnumber, peer_id, action):
        """old? message type action?"""
        name = self.group_peername(groupnumber, peer_id)
        if name and name != NAME:
            print('TOX> %s: %s' % (name, action))
            if action.startswith('>'):
                action = '\x0309%s\x03' % action
            self.irc_send(bytes(sMSG' %s :\x01ACTION [%s]: %s\x01\r\n' %
                                (self._oargs.irc_chan, name, action), 'UTF-8'))

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
        self.irc_send(bytes(sMSG+' %s :%s\r\n' % (self._oargs.irc_chan, content), 'UTF-8'))

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
        return self._toxes.pass_encrypt(data, self._oargs.password)

    def has_password(self):
        return self._oargs.password

    def pass_decrypt(self, data):
        return self._toxes.pass_decrypt(data, self._oargs.password)


def iMain(oArgs, oOpts):
    assert oTOX_OPTIONS
    assert oTOX_OARGS

    try:
        o = SyniTox(oArgs, oOpts)
        __builtins__.app = o
        o.start()
        ret = o.iLoop()
        o.quit()
    except KeyboardInterrupt:
        ret = 0
    except ( SSL.Error, ) as e:
        LOG.error(f"SSL error: {e.args}")
        ret = 1
    except (SSL.SysCallError,) as e:
        # OpenSSL.SSL.SysCallError: (9, 'EBADF')
        LOG.error(f"SSL error: {e.args}")
        ret = 1
    except SyniToxError as e:
        LOG.error(f'Error running program:\n{e}')
        ret = 2
    except Exception as e:
        LOG.exception(f'Error running program:\n{e}')
        ret = 3
    else:
        ret = 0
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

def vInitializeOargs():
    global oTOX_OARGS
    assert oTOX_OARGS.irc_host or oTOX_OARGS.irc_connect
    if not oTOX_OARGS.irc_connect:
        oTOX_OARGS.irc_connect = oTOX_OARGS.irc_host
    if oTOX_OARGS.irc_cadir:
        assert os.path.isdir(oTOX_OARGS.irc_cadir)
    if oTOX_OARGS.irc_cafile:
        assert os.path.isfile(oTOX_OARGS.irc_cafile)
    if oTOX_OARGS.irc_crt:
        assert os.path.isfile(oTOX_OARGS.irc_crt)
        assert oTOX_OARGS.irc_key
    if oTOX_OARGS.irc_key:
        assert os.path.isfile(oTOX_OARGS.irc_key)
        assert oTOX_OARGS.irc_crt
    if not oTOX_OARGS.group_name:
        group_name = oTOX_OARGS.bot_name +oTOX_OARGS.irc_chan
        oTOX_OARGS.group_name = group_name

def oArgparse(lArgv):
    parser = ts.oMainArgparser()
    parser.add_argument('profile', type=str, nargs='?', default=None,
                        help='Path to Tox profile - new groups will be saved there')

    CAcs = []
    for elt in lCAs:
        if os.path.exists(elt):
            CAcs.append(elt)
    CAfs = []
    for elt in lCAfs:
        if os.path.exists(elt):
            CAfs.append(elt)

    parser.add_argument('--log_level', type=int, default=10)
    parser.add_argument('--bot_name', type=str, default=bot_toxname)
    parser.add_argument('--max_sleep', type=int, default=3600,
                        help="max time to sleep waiting for routing before exiting")

    parser.add_argument('--password', type=str, default='',
                        help="password for the profile if encrypted")
#        parser.add_argument('--irc_type', type=str, default='',
#                            choices=['', 'startls', 'direct')
    # does host == connect ?
    # oftcnet6xg6roj6d7id4y4cu6dchysacqj2ldgea73qzdagufflqxrid.onion:6697
    # irc.oftc.net
    parser.add_argument('--irc_host', type=str, default='',
                        help="irc.libera.chat will not work over Tor")
    parser.add_argument('--irc_connect', type=str, default='',
                        help="defaults to irc_host")
    parser.add_argument('--irc_port', type=int, default=6667,
                        help="default 6667, but may be 6697 with SSL")
    parser.add_argument('--irc_chan', type=str, default='#tor',
                        help="IRC channel to join - include the #")
    #
    parser.add_argument('--irc_ssl', type=str, default='',
                        help="TLS version; empty is no SSL",
                        choices=['', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3'])
    parser.add_argument('--irc_cafile', type=str,
                        help="Certificate Authority file (in PEM)",
                        default=CAfs[0])
    parser.add_argument('--irc_cadir', type=str,
                        help="Certificate Authority directory",
                        default=CAcs[0])
    parser.add_argument('--irc_crt', type=str, default='',
                        help="Certificate as pem; use openssl req -x509 -nodes -newkey rsa:2048")
    parser.add_argument('--irc_key', type=str, default='',
                        help="Key as pem; use openssl req -x509 -nodes -newkey rsa:2048")
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
                        help="chat_id of the group - leave empty and will be created on first use")
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
    
    ts.clean_booleans(oTOX_OARGS)
    vInitializeOargs()
        
    global oTOX_OPTIONS
    oTOX_OPTIONS = oToxygenToxOptions(oTOX_OARGS)
    
    ts.vSetupLogging(oTOX_OARGS)
#    ts.setup_logging(oArgs)

    return iMain(oTOX_OARGS, oTOX_OPTIONS)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

# Ran 34 tests in 86.589s OK (skipped=12)
