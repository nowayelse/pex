#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import re
from time import sleep
from ipaddress import ip_address
from io import StringIO
from subprocess import getoutput, getstatusoutput
from pkg_resources import parse_version
try:
    from pexpect import *
    if parse_version(__version__) < parse_version('4.7.0'):
        exit('pexpect version is lower than 4.7.0, please upgrade')
except ImportError:
    exit('pexpect not found, install pexpect 4.7.0 or newer')

def checksid(func):
    def wrapper(*args, sid='', **kwargs):
        global lsid
        if sid == '':
            sid = lsid
        return func(*args, sid=sid, **kwargs)
    return wrapper

def setlsid(func):
    def wrapper(*args, sid='', **kwargs):
        global lsid
        if sid != '':
            lsid = sid
        func(*args, sid=sid, **kwargs)
    return wrapper

class _spawn(spawn):
    
    def __init__(self, cmd, pcmd='', sid='', hostname='EOS',
                       login='admin', password='password'):
        self.pcmd = pcmd
        self.sid = sid
        self.login = login
        self.hostname = hostname
        self.password = password
        spawn.__init__(self, cmd, maxread=500000, encoding='utf-8')
        self.logfile_read = sys.stdout
        self.prompt = self.hostname
        self.exitcmds = ['exit', 'logout', 'quit']

class buffer:
    
    @checksid
    def __init__(self, sid=''):
        self.out = sids[sid].before.split('\r\n')
    def __str__(self):
        return '\n'.join(self.out[1:-1])
    def __repr__(self):
        return '\n'.join(self.out[1:-1])
    def __add__(self, other):
        return str(self) + other
    def __radd__(self, other):
        return other + str(self)
    def __bool__(self):
        return bool(str(self))
    
    @staticmethod
    @checksid
    def cmd(sid=''):
        l,s,r = buffer(sid=sid).out[0].rpartition('\x1b[J')
        l,s,r = r.partition('\x1b[')
        return l
    
    @staticmethod
    @checksid
    def prompt(sid=''):
        return buffer(sid=sid).out[-1]+sids[sid].after
    
    @staticmethod
    @checksid
    def list(sid=''):
         return buffer(sid=sid).out[1:-1]
    
    @staticmethod
    @checksid
    def all(sid=''):
        return '\n'.join(buffer(sid=sid).out)

def parsecmd(cmd):
    pcmd = '^(?:(ssh|telnet):)?([\w.-]+)(?::(\d+))?$'
    try:
        tproc, taddr, tport = re.findall(pcmd, cmd)[0]
    except IndexError:
        exit('Command line parse error: %s' % cmd)
    proc = tproc or 'telnet'
    addr = taddr
    try:
        ip_address(addr)
    except ValueError:
        exit('Command line address error: {}'.format(addr))
    port = tport or ('23' if proc == 'telnet' else '22')
    if proc == 'telnet':
        return addr, '{} {} {}'.format(proc, addr, port)
    else:
        return addr, '{} {}@{} -p{}'.format(proc, login, addr, port)

def connect (cmd, sid=-1, tries=3,
             con_roe=False, # return False on error and do not exit
             con_wfn=False, # waits for netconf anyway
             **kwargs):
    '''ex.: connect('192.168.17.26', hostname='EOS#')'''
    global sids, lsid
    
    def errconnect(code=''):
        nonlocal append, error
        if code == 'STOP':
            exit('Route or DNS issue')
        elif code == 'PING':
            append += 1
        elif code == 'NETCONF':
            if con_wfn:
                return
            else:
                append += 1
                if tries-append > 0:
                    reconnect(tries=tries-append)
        elif code in ['EOF', 'TIMEOUT', 'ERROR']:
            append += 1
        else:
            exit('Unknown error during connect, needs to debug.')
        error = code
    
    '''validate'''
    if type(cmd) != str:
        exit('Command must be a string')
    if type(tries) != int:
        exit('"tries" must be an integer')
    elif tries < 1:
        exit('"tries" must be greater than zero')
    if type(sid) != int:
        exit('"sid" must be an integer')
    
    '''init vars'''
    addr, scmd = parsecmd(cmd)
    error = ''
    append = 0
    nologin = False
    nopassword = False
    
    while append < tries:
        if not pinger(addr):
            errconnect('PING')
        else:
            try:
                if sid < 0:
                    sid = len(sids)
                    sids.append(_spawn(scmd, pcmd=cmd, sid=sid, **kwargs))
                elif sid >= len(sids): 
                    exsid = sid
                    sid = len(sids)
                    sids.append(_spawn(scmd, pcmd=cmd, sid=sid, **kwargs))
                    if sid > len(sids):
                        print('Sid is not {}, but {}'.format(exsid, sid))
                else:
                    sids[sid] = _spawn(scmd, pcmd=cmd, sid=sid, **kwargs)
            except Exception as e:
                exit('Spawn error: {}'.format(e))
            lsid = sid
            sids[sid].setwinsize(1000, 1000)
            setprompt()
            break
    while append < tries:
        try:
            r = sids[sid].expect(['(nknown host)|(not known)',
                            'o route to host',
                            'onnection refused',
                            'closed by foreign host',
                            'sure you want to continue connecting',
                            '(ogin: ?$)|(ame: ?$)',
                            'sword: ?$',
                            'etconf server doesn',
                            sids[sid].prompt], timeout=10)
        except EOF:
            errconnect('EOF')
        except TIMEOUT:
            errconnect('TIMEOUT')
        if r in [0,1]:
            errconnect('STOP')
        if r in [2,3]:
            errconnect('ERROR')
        elif r == 4:
            sids[sid].sendline('yes')
        elif r == 5:
            if nologin:
                exit('Login {}/{} incorrect'.format(sids[sid].login, sids[sid].password))
            else:
                nologin = True
            sids[sid].sendline(sids[sid].login)
        elif r == 6:
            if nopassword:
                exit('Login {}/{} incorrect'.format(sids[sid].login, sids[sid].password))
            else:
                nopassword = True
            sids[sid].sendline(sids[sid].password)
        elif r == 7:
            errconnect('NETCONF')
        elif r == 8:
            error=''
            break
    if error:
        if con_roe:
            return False
        else:
            exit('Exited due to '+error)
    else:
        return True

@checksid
@setlsid
def reconnect (cmd='', sid='', login='', password='', **kwargs):
    global sids
    cmd = cmd if cmd else sids[sid].pcmd
    try:
        cmd = cmd if cmd else sids[sid].pcmd
        login = login if login else sids[sid].login
        password = password if password else sids[sid].password
    except Exception:
        exit('lsid args unpack failed')
    return connect(cmd, sid=sid, login=login, password=password, **kwargs)

@checksid
def setprompt(sid='', hn=''):
    if hn == '':
        hn = sids[sid].hostname
    name,sn = (re.findall('(\S+)(\)|\#|\>|\$|\~)', hn) or [(hn, '')])[0]
    if sn:
        sids[sid].prompt = name+r'((?!\n).)*'+sn
    else:
        sids[sid].prompt = name+r'((?!\n).)*(\)|\#|\>|\$|\~)'

@checksid
@setlsid
def se (*args, sid='', flags='30', timeout=30):
    if sid >= len(sids):
        exit('Sending to unopened sid: '+str(sid))
    if len(args) == 0:
        args += ('', None,)
    elif len(args) % 2 == 1:
        args += (None,)
    pairs = zip(*[iter(args)]*2)
    for cmds,exps in pairs:
        if type(cmds) != list:
            cmds = str(cmds).strip().split('\n')
        cmds = [str(i).strip() for i in cmds]
        for cmd in cmds:
            dontwait = False
            msend = sids[sid].sendline
            if len(cmd) <= 1:
                msend = sids[sid].sendline
            if len(cmd) >= 2 and cmd[-1] == '$':
                cmd = cmd[:-1]
                msend = sids[sid].send
                dontwait = True
            if len(cmd) == 2 and cmd[0] == '^':
                cmd = cmd[1:]
                msend = sids[sid].sendcontrol
            try:
                msend(cmd)
            except:
                exit('Send error')
            if dontwait: continue
            try:
                if exps == None:
                    sids[sid].expect(sids[sid].prompt, timeout=int(timeout))
                else:
                    i = sids[sid].expect(exps, timeout=int(timeout))
                if type(exps) == list and len(exps) > 1:
                    if len(cmds) > 1 or len(list(pairs)) > 1:
                        print('Expect is list! Next S-E will not be performed')
                    return i
            except EOF:
                if cmd in sids[sid].exitcmds:
                    error = 'exit'
                else:
                    error = 'eof'
            except TIMEOUT:
                error = 'timeout'
                exit('TIMEOUT = {}'.format(timeout))
            else:
                sids[sid].last = buffer.prompt()
            finally:
                sids[sid].logfile_send = StringIO('')

def switchecho(val=''):
    global lsid, sids
    states = [sys.stdout, None]
    states.remove(sids[lsid].logfile_read)
    if val == True:
        sids[sid].logfile_read = sys.stdout
    elif val == True:
        sids[sid].logfile_read = None
    else:
        sids[sid].logfile_read = states[0]

def unsend():
    global lsid, sids
    i = repr(sids[lsid].logfile_send.getvalue()).strip('\'')
    while True:
        o = re.sub(r'\S+? ?\\x17', '', i)
        if o == i:
            return o
        i = o

def sleepx(sec=60, msg=''):
    print('Sleep {} seconds. {}'.format(sec, msg))
    for i in range(sec):
        print('{} seconds left\r'.format(sec-i), end='', flush=True)
        sleep(1)

def pinger(host, timeout=1):
    s,_ = getstatusoutput('ping -c1 -w{} {}'.format(timeout, host))
    return True if s == 0 else False

def incrip(addr, i=1):
    return str(ip_address(addr)+i)

''' ME5k specific'''

def me5k_shellprompt(sid=''):
    global lsid, sids
    if sid == '':
        sid = lsid
    else:
        lsid = sid
    hn = sids[sid].hostname
    name,sn = (re.findall('(\S+)(\)|\#|\>|\$|\~)', hn) or [(hn, '')])[0]
    sids[sid].prompt = r'\[root@'+name+r' \S+\]'

class me5k_rootshell(): 
    def __enter__(self): 
        me5k_shellprompt()
        se('rootshell', 'assword:', 'password') 
    def __exit__(self, *args): 
        setprompt()
        se('exit')

@checksid
@setlsid
def me5k_shellprompt(sid=''):
    hn = sids[sid].hostname
    name,sn = (re.findall('(\S+)(\)|\#|\>|\$|\~)', hn) or [(hn, '')])[0]
    sids[sid].prompt = r'\[root@'+name+r' \S+\]'

def me5k_searchlogs(text):
    with me5k_rootshell():
        se('grep -E "{}" /var/log/syslog/buffer* 2>/dev/null | head -5'
            .format(text))
        return True if buffer() else False

def me5k_getlogs():
    se('! show tech-support')
    se('! copy fs://logs tftp://{}/logs/tech-support/ vrf mgmt-intf'.format(host))


host = '192.168.16.254'
lsid = 0
sids = []
