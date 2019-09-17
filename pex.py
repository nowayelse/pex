#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import re
from time import sleep, time as now
from ipaddress import ip_address, ip_network
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
    
    def __init__(self, cmd, **kwargs):
        self.__dict__.update(kwargs)
        self.exitcmds = ['exit', 'logout', 'quit']
        spawn.__init__(self, cmd, maxread=500000, encoding='utf-8')
        self.setwinsize(1000, 1000)
        self.delaybeforesend = 0
        self.ignorecase
        self.logfile_read = sys.stdout
        #self.prompt = self.hostname
    
    def se(self, *args, **kwargs):
        se(*args, sid=self.sid, **kwargs)

class buffer:
    
    @checksid
    def __init__(self, sid=''):
        self.out = sids[sid].before.split('\r\n')
    def __str__(self):
        return '\n'.join(self.out[1:-1])
    def __repr__(self):
        return bool(str(self))
    def __add__(self, other):
        return str(self) + other
    def __radd__(self, other):
        return other + str(self)
    def __bool__(self):
        return bool(str(self))
    
    @staticmethod
    @checksid
    def all(sid=''):
        return '\n'.join(buffer(sid=sid).out[1:-1])
    
    @staticmethod
    @checksid
    def cmd(sid=''):
        l,s,r = buffer(sid=sid).out[0].rpartition('\x1b[J')
        l,s,r = r.partition('\x1b[')
        return l
    
    @staticmethod
    @checksid
    def last(sid=''):
         return buffer(sid=sid).out[-1]
    
    @staticmethod
    @checksid
    def list(sid=''):
         return buffer(sid=sid).out[1:-1]
    
    @staticmethod
    @checksid
    def prompt(sid=''):
        return buffer(sid=sid).out[-1]+sids[sid].after


def connect (cmd, sid=-1, tries=3,
             con_roe=False, # return False on error and do not exit
             con_wfn=False, # waits for netconf anyway
             hostname='EOS', login='admin', password='password',
             **kwargs):
    '''ex.: connect('192.168.17.26', hostname='EOS#')'''
    global sids, lsid
    
    def sp():
        return _spawn(scmd, pcmd=cmd, sid=sid,
                       login=login, password=password, hostname=hostname)
    
    def parsecmd(cmd):
        pat = '^(?:(ssh|telnet):)?([\w.-]+)(?::(\d+))?$'
        try:
            tproc, taddr, tport = re.findall(pat, cmd)[0]
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
                    sids.append(sp())
                elif sid >= len(sids):
                    exsid = sid
                    sid = len(sids)
                    sids.append(sp())
                    if sid > len(sids):
                        print('Sid is not {}, but {}'.format(exsid, sid))
                else:
                    sids[sid] = sp()
            except Exception as e:
                exit('Spawn error: {}'.format(e))
            lsid = sid
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
                            sids[sid].prompt], timeout=15)
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
                exit('Login {}/{} incorrect'.
                    format(sids[sid].login, sids[sid].password))
            else:
                nologin = True
            sids[sid].sendline(sids[sid].login)
        elif r == 6:
            if nopassword:
                exit('Login {}/{} incorrect'.
                    format(sids[sid].login, sids[sid].password))
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
        return sids[sid]

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
    sids[sid].hname=name

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
    for id,(cmds,exps) in enumerate(pairs):
        if type(cmds) != list:
            cmds = str(cmds).strip().split('\n')
        cmds = [str(i).strip() for i in cmds]
        for cmd in cmds:
            se_noexpect = False  # .$
            se_nocarret = False  # -c .
            se_control = False   # ^.
            se_sendslow = False  # -s .
            se_interval = 0.01
            
            pfx,_,pcmd = cmd.partition(' ')
            if pfx[0] == '-':
                cmd = pcmd
                if 'c' in pfx:
                    se_nocarret = True
                if 's' in pfx:
                    se_sendslow = True
            if cmd[0] == '^':
                se_control = True
                se_nocarret = True
                cmd = cmd[1:]
            if cmd[-1] == '$':
                se_noexpect = True
                cmd = cmd[:-1]
            
            try:
                if se_control:
                    sids[sid].sendcontrol(cmd)
                elif se_sendslow:
                    for char in cmd:
                        sids[sid].send(char)
                        sleep(se_interval)
                else:
                    sids[sid].send(cmd)
                if not se_nocarret:
                    sids[sid].send('\r')
            except Exception as e:
                exit('Send error: '+e)
            
            if se_noexpect: continue
            try:
                if exps == None:
                    sids[sid].expect(sids[sid].prompt, timeout=int(timeout))
                else:
                    i = sids[sid].expect(exps, timeout=int(timeout))
                if type(exps) == list and len(exps) > 1:
                    if id < len(pairs)-1:
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
        sids[lsid].logfile_read = sys.stdout
    elif val == False:
        sids[lsid].logfile_read = None
    else:
        sids[lsid].logfile_read = states[0]

def unsend():
    global lsid, sids
    i = repr(sids[lsid].logfile_send.getvalue()).strip('\'')
    while True:
        o = re.sub(r'\S+? ?\\x17', '', i)
        if o == i:
            return o
        i = o

@checksid
def prompt(sid=''):
    return sids[sid].prompt

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


''' ME5k specific '''

def me5k_confview(f):
    def wrap(*args, **kwargs):
        if re.search(sids[lsid].hname+r'\(config', buffer.prompt()):
            se('-ns do ')
        f(*args, **kwargs)
    return wrap

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
    me5k_confview(se)('show tech-support')
    me5k_confview(se)('copy fs://logs tftp://{}/logs/tech-support/ vrf mgmt-intf'.format(host))

def me5k_switchover():
    se('redundancy switchover', 'with the switchover', 'y')
    var = r'(ot all services)|(is not allowed on slave)|(lave fmc is not found)'
    ans = re.search(var, buffer.all())
    if ans:
        return ans.lastindex
    else:
        return 0

def me5k_showtree(cmd):
    
    def gethelp(cmds):
        return re.findall(r'  (\S(?:.*\S)?)  ', cmds)
    
    def parsehelp(cmds):
        subs = {
            'IF    <unit>/<dev>/<port>': ['0/0/1'],
            'SUBIF <unit>/<dev>/<port>.<sub-id>': ['0/0/1.10'],
            'IF <unit>/<dev>/<port> or SUBIF <unit>/<dev>/<port>.<vid>': ['0/0/1', '0/0/1.10'],
            'IF <unit>/<dev>/<port> || SUBIF <unit>/<dev>/<port>.<sub-id>': ['0/0/1', '0/0/1.10'],
            'IF    <bundle-id>': ['1'],
            'SUBIF <bundle-id>.<sub-id>': ['1.10'],
            'IF <bundle-id> or SUBIF <bundle-id>.<bundle-subid>': ['1', '1.10'],
            'Loopback ID (1-8000)': ['1'],
            'MGMT    <unit>/fmc<dev>/<port>': ['0/fmc0/1'],
            'IPv4 (A.B.C.D)': ['10.0.0.30'],
            'IPv4 (A.B.C.D/N)': ['10.0.0.30/32'],
            'IPv4 Multicast (A.B.C.D)': ['225.54.205.135'],
            'IPv6 (X:X:X:X::X)': ['2001::1'],
            'IPv6 (X:X:X:X::X/N)': ['2001::1/64'],
            'IPv4 (A.B.C.D) or IPv6 (X:X:X:X::X)': ['10.0.0.30'],
            'VRF name WORD (1-31)': ['test'],
            'all | VRF name WORD (1-31)': ['all', 'test'],
            'RD AS:Nr(0-4294967295:0-65535)': ['4294967295:65535'],
            'RD AS:Nr(0-65535:0-4294967295)': ['65535:4294967295'],
            'RD IPv4:Nr(0-65535)': ['10.0.0.134:0'],
            'RT': ['65535:4294967295', '4294967295:65535', '10.0.0.134:0'],
            'A.B.C.D:N': ['10.0.0.111:0'],
            'INTEGER': ['1'],
            'String': ['admin'],
            'WORD': ['test'],
            'TUNNEL ID': ['1'],
            'Router ID': ['10.0.0.111'],
            'Area id (A.B.C.D)': ['0.0.0.0'],
            'MAC (XX:XX:XX:XX:XX:XX)': ['00:11:22:33:44:55'],
            '(1-': ['1'],
            '(0-': ['1'],
            '<unit>/<dev> | all': ['all', '0/0'],
            '<unit>/<dev>': ['0/0'],
            'SLOT <unit>/<dev>': ['0/0'],
            'SLOT <unit>/fmc<dev>': ['0/fmc0'],
            'Link state id': ['10.0.0.111'],
            'Period': [],
            'Location': []
        }
        out = [] 
        if '<cr>' in cmds:
            out.append('<cr>')
        cmds = [cmd for cmd in cmds if cmd not in last]
        for cmd in cmds:
            for key in subs:
                if cmd.startswith(key):
                    out += subs[key]
                    break
            else:
                out.append(cmd.split()[0])
        return out
    
    def shownext(helps):
        nonlocal cmds
        if helps == []:
            cmds.append('! '+buffer.cmd().strip())
        for cmd in parsehelp(helps):
            if cmd in ['fortygigabitethernet', 'gigabitethernet', 'hundredgigabitethernet']:
                continue
            if cmd == '<cr>':
                cmds.append(buffer.cmd().strip())
            else:
                se('-c {} ?'.format(cmd))
                shownext(gethelp(buffer.all()))
        se('^w$')
    
    cmds = []
    last = ['|', '<cr>']
    if type(cmd) == str:
        cmd = [cmd]
    for i in cmd:
        se('-c show {} ?'.format(i))
        shownext(gethelp(buffer.all()))
        se('^c')
    return cmds



host = '192.168.16.22'
lsid = 0
sids = []
