#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

import sys
import os
import re
from time import sleep, time as now
from ipaddress import ip_address, ip_network, ip_interface, IPv4Network
from io import StringIO
from subprocess import getoutput, getstatusoutput
from pkg_resources import parse_version
from functools import partial, wraps
from contextlib import contextmanager
from collections import namedtuple

''' Check module versions'''
if sys.version_info[0:2] < (3,8):
    exit('python version is lower than 3.8.0, please upgrade')
try:
    from pexpect import *
    if parse_version(__version__) < parse_version('4.7.0'):
        exit('pexpect version is lower than 4.7.0, please upgrade')
    else:
        from pexpect.fdpexpect import *
except ImportError:
    exit('pexpect not found, install pexpect 4.7.0 or newer')

try:
    import pyte
    pyte_ok = True
except ImportError:
    print('pyte not found, "pip install pyte"')
    pyte_ok = False
    from pexpect import ANSI


def setmethod(cls):
    def wrapper(func):
        setattr(cls, re.sub('^_', '', func.__name__), func)
    return wrapper

@setmethod(IPv4Network)
def _intf(self, i=0):
    '''Takes network as list and item i as host and returns interface'''
    return ip_interface(str(self[int(i)])+'/'+str(self.prefixlen))

@setmethod(IPv4Network)
def ___add__(self, i=1):
    '''Shift network i times'''
    return ip_network(str(ip_address(self.network_address) + \
        int(i)*self.num_addresses)+'/'+str(self.prefixlen))

def chunk(t, i=2):
    '''Takes list and returns list of list with i elements'''
    return list(map(list, zip(*(iter(t),)*i)))

def checksid(func):
    @wraps(func)
    def wrapper(*args, sid='', **kwargs):
        global lsid
        if sid == '':
            sid = lsid
        return func(*args, sid=sid, **kwargs)
    return wrapper

def setlsid(func):
    @wraps(func)
    def wrapper(*args, sid='', **kwargs):
        global lsid
        if sid != '':
            lsid = sid
        return func(*args, sid=sid, **kwargs)
    return wrapper

class _spawn(fdspawn, spawn):
    
    def __init__(self, scmd, **kwargs):
        self.__dict__.update(kwargs)
        self.exitcmds = ['exit', 'logout', 'quit']
        spm = fdspawn
        if self.proc == 'serial': scmd = os.open(self.addr, os.O_RDWR)
        else: spm = spawn
        spm.__init__(self, scmd, maxread=500000, encoding='utf-8')
        self.irows, self.icols = os.get_terminal_size()
        if self.proc == 'serial': self.ptyproc = ''
        else: self.setwinsize(self.icols, self.irows)
        self.delaybeforesend = 0.01
        self.delayafterread = 0.01
    
    def se(self, *args, **kwargs):
        se(*args, sid=self.sid, **kwargs)


class Prompt:
    @staticmethod
    @checksid
    def basic(hostname, sid=''):
        hn, sn = gethostname(hostname)
        if sn: return hn+r'(?:(?!\n).)*'+sn
        return hn+r'(?:(?!\n).)*(\)|\#|\>|\$|\~)'


class buffer:
    
    @checksid
    def __init__(self, sid=''):
        
        # self.out = sids[sid].before.replace('\r\r\n', '').split('\r\n')
        # return
        
        if pyte_ok:
            screen = pyte.Screen(os.get_terminal_size()[0], max_lines)
            stream = pyte.Stream(screen)
            screen.mode.add(pyte.modes.LNM)
            ss = sids[sid].before.replace('\r\r\n', '').replace('\r\n', 'CRNL')
            stream.feed(ss)
            self.out = [i.rstrip() for i in ''.join(screen.display).split('CRNL')]
            del screen, stream
        else:
            l,s,r = sids[sid].before.replace('\r\r\n', '').rpartition('\x1b')
            if l == '':
                l,s,r = sids[sid].before.replace('\r\r\n', '').partition('\r\n')
            else:
                l1,s,r = r.partition('\r\n')
            term = ANSI.ANSI(*os.get_terminal_size()[::-1])
            term.process_list(l)
            self.out = [(''.join(str(term).split('\n'))).strip()]+r.split('\r\n')
     
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
        return buffer(sid=sid).out[0].lstrip()
    
    @staticmethod
    @checksid
    def last(sid=''):
        return '\n'.join(buffer(sid=sid).out[1:-1][-1:])
    
    @staticmethod
    @checksid
    def list(sid=''):
         return buffer(sid=sid).out[1:-1]
    
    @staticmethod
    @checksid
    def prompt(sid=''):
        return buffer(sid=sid).out[-1]+sids[sid].after

def connect(cmd='', /,
            proc='', addr='', port='', login='', password='',
            prompt = '', hostname='', promptype='',
            d_proc='', d_addr='', d_port='', d_login='', d_password='',
            d_prompt = '', d_hostname='', d_promptype='',
            sid=-1, tries=3, con_timeout=50,
            con_roe=False, # Return on error if True, else exits
            con_wfn=False, # Ignore netconf issues if True, else reconnect
            con_ser=False, # Destination is serial port
            con_sil=False # Silent connection
            ):
            #**kwargs):
    '''ex.: connect('192.168.17.26', hostname='EOS#')'''
    global sids, lsid
    
    def scmd():
        if   proc == 'serial': return addr
        elif proc == 'telnet': return f'{proc} {addr} {port}'
        elif proc == 'ssh':    return f'{proc} {login}@{addr} -p{port}'
        else:                  exit(f'{proc = }, is not a valid process')
    
    def parsecmd(cmd):
        '''Extract process, address and port from cmd string'''
        pat = r'^(?:\b(ssh|telnet|serial)\b(?::\/\/| )?)?' \
              '(?:(?:(\w+)(?::(\w+))?@)?([\w\/\.\-]+))?(?::(\d+))?$'
        try:
            return re.findall(pat, cmd)[0]
        except IndexError:     exit(f'{cmd = }, has invalid format')
        
    '''Validate and init params'''
    if   type(cmd) != str:     exit(f'{cmd = }, command must be a string')
    if   type(tries) != int:   exit(f'{tries = }, must be an integer')
    elif tries < 1:            exit(f'{tries = }, must be greater than zero')
    if   type(sid) != int:     exit(f'{sid = }, must be an integer')
    p_proc, p_login, p_password, p_addr, p_port = parsecmd(cmd)
    proc = proc or p_proc or d_proc or 'telnet'
    addr = addr or p_addr or d_addr or \
        ('/dev/ttyUSB0' if proc == 'serial' else '127.0.0.1')
    if proc == 'serial':
        if not os.path.exists(addr): exit(f'{addr = }, must be a valid file')
        con_ser = True
    else:
        try:
            ip_address(addr)
        except ValueError: exit(f'{addr = }, must be a valid ipv4 address')
    port = port or p_port or d_port or ('23' if proc == 'telnet' else '22')
    login = login or p_login or d_login or 'admin'
    password = password or p_password or d_password or 'password'
    hostname = hostname or d_hostname or 'EOS'
    
    hname, _ = gethostname(hostname)
    prompt = prompt or getprompt(hostname, type=promptype)
    
    '''Try to connect'''
    for append in range(tries):
        error = ''
        nologin = nopassword = logged = False
        if proc != 'serial' and not pinger(addr):
            error = 'PING ('+addr+')'
            continue
        try:
            p = _spawn(scmd(), cmd=cmd, proc=proc, addr=addr, port=port,
                    login=login, password=password, hostname=hostname,
                    hname=hname, prompt=prompt, sid=sid)
        except Exception as e:
            exit(f'Spawn error: {e}')
        p.logfile_read = None if con_sil else sys.stdout
        if con_ser:
            sleep(0.2)
            p.sendline('')
        exps = ['(nknown host)|(not known)',
                'o route to host',
                'onnection refused',
                'closed by foreign host',
                'sure you want to continue connecting',
                '(ogin: ?$)|(ame: ?$)',
                'sword: ?$',
                p.prompt]
        if not con_wfn:
            exps.append('etconf server doesn')
        r = error = ''
        while not error and not logged:
            try:
                r = p.expect(exps, timeout=con_timeout)
            except EOF:
                error = 'EOF'
            except TIMEOUT:
                error = 'TIMEOUT'
            if r in [0,1]:
                exit('Route or DNS issue')
            if r in [2,3]:
                error = 'REFUSED'
                sleepx(5)
            elif r == 4:
                p.send('yes\r')
            elif r == 5:
                if nologin:
                    error = 'AUTH'
                else:
                    nologin = True
                    p.send(p.login)
                    p.send('\r')
            elif r == 6:
                if nopassword:
                    error = 'AUTH'
                else:
                    nologin = True
                    nopassword = True
                    p.send(p.password)
                    p.send('\r')
            elif r == 7:
                logged = True # got prompt 
            elif r == 8:
                error = 'NETCONF'
        else:
            if logged:
                break
            else:
                continue
    if error:
        '''Error while connecting'''
        if error == 'AUTH':
            try:
                se('-te c')
            except: pass
            p.close()
        return False if con_roe else exit('Exited due to '+error)
    else:
        '''Connection done'''
        if sid < 0:
            sid = len(sids)
            sids.append(p)
        elif sid >= len(sids):
            exsid = sid
            sid = len(sids)
            sids.append(p)
            if sid > len(sids): print(f'Sid is {sid} instead of {exsid}')
        else:
            sids[sid] = p
        lsid = sid
        return sids[sid]

@checksid
@setlsid
def reconnect(cmd='', sid='', login='', password='', **kwargs):
    global sids
    cmd = cmd or sids[sid].pcmd
    try:
        cmd = cmd if cmd else sids[sid].pcmd
        login = login if login else sids[sid].login
        password = password if password else sids[sid].password
    except Exception:
        exit('lsid args unpack failed')
    return connect(cmd, sid=sid, login=login, password=password, **kwargs)


@checksid
def setprompt(hostname='', type='', sid=''):
    hostname = hostname or sids[sid].hname
    sids[sid].prompt = getprompt(hostname=hostname, type=type, sid=sid)

@checksid
def getprompt(hostname='', type='', sid=''):
    if not hostname: return sids[sid].prompt
    if type:
        if hasattr(Prompt, type): return getattr(Prompt, type)(hostname)
        else:                  exit(f'Can not set prompt by "{type}" method')
    else: return Prompt.basic(hostname)

def gethostname(hostname):
    hpat = re.compile(r'^([A-Za-z][A-Za-z0-9-._]{0,62})(\)|\#|\>|\$|\~)?$')
    return re.findall(hpat, hostname)[0]

@checksid
@setlsid
def se(*args, sid='', f=''):
    if sid >= len(sids):
        exit('Sending to unopened sid: '+str(sid))
    if len(args) == 0:
        args += ('', None,)
    elif len(args) % 2 == 1:
        args += (None,)
    pairs = zip(*[iter(args)]*2)
    for id, (cmds,exps) in enumerate(pairs):
        if type(cmds) != list: cmds = str(cmds).split('\n')
        cmds = [str(i).lstrip() for i in cmds if str(i).lstrip()[:1] != '#']
        ans = 0
        err = ''
        for cmd in cmds:
            f, cmd = (m[1], m[2]) if (m := re.match(r'\-(\S*) ?(.*)', cmd)) \
                else ('', cmd)
            se_interval = 0.01
            se_timeout  = (re.search(r'\d+', f) or [600])[0]
            se_control  = 't' in f                  # send control sequence
            se_nocarret = 'c' in f or se_control    # don't '\r'
            se_noexpect = 'e' in f                  # den't expect
            se_sendslow = 's' in f                  # send slow
            se_noexit   = 'x' in f                  # don't exit if timeout
            se_resetexp = 'r' in f                  # reset expect
            
            ''' Sending '''
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
                exit(f'Send error: {e}')
            
            ''' Expecting '''
            ans = -1
            err = ''
            if se_noexpect:
                ans = 0
                continue
            try:
                if exps == None:
                    ans = sids[sid].expect(sids[sid].prompt,
                                           timeout=int(se_timeout))
                else:
                    ans = sids[sid].expect(exps, timeout=int(se_timeout))
                if se_resetexp:
                    expclear(sids[sid].prompt)
            except EOF:
                ans = -1
                err = 'EOF'
            except TIMEOUT:
                ans = -2
                err = 'TIMEOUT '+str(se_timeout)
            finally:
                sids[sid].logfile_send = StringIO('')
                if type(exps) == list and len(exps) > 1:
                    if id < len(list(pairs))-1:
                        if len(cmds) > 1 or len(list(pairs)) > 1:
                            print('Expect list! Next SE will not be performed')
                    if ans >= 0:
                        return ans
                    else:
                        break
    if ans >= 0:
        return True
    elif ans == -1:
        if cmd in sids[sid].exitcmds or se_noexit:
            return False
        else:
            exit(f'Expect: {err}')
    elif ans == -2:
        if se_noexit:
            return False
        else:
            exit(f'Expect: {err}')

@checksid
def expclear(ex=r'.*', sid=''):
    sids[sid].expect(ex, timeout=5)

def switchecho(val=''):
    global lsid, sids
    if lsid >= len(sids):
        exit('Sending to unopened sid: '+str(lsid))
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
    print(f'Sleep {sec} seconds. {msg}')
    for i in range(sec):
        print(f'{sec-i} seconds left')
        sleep(1)
        print('\x1b[A\x1b[K', end='', flush=True)

def pinger(host, timeout=1):
    s,_ = getstatusoutput(f'ping -c1 -w{timeout} {host}')
    return True if s == 0 else False

def incrip(addr, i=1):
    return str(ip_address(addr)+int(i))

def incrmac(mac, i=1):
    return re.sub(r'(..)(?!$)', r'\1:',
                   f'{(int(mac.replace(":", ""), 16) + i):012X}')

def inbuffer(txt):
    try:
        txt = re.compile(r'(?i)'+txt)
    except:
        txt = re.compile(r'(?i)'+re.escape(txt))
    return len(re.findall(txt, buffer.all()))

def printf(file, *text, **kwargs):
    file.write(' '.join(repr(i) for i in text))
    print(*text, **kwargs)

printn = partial(print, end='', flush=True)

dev = 'd_proc d_addr d_port d_login d_password d_prompt d_hostname d_promptype'
Device = namedtuple('Device', dev, defaults=('',)*8)

def dts(d):
    '''Takes string, searches date and returns seconds. Otherwise None'''
    p = {r'(\d+) years, (\d+) weeks, (\d+) days, (\d+) hours, (\d+) minutes':
            [220752000, 604800, 86400, 3600, 60],
         r'(\d+) weeks, (\d+) days, (\d+) hours, (\d+) minutes':
            [604800, 86400, 3600, 60],
         r'(\d+) days, (\d+) hours, (\d+) minutes': [86400, 3600, 60],
         r'(\d+) hours, (\d+) minutes, (\d+) seconds': [3600, 60, 1],
         r'(\d{2})y(\d{2})w(\d{2})d': [220752000, 604800, 86400],
         r'(\d{2})w(\d{2})d(\d{2})h': [604800, 86400, 3600],
         r'(\d{2})d(\d{2})h(\d{2})m': [86400, 3600, 60],
         r'(\d{2})h(\d{2})m(\d{2})s': [3600, 60, 1],
         r'(\d{2}):(\d{2}):(\d{2})': [3600, 60, 1]
        }
    for k,v in p.items():
        try:
            return sum([a*int(b) for a,b in zip(v,re.match(k,d).groups())])
        except AttributeError: pass
    else:
        return None


class t:
    def u(n=1):                 # up
        return f'\x1b[{n}A'
    def d(n=1):                 # down
        return f'\x1b[{n}B'
    def f(n=1):                 # forward
        return f'\x1b[{n}C'
    def b(n=1):                 # backward
        return f'\x1b[{n}D'
    def n(n=1):                 # next
        return f'\x1b[{n}E'
    def p(n=1):                 # prev
        return f'\x1b[{n}F'
    def m(n=1, m=1):            # move
        return f'\x1b[{n};{m}H'
    e = '\x1b[1J'               # erase
    s = '\x1b[s'                # save
    r = '\x1b[r'                # restore

os.environ["TERM"] = "dumb"
lsid = 0
max_lines = 300                 # maximum lines for pyte terminal
sids = []
