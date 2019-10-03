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
        return func(*args, sid=sid, **kwargs)
    return wrapper

class _spawn(spawn):
    
    def __init__(self, cmd, **kwargs):
        self.__dict__.update(kwargs)
        self.exitcmds = ['exit', 'logout', 'quit']
        spawn.__init__(self, cmd, maxread=500000, encoding='utf-8')
        self.setwinsize(1000, 1000)
        self.delaybeforesend = 0.0
        self.delayafterread = 0.0
        self.ignorecase
        self.logfile_read = sys.stdout
    
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


def connect(cmd, sid=-1, tries=3,
            con_roe=False,  # Retrurn on error if True else exits
            con_wfn=False,  # Ignore netconf issues if True, else reconnect
            hostname='EOS', login='admin', password='password', **kwargs):
    '''ex.: connect('192.168.17.26', hostname='EOS#')'''
    global sids, lsid
    
    def sp():
        return _spawn(scmd, pcmd=cmd, sid=sid, addr=addr,
                       login=login, password=password, hostname=hostname)
    
    def parsecmd(cmd):
        pat = '^(?:(ssh|telnet):)?([\w.-]+)(?::(\d+))?$'
        try:
            tproc, taddr, tport = re.findall(pat, cmd)[0]
        except IndexError:
            exit(f'Command line parse error: {cmd}')
        proc = tproc or 'telnet'
        addr = taddr
        try:
            ip_address(addr)
        except ValueError:
            exit(f'Command line address error: {addr}')
        port = tport or ('23' if proc == 'telnet' else '22')
        if proc == 'telnet':
            return addr, f'{proc} {addr} {port}'
        else:
            return addr, f'{proc} {login}@{addr} -p{port}'
    
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
    
    for append in range(tries):
        error = ''
        nologin = False
        nopassword = False
        logged = False
        if not pinger(addr):
            error = 'PING'
            continue
        try:
            if sid < 0:
                sid = len(sids)
                sids.append(sp())
            elif sid >= len(sids):
                exsid = sid
                sid = len(sids)
                sids.append(sp())
                if sid > len(sids):
                    print(f'Sid is not {exsid}, but {sid}')
            else:
                sids[sid] = sp()
        except Exception as e:
            exit(f'Spawn error: {e}')
        lsid = sid
        setprompt()
        exps = ['(nknown host)|(not known)',
                'o route to host',
                'onnection refused',
                'closed by foreign host',
                'sure you want to continue connecting',
                '(ogin: ?$)|(ame: ?$)',
                'sword: ?$',
                sids[sid].prompt]
        if not con_wfn:
            exps.append('etconf server doesn')
        r = error = ''
        while not error and not logged:
            try:
                r = sids[sid].expect(exps, timeout=50)
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
                sids[sid].send('yes\r')
            elif r == 5:
                if nologin:
                    error = 'AUTH'
                else:
                    nologin = True
                    sids[sid].sendline(sids[sid].login)
            elif r == 6:
                if nopassword:
                    error = 'AUTH'
                else:
                    nologin = True
                    nopassword = True
                    sids[sid].sendline(sids[sid].password)
            elif r == 7:
                logged = True
            elif r == 8:
                error = 'NETCONF'
        else:
            if logged:
                break
            else:
                continue
    if error:
        if error == 'AUTH':
            try:
                se('^c$')
            except: pass
            sids.remove(sids[sid])
        if con_roe:
            return False
        else:
            exit('Exited due to '+error)
    else:
        return sids[sid]

@checksid
@setlsid
def reconnect(cmd='', sid='', login='', password='', **kwargs):
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
        sids[sid].prompt = name+r'(?:(?!\n).)*'+sn
    else:
        sids[sid].prompt = name+r'(?:(?!\n).)*(\)|\#|\>|\$|\~)'
    sids[sid].hname=name

@checksid
def getprompt(sid='', hn=''):
    return sids[sid].prompt

@checksid
@setlsid
def se(*args, sid='', flags='30'):
    if sid >= len(sids):
        exit('Sending to unopened sid: '+str(sid))
    if len(args) == 0:
        args += ('', None,)
    elif len(args) % 2 == 1:
        args += (None,)
    pairs = zip(*[iter(args)]*2)
    for id, (cmds,exps) in enumerate(pairs):
        if type(cmds) != list:
            cmds = str(cmds).strip().split('\n')
        cmds = [str(i).strip() for i in cmds if i]
        ans = 0
        err = ''
        for cmd in cmds:
            se_noexpect = False  # .$
            se_resetexp = False  # .#
            se_nocarret = False  # -c .
            se_control = False   # ^.
            se_sendslow = False  # -s .
            se_noexit = False    # -x .
            se_timeout = 600     # -t\d .
            se_interval = 0.01
            
            ''' Parse flags '''
            pfx = pcmd = ''
            pfx, _, pcmd = cmd.partition(' ')
            if pfx[0] == '-':
                cmd = pcmd
                if 'c' in pfx:
                    se_nocarret = True
                if 's' in pfx:
                    se_sendslow = True
                if 'x' in pfx:
                    se_noexit = True
                if 't' in pfx:
                    se_timeout = (re.findall(r'\d+', pfx) or [se_timeout])[0]
            else:
                pfx = ''
            if cmd[0] == '^':
                se_control = True
                se_nocarret = True
                cmd = cmd[1:]
            if cmd[-1] == '$':
                se_noexpect = True
                cmd = cmd[:-1]
            elif 'e' in pfx:
                se_noexpect = True
            elif cmd[-1] == '#':
                se_resetexp = True
                cmd = cmd[:-1]
            elif 'r' in pfx:
                se_resetexp = True
            
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
                exit('Send error: '+e)
            
            ''' Expecting '''
            ans = -1
            err = ''
            if se_noexpect:
                ans = 0
                continue
            try:
                if exps == None:
                    ans = sids[sid].expect(sids[sid].prompt, timeout=int(se_timeout))
                else:
                    ans = sids[sid].expect(exps, timeout=int(se_timeout))
            except EOF:
                if cmd in sids[sid].exitcmds:
                    err = 'EXITCMD'
                else:
                    err = 'EOF'
            except TIMEOUT:
                err = 'timeout'
                exit(f'TIMEOUT = {se_timeout}')
            else:
                sids[sid].last = buffer.prompt()
            finally:
                sids[sid].logfile_send = StringIO('')
                if se_resetexp:
                    sleep(0.5)
                    expclear()
                if type(exps) == list and len(exps) > 1:
                    if id < len(list(pairs))-1:
                        if len(cmds) > 1 or len(list(pairs)) > 1:
                            print('Expect list! Next SE will not be performed')
                    return ans
    if ans >= 0:
        return ans
    elif se_noexit or err == 'EXITCMD':
        return False
    else:
        exit(f'Expect: {err}')

@checksid
def expclear(ex=r'.*', sid=''):
    sids[sid].expect(ex, timeout=1)

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
    return str(ip_address(addr)+i)

def incrmac(mac, i=1):
     return re.sub(r'(..)(?!$)', r'\1:', f'{(int(mac.replace(":", ""), 16) + i):012X}')

def inbuffer(txt):
    try:
        txt = re.compile(r'(?i)'+txt)
    except:
        txt = re.compile(r'(?i)'+re.escape(txt))
    return len(re.findall(txt, buffer.all()))

def printf(file, text):
    file.write(text)
    print(text, end='', flush=True)

class t:
    def u(n=1):                 # up
        return f'\x1b[{n}A'
    def d(n=1):                 # down
        return f'\x1b[{n}B'
    def f(n=1):                 # forward
        return f'\x1b[{n}C'
    def b(n=1):                 # backward
        return f'\x1b[{n}D'
    def p(n=1):                 # prev
        return f'\x1b[{n}F'
    def n(n=1):                 # next
        return f'\x1b[{n}E'
    def m(n=1, m=1):            # move
        return f'\x1b[{n};{m}H'
    e = '\x1b[1J'               # erase
    s = '\x1b[s'                # save
    r = '\x1b[r'                # restore

os.environ["TERM"] = "dumb"
lsid = 0
sids = []
