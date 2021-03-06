#!/usr/bin/env python3.8
# -*- coding: utf-8 -*-

from .pex import *

@staticmethod
@setmethod(Prompt)
@checksid
def _shell(hostname, sid=''):
    name, sn = gethostname(hostname)
    return r'\[\S+@'+name+r' \S+\] ?'

def tping(addr, count=1):
    s,_ = getstatusoutput(f'for i in `seq 1 {count}`; '
                           'do sudo ip netns exec test_a '
                          f'ping {addr} -c 1 -w 1 >/dev/null 2>&1 '
                           '&& break; done')
    return True if s == 0 else False

def lping(dst, src='', cnt=1, vrf=''):
    for i in range(cnt):
        se(f'ping {dst}' + \
          (f' source {src}' if src else '') + \
          (f' vrf {vrf}' if vrf else '') + \
            'count 1')
        if inbuffer('100 percent'): return True
        sleep(3)
    return False

@checksid
def isrootview(sid=''):
    return bool(re.search(sids[sid].hname+r'\(config', buffer.prompt()))

def isoffline():
    return bool(re.search(r'offline mode', buffer.prompt()))

def confview(f):
    def wrap(*args, **kwargs):
        if isrootview():
            se('-ce do ')
        f(*args, **kwargs)
    return wrap

@contextmanager
def rootshell():
    setprompt(type='shell')
    confview(se)('rootshell', 'assword:', 'password')
    if inbuffer('Authentication'):
        exit('Check rootshell password or SE logic')
    yield
    setprompt()
    se('exit')

def inbufferlog(text, ex=''):
    with rootshell():
        se(f'grep -E "{text}" /var/log/syslog/buffer* 2>/dev/null '+ \
           f'| grep -Ev "took|timed ou'+(f'|{ex}"' if ex else '"')+' | head -5')
        return True if buffer.all() else False

def getlogs(msg='', quit=True):
    print(f'\nError: {msg}') if msg else None
    confview(se)('show tech-support')
    confview(se)(f'copy fs://logs tftp://{host}/logs/tech-support/ vrf mgmt-intf')
    if quit: exit(1)

def switchover():
    se('redundancy switchover', 'with the switchover', 'y')
    var = r'(ot all services)|(is not allowed on slave)|(lave fmc is not found)'
    return ans.lastindex if (ans := re.search(var, buffer.all())) else 0

def showtree(cmd):
    
    def gethelp(cmds):
        out = re.findall(r'(?m)^  (\S+(?: \S+)*)', cmds)
        return out
    
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
            'RD IPv4:Nr(0-65535)': ['10.0.0.134:0', '10.0.0.26:0'],
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
            'Location': [],
            'IF': ['0/0/1']
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
                expclear()
                se(f'-c {cmd} ?')
                shownext(gethelp(buffer.all()))
        se('-te w')
    
    cmds = []
    last = ['|', '<cr>']
    if type(cmd) == str:
        cmd = [cmd]
    for i in cmd:
        se(f'-c show {i} ?')
        shownext(gethelp(buffer.all()))
        se('-t c')
    return cmds

def entercfg(filename, commitonexit=False, exitonerror=True, startcmd=''):
    if not os.path.exists(filename):
        print(f'\nFile {filename} not exist')
        return False
    with open(filename) as file:
        cmds = [i.rstrip('\n') for i in file.readlines()]
    flen = len(cmds)
    if not isrootview():
        se('config')
    tstart = now()
    for num, cmd in enumerate(cmds):
        if startcmd and not cmd.strip().startswith(startcmd):
            continue
        else:
            startcmd = ''
        ans = se(cmd.strip(), [getprompt(), 'changes found'])
        if ans == 1:
            se('n')
            se('clear')
            print('\nSuddenly exited from root view')
            return False
        if exitonerror and buffer.all().startswith('Syntax error'):
            se('clear')
            print('\nCommand error')
            return False
        if not isrootview():
            print('\nSuddenly exited from root view')
            return False
        if (commitonexit and cmd.startswith('exit')) or num == flen-1:
            se('commit')
            if not inbuffer('successfully'):
                se('clear')
                print('\nCommit error')
                return False
    print(f'\nEntered {flen} lines with {int(flen/(now()-tstart))} lps')


host = '192.168.16.22'
