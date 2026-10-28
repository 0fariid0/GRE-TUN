#!/usr/bin/env python3
"""Opt-in IPv4 TCP transparent HAProxy forwards, with per-connection return routing.
No shell execution, no PROXY headers, no changes during plan generation.
"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

VERSION = '12.2.0'
STATE = Path('/etc/gretun-transparent')
CONFIG = Path('/etc/haproxy/haproxy.cfg')
MODULE = Path('/usr/local/lib/gretun/transparent_forward.py')
UNIT = Path('/etc/systemd/system/gretun-transparent.service')
SYSTEMD = Path('/etc/systemd/system')
MASK = '0xffff0000'
PREFIX = 'gretun-tp:'

class Error(Exception):
    pass

def run(*args, check=True, timeout=20):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise Error(f"{shlex.join(str(x) for x in args[:8])}: {result.stderr.strip()[:1500] or 'failed'}")
    return result

def jrun(*args):
    return json.loads(run(*args).stdout)

def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise Error('An IPv4 address is required.')
    if address.is_multicast or address.is_unspecified or address.is_loopback:
        raise Error('Invalid tunnel/peer IPv4 address.')
    return str(address)

def port(value):
    if not re.fullmatch(r'[0-9]{1,5}', str(value)) or not 1 <= int(value) <= 65535:
        raise Error('Port must be between 1 and 65535.')
    return int(value)

def validate_plan(p):
    keys = {'version','iface','iran','outside','backend_port','frontend_port','test_port','kind','id'}
    if not isinstance(p, dict) or set(p) != keys or p['version'] != 1:
        raise Error('Unsupported plan format.')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', p['iface']) or p['iface'] in ('lo','eth0'):
        raise Error('A dedicated tunnel interface is required.')
    if p['kind'] not in ('gre','wireguard'):
        raise Error('Only routed GRE/GRE Plus and single-peer WireGuard are supported.')
    for name in ('iran','outside'):
        p[name] = ipv4(p[name])
    if p['iran'] == p['outside']:
        raise Error('Tunnel addresses must differ.')
    for name in ('backend_port','frontend_port','test_port'):
        p[name] = port(p[name])
    if p['test_port'] == p['frontend_port']:
        raise Error('The trial port must differ from the production port.')
    identity = {k:v for k,v in p.items() if k != 'id'}
    expected = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:12]
    if p['id'] != expected:
        raise Error('Plan checksum mismatch.')
    return p

def make_plan(iface, iran, outside, backend_port, frontend_port, test_port, kind):
    p = dict(version=1, iface=iface, iran=iran, outside=outside, backend_port=port(backend_port),
             frontend_port=port(frontend_port), test_port=port(test_port), kind=kind)
    p['id'] = hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest()[:12]
    return validate_plan(p)

def encode(p):
    return base64.urlsafe_b64encode(json.dumps(validate_plan(dict(p)), sort_keys=True).encode()).decode().rstrip('=')

def decode(token):
    if len(token) > 4096 or not re.fullmatch(r'[A-Za-z0-9_-]+', token):
        raise Error('Invalid plan token.')
    try:
        return validate_plan(json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))))
    except (ValueError, TypeError, KeyError) as e:
        raise Error('Invalid plan token.') from e

def plan_argument(value):
    if value.startswith('@'):
        path=Path(value[1:])
        if path.stat().st_size>4096: raise Error('Plan file is too large.')
        return validate_plan(json.loads(path.read_text()))
    return decode(value)

def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.'+path.name+'.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as out:
            out.write(data.encode() if isinstance(data, str) else data)
            out.flush(); os.fsync(out.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

@contextlib.contextmanager
def locked():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE, 0o700)
    with (STATE/'lock').open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield

def records():
    if not STATE.exists(): return []
    return [json.loads(p.read_text()) for p in sorted(STATE.glob('profile-*.json'))]

def save(record):
    atomic(STATE/f"profile-{record['plan']['id']}.json", json.dumps(record, indent=2)+'\n')

def load(identifier):
    if not re.fullmatch(r'[a-f0-9]{12}', identifier): raise Error('Invalid profile ID.')
    path = STATE/f'profile-{identifier}.json'
    if not path.exists(): raise Error('Profile not found.')
    r = json.loads(path.read_text()); validate_plan(r['plan'])
    return r

def interfaces():
    addresses = {a['ifname']:a for a in jrun('ip','-j','-4','addr','show')}
    result=[]
    for link in jrun('ip','-j','-d','link','show'):
        name = link['ifname'].split('@')[0]
        kind = link.get('linkinfo',{}).get('info_kind')
        if kind not in ('gre','wireguard'): continue
        for address in addresses.get(name,{}).get('addr_info',[]):
            if address.get('family') == 'inet':
                result.append(dict(iface=name, kind=kind, address=address['local'], prefix=address['prefixlen'],
                                   up='UP' in link.get('flags',[])))
    return result

def check_interface(p, role):
    expected = p[role]
    found = next((x for x in interfaces() if x['iface']==p['iface'] and x['address']==expected), None)
    if not found or not found['up'] or found['kind'] != p['kind']:
        raise Error(f"{p['iface']} must be UP with {expected} on this {role} server.")
    peer = p['iran' if role=='outside' else 'outside']
    network = ipaddress.IPv4Network(f"{expected}/{found['prefix']}", strict=False)
    if ipaddress.IPv4Address(peer) not in network or peer in (str(network.network_address),str(network.broadcast_address)):
        raise Error('The two inner addresses must be usable hosts in the same subnet.')
    route = jrun('ip','-j','-4','route','get',peer)
    if not route or route[0].get('dev') != p['iface']:
        raise Error('Peer route is not through the selected tunnel.')
    return found

def sections(text):
    lines=text.splitlines(keepends=True); found=[]
    for i,line in enumerate(lines):
        match=re.match(r'^(global|defaults|frontend|backend|listen|resolvers|peers|userlist|program|mailers|cache|ring|log-forward)(?:\s+(\S+))?',line)
        if match: found.append((i,match[1],match[2]))
    return lines, [(start, found[n+1][0] if n+1<len(found) else len(lines), kind,name)
                   for n,(start,kind,name) in enumerate(found)]

def block(text, kind, name):
    lines, items=sections(text)
    matches=[(a,b) for a,b,k,n in items if k==kind and n==name]
    if len(matches)!=1: raise Error(f'Expected exactly one {kind} {name}.')
    a,b=matches[0]; return ''.join(lines[a:b])

def forward(text, number):
    front=block(text,'frontend',f'ws_{number}_in')
    back=block(text,'backend',f'ws_{number}_out')
    if not re.search(r'^\s*mode\s+tcp\s*$',front,re.M) or not re.search(r'^\s*mode\s+tcp\s*$',back,re.M):
        raise Error('First release supports TCP-mode forwards only; HTTP-mode rows are left unchanged.')
    binds=re.findall(r'^\s*bind\s+(\S+)\s*$',front,re.M)
    if len(binds)!=1 or binds[0] not in (f'*:{number}',f'0.0.0.0:{number}'):
        raise Error('Requires a simple IPv4 wildcard listener; TLS-terminating/IPv6/multiple binds are left unchanged.')
    if len(re.findall(r'^\s*default_backend\s+',front,re.M))!=1 or re.search(r'^\s*(use_backend|tcp-request)\s',front,re.M):
        raise Error('Custom frontend ACLs/routing need manual review.')
    servers=re.findall(r'^\s*server\s+(\S+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s*$',back,re.M)
    if len(servers)!=1 or re.search(r'^\s*(source|default-server|server-template)\s',back,re.M):
        raise Error('Requires one plain TCP backend server, without PROXY/TLS/server overrides.')
    return ipv4(servers[0][1]),port(servers[0][2])

def add_trial(text,p):
    forward(text,p['frontend_port'])
    if re.search(r'^\s*bind\s+\S*:'+str(p['test_port'])+r'(?:\s|$)',text,re.M):
        raise Error('Trial port already exists in HAProxy.')
    name='gtp_'+p['id']
    return text.rstrip()+f'''\n\n# {PREFIX}{p['id']} BEGIN
frontend {name}_test
    bind 0.0.0.0:{p['test_port']}
    mode tcp
    timeout client 2h
    default_backend {name}_out
backend {name}_out
    mode tcp
    timeout connect 10s
    timeout server 2h
    source 0.0.0.0 usesrc clientip
    server transparent {p['outside']}:{p['backend_port']}
# {PREFIX}{p['id']} END
'''

def promote_text(text,p,disable=False):
    name=f"ws_{p['frontend_port']}_in"
    current=block(text,'frontend',name)
    old='gtp_'+p['id']+'_out' if disable else f"ws_{p['frontend_port']}_out"
    new=f"ws_{p['frontend_port']}_out" if disable else 'gtp_'+p['id']+'_out'
    expression=r'(^\s*default_backend\s+)'+re.escape(old)+r'(\s*$)'
    updated,count=re.subn(expression,lambda m:m[1]+new+m[2],current,flags=re.M)
    if count!=1: raise Error('The production frontend changed; refuse to overwrite it.')
    return text.replace(current,updated,1)

def remove_trial(text,p):
    pattern=r'\n?# '+re.escape(PREFIX+p['id'])+r' BEGIN\n.*?# '+re.escape(PREFIX+p['id'])+r' END\n?'
    updated,n=re.subn(pattern,'\n',text,flags=re.S)
    if n!=1: raise Error('Managed trial block was changed; remove it manually after review.')
    return updated

def root_checks(role):
    if os.geteuid()!=0: raise Error('Run with sudo.')
    capabilities=int(re.search(r'^CapEff:\s*(\w+)',Path('/proc/self/status').read_text(),re.M)[1],16)
    if not capabilities & (1<<12): raise Error('CAP_NET_ADMIN is required; containers without network privileges are refused.')
    for binary in ('ip','iptables','iptables-save','conntrack','systemctl','ss'):
        if not shutil.which(binary): raise Error(f'Missing {binary}; install prerequisites first (iproute2 iptables conntrack).')
    if role=='iran':
        if not shutil.which('haproxy'): raise Error('HAProxy is not installed.')
        features=run('haproxy','-vv').stdout
        if '+TPROXY' not in features: raise Error('HAProxy lacks TPROXY support.')
        if not capabilities & (1<<13): raise Error('CAP_NET_RAW is required on Iran.')
        config=CONFIG.read_text()
        if re.search(r'^\s*hard-stop-after\s+',config,re.M):
            raise Error('hard-stop-after can terminate old sessions during reload; review it before transparent migration.')
        # Do not globally change the service account to root, or weaken a hardened service.
        if re.search(r'^\s*(user|uid)\s+(?!root\s*$|0\s*$)\S+',block(config,'global',None),re.M):
            raise Error('HAProxy drops worker privileges. Capability setup needs manual review; no user/group change was made.')
        user=run('systemctl','show','haproxy','--property=User','--value').stdout.strip()
        if user not in ('','root'): raise Error('HAProxy systemd User is not root; capability setup needs review.')
        bounding=run('systemctl','show','haproxy','--property=CapabilityBoundingSet','--value').stdout.lower()
        if 'cap_net_raw' not in bounding and 'cap_net_admin' not in bounding:
            raise Error('HAProxy service capability bounding set excludes transparent sockets.')
        if run('systemctl','show','haproxy','--property=CanReload','--value').stdout.strip()!='yes':
            raise Error('A working graceful reload service is required; restart is never substituted.')
        if run('systemctl','is-active','--quiet','haproxy',check=False).returncode:
            raise Error('HAProxy must already be active.')
        # Test the same non-local socket capability used by HAProxy, without sending packets.
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_IP,19,1)  # IP_TRANSPARENT
                sock.bind(('198.18.255.254',0))
        except OSError as e: raise Error(f'Transparent socket capability unavailable: {e}')
    # Detect broad third-party mark overwrites, which could erase our connection marks.
    for line in run('iptables-save','-t','mangle').stdout.splitlines():
        if PREFIX in line: continue
        match=re.search(r'--set-(?:x)?mark\s+(0x[0-9a-fA-F]+|[0-9]+)(?:/(0x[0-9a-fA-F]+|[0-9]+))?',line)
        if match and (int(match[2],0) if match[2] else 0xffffffff)&0xffff0000:
            raise Error('Existing mangle mark rules overlap the reserved high mark bits; manual review required.')

def allocate_slot():
    used={r['slot'] for r in records()}
    rules=jrun('ip','-j','-4','rule','show')
    usedpriorities={int(r.get('priority',0)) for r in rules}
    usedtables={str(r.get('table','')) for r in rules}
    for location in ('/etc/iproute2','/usr/lib/iproute2'):
        base=Path(location)
        for path in [base/'rt_tables',*(base/'rt_tables.d').glob('*.conf')]:
            if not path.is_file(): continue
            for line in path.read_text().splitlines():
                fields=line.split('#',1)[0].split()
                if len(fields)>=2 and fields[0].isdigit(): usedtables.add(fields[0])
    for slot in range(1,201):
        if slot in used or 25000+slot in usedpriorities: continue
        table=str(45000+slot)
        if table in usedtables: continue
        if run('ip','-4','route','show','table',table,check=False).stdout.strip(): continue
        mark=0x6d000000+(slot<<16)
        conflict=False
        for r in rules:
            if 'fwmark' in r:
                value=int(str(r['fwmark']),0); mask=int(str(r.get('fwmask',0xffffffff)),0)
                if (value & mask & 0xffff0000)==(mark & mask & 0xffff0000): conflict=True
        if not conflict: return slot
    raise Error('No unused routing slot available.')

def rules_for(r):
    p=r['plan']; role=r['role']; tag=PREFIX+p['id']+':'+role
    mark=hex(0x6d000000+(r['slot']<<16)); marked=mark+'/'+MASK
    iface=p['iface']; outside=p['outside']; bp=str(p['backend_port'])
    rules=[]
    def add(table,chain,kind,*args):
        rules.append([table,chain,*args,'-m','comment','--comment',tag+':'+kind])
    if role=='outside':
        add('mangle','PREROUTING','new','-i',iface,'-d',outside,'!','-s',p['iran'],'-p','tcp','--dport',bp,
            '-m','conntrack','--ctstate','NEW','--ctdir','ORIGINAL','-j','CONNMARK','--set-xmark',marked)
        add('mangle','OUTPUT','reply','-s',outside,'-p','tcp','--sport',bp,'-m','connmark','--mark',marked,
            '-j','CONNMARK','--restore-mark','--nfmask',MASK,'--ctmask',MASK)
        add('nat','POSTROUTING','no-snat','-o',iface,'-s',outside,'-p','tcp','--sport',bp,
            '-m','connmark','--mark',marked,'-j','ACCEPT')
        add('filter','INPUT','input','-i',iface,'-d',outside,'-p','tcp','--dport',bp,'-j','ACCEPT')
        add('filter','OUTPUT','output','-o',iface,'-s',outside,'-p','tcp','--sport',bp,'-j','ACCEPT')
    else:
        add('mangle','PREROUTING','socket','-i',iface,'-s',outside,'-p','tcp','--sport',bp,
            '-m','socket','--transparent','-j','MARK','--set-xmark',marked)
        if r['phase']!='draining':
            add('mangle','OUTPUT','track','-o',iface,'-d',outside,'-p','tcp','--dport',bp,
                '-m','addrtype','!','--src-type','LOCAL','-m','conntrack','--ctstate','NEW',
                '-j','CONNMARK','--set-xmark',marked)
        add('nat','POSTROUTING','no-snat','-o',iface,'-d',outside,'-p','tcp','--dport',bp,'-j','ACCEPT')
        add('filter','INPUT','reply','-i',iface,'-s',outside,'-p','tcp','--sport',bp,'-j','ACCEPT')
        add('filter','OUTPUT','output','-o',iface,'-d',outside,'-p','tcp','--dport',bp,'-j','ACCEPT')
        if r['phase']!='draining':
            add('filter','INPUT','trial','-p','tcp','--dport',str(p['test_port']),'-j','ACCEPT')
    return rules

def apply_rule(rule):
    table,chain,*args=rule
    if run('iptables','-w','5','-t',table,'-C',chain,*args,check=False).returncode:
        run('iptables','-w','5','-t',table,'-I',chain,'1',*args)

def delete_rule(rule):
    table,chain,*args=rule
    while run('iptables','-w','5','-t',table,'-C',chain,*args,check=False).returncode==0:
        run('iptables','-w','5','-t',table,'-D',chain,*args)

def rp_path(iface):
    return Path('/proc/sys/net/ipv4/conf')/iface/'rp_filter'

def wg_settings(text):
    sections_found=re.findall(r'^\s*\[([^]]+)\]',text,re.M)
    if sections_found!=['Interface','Peer']: raise Error('WireGuard requires exactly one peer.')
    peer=re.search(r'^\s*PublicKey\s*=\s*(\S+)\s*$',text,re.M)
    allowed=re.search(r'^\s*AllowedIPs\s*=\s*(.*?)\s*$',text,re.M)
    table=re.search(r'^\s*Table\s*=\s*(\S+)\s*$',text,re.M)
    if not peer or not allowed: raise Error('Invalid WireGuard config.')
    return peer[1],allowed[1],table[1] if table else None

def patch_wg(text):
    wg_settings(text)
    text=re.sub(r'(^\s*AllowedIPs\s*=).*$',r'\1 0.0.0.0/0',text,flags=re.M)
    if re.search(r'^\s*Table\s*=',text,re.M):
        text=re.sub(r'(^\s*Table\s*=).*$',r'\1 off',text,flags=re.M)
    else: text=re.sub(r'(^\s*\[Interface\]\s*\n)',r'\1Table = off\n',text,count=1,flags=re.M)
    return text

def wireguard_path(iface):
    return Path('/etc/wireguard')/(iface+'.conf')

def prepare_wg(r):
    if r['role']!='outside' or r['plan']['kind']!='wireguard': return
    iface=r['plan']['iface']; path=wireguard_path(iface)
    shared=next((x for x in records() if x['plan']['iface']==iface and x['plan']['id']!=r['plan']['id']),None)
    if shared and shared.get('wg'):
        r['wg']=shared['wg']; return
    text=path.read_text(); key,allowed,table=wg_settings(text)
    if allowed.strip()!=r['plan']['iran']+'/32' or table not in (None,'auto','off'):
        raise Error('WireGuard baseline must have one peer and only the Iran inner /32; custom AllowedIPs need review.')
    peers=run('wg','show',iface,'peers').stdout.split()
    if peers!=[key]: raise Error('WireGuard runtime peer does not match its saved config.')
    runtime=run('wg','show',iface,'allowed-ips').stdout.split()
    if runtime != [key,r['plan']['iran']+'/32']:
        raise Error('WireGuard runtime AllowedIPs differ from the saved /32; review first.')
    if re.search(r'^\s*(SaveConfig\s*=\s*true|PreUp|PostUp|PreDown|PostDown)\b',text,re.M|re.I):
        raise Error('WireGuard hooks/SaveConfig need manual review.')
    directory=STATE/('backup-'+r['plan']['id']); directory.mkdir(mode=0o700,exist_ok=True)
    atomic(directory/'wireguard.conf',text)
    patched=patch_wg(text)
    r['wg']=dict(key=key,allowed=allowed,path=str(path),backup=str(directory/'wireguard.conf'),
                 patched_hash=hashlib.sha256(patched.encode()).hexdigest())

def apply_wg(r):
    if not r.get('wg'): return
    w=r['wg']; path=Path(w['path']); text=path.read_text()
    original=Path(w['backup']).read_bytes()
    if text.encode()!=original and hashlib.sha256(text.encode()).hexdigest()!=w['patched_hash']:
        raise Error('WireGuard config changed since preparation; refusing to overwrite it.')
    atomic(path,patch_wg(text))
    run('wg','set',r['plan']['iface'],'peer',w['key'],'allowed-ips','0.0.0.0/0')

def restore_wg(r):
    if not r.get('wg'): return
    if any(x['plan']['id']!=r['plan']['id'] and x['plan']['iface']==r['plan']['iface'] for x in records()): return
    w=r['wg']; path=Path(w['path'])
    if path.read_bytes()==Path(w['backup']).read_bytes(): return
    if hashlib.sha256(path.read_bytes()).hexdigest()!=w['patched_hash']:
        raise Error('WireGuard file changed; backup retained, no overwrite attempted.')
    atomic(path,Path(w['backup']).read_bytes())
    run('wg','set',r['plan']['iface'],'peer',w['key'],'allowed-ips',w['allowed'])

def apply_network(r):
    p=r['plan']; check_interface(p,r['role'])
    mark=hex(0x6d000000+(r['slot']<<16))+'/'+MASK
    table=str(45000+r['slot']); priority=str(25000+r['slot'])
    # This table belongs to this profile only. Never change the main/default table.
    if r['role']=='outside':
        run('ip','-4','route','replace','default','via',p['iran'],'dev',p['iface'],'table',table)
    else:
        run('ip','-4','route','replace','local','0.0.0.0/0','dev','lo','table',table)
    rules=jrun('ip','-j','-4','rule','show')
    matches=[x for x in rules if x.get('priority')==int(priority)]
    if matches:
        existing=matches[0]
        if int(str(existing.get('table',0)),0)!=int(table) or int(str(existing.get('fwmark','0')),0)!=int(mark.split('/')[0],0) or int(str(existing.get('fwmask',0xffffffff)),0)!=0xffff0000:
            raise Error('Policy routing priority was taken by another service.')
    else: run('ip','-4','rule','add','priority',priority,'fwmark',mark,'table',table)
    if r.get('wg'): apply_wg(r)
    rp_path(p['iface']).write_text('2') # Per-interface loose RPF; leave global settings alone.
    for rule in rules_for(r): apply_rule(rule)

def remove_network(r):
    if r.get('wg') and not any(x['plan']['id']!=r['plan']['id'] and x['plan']['iface']==r['plan']['iface'] for x in records()):
        path=Path(r['wg']['path']); original=Path(r['wg']['backup']).read_bytes()
        if path.read_bytes()!=original and hashlib.sha256(path.read_bytes()).hexdigest()!=r['wg']['patched_hash']:
            raise Error('WireGuard file changed; return paths retained pending review.')
    all_rules=rules_for(r)
    if r['role']=='iran':
        # Also remove trial/new-connection rules left by an interrupted drain.
        for rule in rules_for(dict(r,phase='trial')):
            if rule not in all_rules: all_rules.append(rule)
    for rule in reversed(all_rules): delete_rule(rule)
    table=str(45000+r['slot']); priority=str(25000+r['slot'])
    mark=hex(0x6d000000+(r['slot']<<16))+'/'+MASK
    run('ip','-4','rule','del','priority',priority,'fwmark',mark,'table',table,check=False)
    if r['role']=='iran':
        run('ip','-4','route','del','local','0.0.0.0/0','dev','lo','table',table,check=False)
    else:
        run('ip','-4','route','del','default','via',r['plan']['iran'],'dev',r['plan']['iface'],'table',table,check=False)
    restore_wg(r)
    if not any(x['plan']['id']!=r['plan']['id'] and x['plan']['iface']==r['plan']['iface'] for x in records()):
        rp_path(r['plan']['iface']).write_text(r['original_rp'])

def persist():
    MODULE.parent.mkdir(parents=True,exist_ok=True)
    if Path(__file__).resolve()!=MODULE.resolve(): atomic(MODULE,Path(__file__).read_bytes(),0o755)
    dependencies=[]
    for r in records():
        iface=r['plan']['iface']
        if r['plan']['kind']=='wireguard': dependencies.append('wg-quick@'+iface+'.service')
        elif re.fullmatch(r'greplus\d+',iface): dependencies.append('greplus-tunnel@'+iface[7:]+'.service')
        elif re.fullmatch(r'gre\d+',iface): dependencies.append('gre-tunnel@'+iface[3:]+'.service')
    deps=' '.join(sorted(set(dependencies)))
    for r in records():
        if r['plan']['kind']=='wireguard':
            dropin=SYSTEMD/('wg-quick@'+r['plan']['iface']+'.service.d')/'70-gretun-transparent.conf'
            if dropin.exists() and not dropin.read_text().startswith('# GRE-TUN transparent'):
                raise Error('The transparent WireGuard drop-in path already belongs to another configuration.')
            atomic(dropin,f"# GRE-TUN transparent\n[Service]\nExecStartPost=/usr/bin/python3 {MODULE} restore {r['plan']['iface']}\n",0o644)
    if UNIT.exists() and not UNIT.read_text().startswith('# GRE-TUN transparent'):
        raise Error('The service unit path already belongs to another configuration.')
    atomic(UNIT,f'''# GRE-TUN transparent
[Unit]
Description=GRE-TUN transparent forwarding routes
After=network-online.target {deps}
Wants=network-online.target {deps}
Before=haproxy.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {MODULE} restore
RemainAfterExit=yes
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
''',0o644)
    run('systemctl','daemon-reload'); run('systemctl','enable','gretun-transparent.service')

def validate_config(text):
    fd,name=tempfile.mkstemp(prefix='.tp-check.',dir=CONFIG.parent)
    try:
        with os.fdopen(fd,'w') as f: f.write(text)
        run('haproxy','-c','-q','-f',name)
    finally: os.unlink(name)

def reload_config(old,new):
    validate_config(new)
    if CONFIG.read_text()!=old: raise Error('HAProxy config changed concurrently; try again after review.')
    atomic(CONFIG,new,CONFIG.stat().st_mode&0o777)
    try: run('systemctl','reload','haproxy')
    except Exception:
        atomic(CONFIG,old)
        run('systemctl','reload','haproxy',check=False)
        raise

def stage(p,role):
    root_checks(role); check_interface(p,role)
    if any(r['plan']['id']==p['id'] for r in records()):
        raise Error('This profile already exists; use status/promote/drain instead.')
    if any(r['role']==role and r['plan']['iface']==p['iface'] and r['plan']['outside']==p['outside']
           and r['plan']['backend_port']==p['backend_port'] for r in records()):
        raise Error('That tunnel/backend port already belongs to a profile.')
    shared=next((r for r in records() if r['plan']['iface']==p['iface']),None)
    if shared and shared['role']!=role: raise Error('Do not combine Iran/outside roles on one interface.')
    r=dict(plan=p,role=role,phase='trial' if role=='iran' else 'ready',slot=allocate_slot(),
           original_rp=shared['original_rp'] if shared else rp_path(p['iface']).read_text().strip())
    old=None
    if p['kind']=='wireguard' and not shutil.which('wg'): raise Error('WireGuard tools are missing.')
    if role=='iran':
        old=CONFIG.read_text(); original_target,bp=forward(old,p['frontend_port'])
        if bp!=p['backend_port']: raise Error('Backend port differs from the plan.')
        # Reject an existing kernel listener on the new external test port.
        listeners=run('ss','-H','-lnt').stdout
        if re.search(r':'+str(p['test_port'])+r'\s',listeners): raise Error('Trial port is busy.')
        new=add_trial(old,p); validate_config(new)
        directory=STATE/('backup-'+p['id']); directory.mkdir(mode=0o700,exist_ok=True)
        atomic(directory/'haproxy.cfg',old)
        r['original_target']=original_target
    else:
        if p['kind']=='wireguard': prepare_wg(r)
        listeners=run('ss','-H','-lnt').stdout
        if not any(re.search(r'(?:0\.0\.0\.0|\*|'+re.escape(p['outside'])+r'|\[::\]):'+str(p['backend_port'])+r'\s',x) for x in listeners.splitlines()):
            raise Error('No TCP listener found for the selected backend address/port.')
    # Save a recoverable transaction before applying kernel resources.
    r['phase_before_apply']=r['phase']; r['phase']='preparing'; save(r)
    try:
        r['phase']=r.pop('phase_before_apply')
        apply_network(r)
        if old is not None: reload_config(old,new)
        save(r); persist()
    except (Exception, KeyboardInterrupt) as problem:
        # If reload succeeded, undo the generated listener before removing its return path.
        if old is not None and CONFIG.exists() and CONFIG.read_text()!=old:
            try: reload_config(CONFIG.read_text(),old)
            except Exception:
                r['phase']='recovery-needed'; save(r)
                raise Error('Rollback reload failed; kernel routes retained. Inspect HAProxy and profile status.') from problem
        try: remove_network(r)
        except Exception:
            r['phase']='recovery-needed'; save(r)
            raise Error('Rollback incomplete; saved profile retained for recovery.') from problem
        (STATE/f"profile-{p['id']}.json").unlink(missing_ok=True)
        raise
    print(f"Prepared {role} profile {p['id']}. Main default gateway and Xray settings were not changed.")
    if role=='iran':
        print(f"TRIAL ONLY: test one client using the SAME credentials/transport, external port {p['test_port']}.")
        print('Only after confirming handshake, real client IP and traffic, use promote '+p['id'])
    else: print('Now prepare the Iran side with the same token. Keep this outside profile enabled.')


def marked_connections(r):
    mark=hex(0x6d000000+(r['slot']<<16))+'/'+MASK
    result=run('conntrack','-L','-p','tcp','--mark',mark,check=False)
    if result.returncode not in (0,1) or (result.returncode==1 and not re.search(r'0 flow entries',result.stderr)):
        raise Error('Could not count conntrack entries; refuse to remove return routes.')
    return len([x for x in result.stdout.splitlines() if x.strip()])

def promote(identifier):
    r=load(identifier); root_checks('iran')
    if r['role']!='iran' or r['phase']!='trial': raise Error('Only an Iran trial profile can be promoted.')
    old=CONFIG.read_text(); new=promote_text(old,r['plan'])
    reload_config(old,new)
    r['phase']='active'
    try: save(r)
    except Exception:
        reload_config(CONFIG.read_text(),old)
        raise
    print('New connections now use the transparent backend. Existing sessions drain via graceful reload.')

def drain(identifier):
    r=load(identifier); root_checks(r['role'])
    if r['role']=='iran' and r['phase']!='draining':
        old=CONFIG.read_text(); new=old; previous_phase=r['phase']
        if r['phase']=='active': new=promote_text(new,r['plan'],disable=True)
        new=remove_trial(new,r['plan']); reload_config(old,new)
        r['phase']='draining'
        try: save(r)
        except Exception:
            reload_config(CONFIG.read_text(),old)
            raise
        # Persist the phase first: an interrupted drain keeps extra owned rules,
        # which cleanup can remove after the connections have finished.
        for rule in rules_for(dict(r,phase=previous_phase)):
            if rule[-1].endswith(':track') or rule[-1].endswith(':trial'): delete_rule(rule)
    else:
        r['phase']='draining'; save(r)
    print('Return paths remain until all marked TCP connections have closed.')
    print('Drain/remove Iran first; then drain/remove the corresponding outside profile.')
    print('Marked connections remaining:',marked_connections(r))


def cleanup(identifier):
    r=load(identifier); root_checks(r['role'])
    if r['phase']!='draining': raise Error('Use drain first; active profiles cannot be deleted.')
    if r['role']=='iran':
        current=CONFIG.read_text()
        if PREFIX+r['plan']['id']+' BEGIN' in current or 'gtp_'+r['plan']['id']+'_out' in current:
            raise Error('HAProxy still references this profile; refuse to remove its return paths.')
    count=marked_connections(r)
    if count: raise Error(f'{count} marked connections remain; routes retained. Retry cleanup later.')
    remove_network(r)
    (STATE/f'profile-{identifier}.json').unlink()
    if r['plan']['kind']=='wireguard' and not any(x['plan']['iface']==r['plan']['iface'] for x in records()):
        dropin=SYSTEMD/('wg-quick@'+r['plan']['iface']+'.service.d')/'70-gretun-transparent.conf'
        if dropin.exists() and dropin.read_text().startswith('# GRE-TUN transparent'): dropin.unlink()
    if records(): persist()
    else:
        run('systemctl','disable','gretun-transparent.service')
        UNIT.unlink(missing_ok=True); run('systemctl','daemon-reload')
    print('Profile removed after its connections drained. Backups retained under',STATE)

def status():
    for r in records():
        p=r['plan']; print(p['id'],r['role'],r['phase'],p['iface'],f"{p['iran']} <-> {p['outside']}:{p['backend_port']}")

def restore(iface=None):
    errors=[]
    for r in records():
        if iface and r['plan']['iface']!=iface: continue
        try:
            if r['phase'] in ('preparing','recovery-needed'):
                raise Error('Incomplete transaction; review this profile before restoring it.')
            deadline=time.monotonic()+10
            while True:
                try: check_interface(r['plan'],r['role']); break
                except Error:
                    if time.monotonic()>=deadline: raise
                    time.sleep(1)
            apply_network(r)
        except (Error,OSError,subprocess.SubprocessError) as problem:
            errors.append(r['plan']['id']+': '+str(problem))
    if errors:
        raise Error('Other valid profiles were restored. Problems: '+'; '.join(errors))


def menu():
    while True:
        print('\nTransparent IPv4 TCP forwarding |',VERSION)
        print('1) Create a plan on Iran (read-only)\n2) Prepare OUTSIDE using token\n3) Start IRAN trial using token')
        print('4) Promote a tested Iran profile\n5) Status\n6) Drain profile\n7) Cleanup drained profile\n00) Back')
        choice=input('Choose: ').strip()
        if choice=='00': return
        if choice=='1':
            options=interfaces()
            for n,x in enumerate(options,1): print(n,x['iface'],x['address'],x['kind'],'UP' if x['up'] else 'DOWN')
            selected=int(input('Tunnel row: '))-1
            if not 0<=selected<len(options): raise Error('Invalid tunnel row.')
            x=options[selected]
            rows=[]
            for match in re.finditer(r'^frontend ws_(\d+)_in\s*$',CONFIG.read_text(),re.M):
                try:
                    address,bp=forward(CONFIG.read_text(),int(match[1])); rows.append((int(match[1]),address,bp))
                except Error: pass
            for n,row in enumerate(rows,1): print(n,'public',row[0],'->',f'{row[1]}:{row[2]}')
            selected=int(input('Existing TCP forward row: '))-1
            if not 0<=selected<len(rows): raise Error('Invalid forward row.')
            fp,address,bp=rows[selected]
            suggested=''
            network=ipaddress.IPv4Interface(f"{x['address']}/{x['prefix']}").network
            if network.prefixlen==30:
                suggested=next((str(h) for h in network.hosts() if str(h)!=x['address']),'')
            peer=input(f'Outside inner IPv4 on {x["iface"]} [{suggested}]: ').strip() or suggested
            tp=input(f'Trial external port [{fp+10000 if fp+10000<=65535 else 40000}]: ').strip()
            p=make_plan(x['iface'],x['address'],peer,bp,fp,tp or (fp+10000 if fp+10000<=65535 else 40000),x['kind'])
            token=encode(p)
            print(json.dumps(p,indent=2))
            if address!=p['outside']: print('Selected trial route differs from the old backend. Old connections retain the old route.')
            if x['kind']=='wireguard': print('OUTSIDE preparation expands this single peer AllowedIPs to 0.0.0.0/0 with Table=off; only marked replies use it.')
            print('No changes applied. Copy this token:',token)
            print('First on outside: sudo python3 transparent_forward.py outside '+token)
            print('Then on Iran: sudo python3 transparent_forward.py iran '+token)
        elif choice in ('2','3'):
            p=decode(input('Plan token: ').strip())
            print(json.dumps(p,indent=2)); print('Outside must be prepared before starting the Iran trial.')
            if input('Type APPLY to prepare this side: ').strip()=='APPLY':
                with locked(): stage(p,'outside' if choice=='2' else 'iran')
        elif choice=='5': status()
        elif choice in ('4','6','7'):
            status(); identifier=input('Profile ID: ').strip()
            if choice=='4':
                if input('After successful live trial, type PROMOTE: ').strip()=='PROMOTE':
                    with locked(): promote(identifier)
            elif choice=='6':
                with locked(): drain(identifier)
            else:
                with locked(): cleanup(identifier)
        else: print('Invalid option.')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['menu','outside','iran','promote','drain','cleanup','status','restore','guard'],nargs='?',default='menu')
    parser.add_argument('value',nargs='?')
    args=parser.parse_args()
    if args.action=='guard':
        active=records()
        if active and (args.value in (None,'all','haproxy') or any(r['plan']['iface']==args.value for r in active)):
            print('Transparent profiles protect this configuration. Drain/cleanup the matching profile before changing it.',file=sys.stderr)
            return 1
        return 0
    if args.action=='status': status(); return 0
    if args.action=='menu': menu(); return 0
    with locked():
        if args.action in ('iran','outside'): stage(plan_argument(args.value or ''),args.action)
        elif args.action=='promote': promote(args.value or '')
        elif args.action=='drain': drain(args.value or '')
        elif args.action=='cleanup': cleanup(args.value or '')
        elif args.action=='restore': restore(args.value)
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except (Error,ValueError,KeyError,OSError,subprocess.SubprocessError,EOFError) as e:
        print('ERROR:',e,file=sys.stderr); sys.exit(1)
    except KeyboardInterrupt:
        print('\nCancelled. Inspect status before retrying an interrupted apply.',file=sys.stderr); sys.exit(130)
