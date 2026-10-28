#!/usr/bin/env python3
import base64
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('tp',ROOT/'transparent_forward.py')
tp=importlib.util.module_from_spec(spec); spec.loader.exec_module(tp)
CONFIG='''global
    daemon
    maxconn 500000

defaults
    mode http
    timeout connect 10s
    timeout client 2h
    timeout server 2h
frontend ws_2044_in
    bind *:2044
    mode tcp
    default_backend ws_2044_out
backend ws_2044_out
    mode tcp
    server foreign_2044 10.20.1.2:2044
frontend ws_2095_in
    bind *:2095
    mode http
    default_backend ws_2095_out
backend ws_2095_out
    mode http
    server foreign_2095 10.20.1.2:2095
'''
WG='''[Interface]
PrivateKey = PRIVATE-DO-NOT-CHANGE
Address = 10.20.1.2/30
ListenPort = 51801
[Peer]
PublicKey = PUBLIC-UNCHANGED
Endpoint = 10.30.1.1:51801
AllowedIPs = 10.20.1.1/32
PersistentKeepalive = 25
'''

class Kernel:
    def __init__(self):
        self.calls=[]; self.iptables=set(); self.routes={}; self.policy=[]; self.connections=0
        self.failure=None; self.reload_fails=0; self.wg_allowed='10.20.1.1/32'
    def __call__(self,*args,check=True,timeout=20):
        args=tuple(str(a) for a in args); self.calls.append(args); output=''; error=''; rc=0
        if self.failure and self.failure(args): raise tp.Error('injected failure')
        if args[0]=='iptables':
            idx=next(i for i,a in enumerate(args) if a in ('-C','-I','-D'))
            op=args[idx]; chain=args[idx+1]; remainder=list(args[idx+2:])
            if op=='-I': remainder.pop(0)
            key=(args[args.index('-t')+1],chain,*remainder)
            if op=='-C': rc=0 if key in self.iptables else 1
            elif op=='-I': self.iptables.add(key)
            else: self.iptables.discard(key)
        elif args[0]=='ip' and 'rule' in args:
            if 'add' in args:
                value,mask=args[args.index('fwmark')+1].split('/')
                self.policy.append(dict(priority=int(args[args.index('priority')+1]),fwmark=int(value,0),fwmask=int(mask,0),table=int(args[-1])))
            elif 'del' in args:
                priority=int(args[args.index('priority')+1]); self.policy=[x for x in self.policy if x['priority']!=priority]
        elif args[0]=='ip' and 'route' in args and 'table' in args:
            table=args[-1]
            if 'replace' in args: self.routes[table]=args
            elif 'show' in args: output='route' if table in self.routes else ''
            elif 'del' in args: self.routes.pop(table,None)
        elif args[0]=='ss': output='LISTEN 0 128 0.0.0.0:2044 0.0.0.0:*\n'
        elif args[:3]==('systemctl','reload','haproxy'):
            if self.reload_fails: self.reload_fails-=1; rc=1; error='reload failed'
        elif args[0]=='conntrack':
            output='\n'.join(['tcp ESTABLISHED mark=...']*self.connections)
            error=f'{self.connections} flow entries have been shown.'
        elif args[0]=='wg':
            if args[1]=='show':
                if args[-1]=='peers': output='PUBLIC-UNCHANGED\n'
                else: output='PUBLIC-UNCHANGED\t'+self.wg_allowed+'\n'
            else: self.wg_allowed=args[-1]
        if rc and check: raise tp.Error(error or 'command failed')
        return subprocess.CompletedProcess(args,rc,output,error)

class PureTests(unittest.TestCase):
    def p(self,iface='greplus1',iran='10.30.1.1',outside='10.30.1.2',kind='gre'):
        return tp.make_plan(iface,iran,outside,2044,2044,12044,kind)
    def test_plan_round_trip_for_both_iran_paths(self):
        for p in [self.p(),self.p('greplus3','10.30.3.1','10.30.3.2'),self.p('wgtun1','10.20.1.1','10.20.1.2','wireguard')]:
            self.assertEqual(tp.decode(tp.encode(p)),p)
    def test_rejects_modified_token(self):
        p=self.p(); p['backend_port']=22
        with self.assertRaises(tp.Error): tp.validate_plan(p)
    def test_rejects_shell_injection_and_unsafe_interface(self):
        for iface in ['x;rm -rf /','$(id)','eth0','lo','-i','bad/name']:
            with self.subTest(iface=iface),self.assertRaises(tp.Error): self.p(iface=iface)
    def test_invalid_addresses_ports_and_transport(self):
        for field,value in [('outside','::1'),('iran','127.0.0.1'),('outside','10.30.1.1'),('kind','vxlan'),('test_port',2044),('backend_port',0),('frontend_port',65536)]:
            p=self.p(); p[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(tp.Error): tp.validate_plan(p)
    def test_trial_preserves_every_old_section(self):
        new=tp.add_trial(CONFIG,self.p())
        self.assertTrue(new.startswith(CONFIG.rstrip()))
        self.assertIn('source 0.0.0.0 usesrc clientip',new)
        self.assertNotIn('send-proxy',new)
        self.assertIn('bind 0.0.0.0:12044',new)
        self.assertEqual(tp.block(new,'backend','ws_2044_out'),tp.block(CONFIG,'backend','ws_2044_out'))
    def test_promotion_changes_only_selected_frontend(self):
        p=self.p(); trial=tp.add_trial(CONFIG,p); active=tp.promote_text(trial,p)
        self.assertEqual(tp.block(active,'frontend','ws_2095_in'),tp.block(CONFIG,'frontend','ws_2095_in'))
        self.assertIn('default_backend gtp_'+p['id']+'_out',tp.block(active,'frontend','ws_2044_in'))
        self.assertEqual(tp.remove_trial(tp.promote_text(active,p,disable=True),p).strip(),CONFIG.strip())
    def test_http_or_custom_listener_is_rejected(self):
        for config,fp in [(CONFIG,2095),(CONFIG.replace('bind *:2044','bind :::2044 v4v6'),2044),
                         (CONFIG.replace('10.20.1.2:2044','10.20.1.2:2044 send-proxy-v2'),2044)]:
            with self.subTest(config=config),self.assertRaises(tp.Error): tp.forward(config,fp)
    def test_changed_production_backend_is_not_overwritten(self):
        trial=tp.add_trial(CONFIG,self.p()).replace('default_backend ws_2044_out','default_backend custom')
        with self.assertRaises(tp.Error): tp.promote_text(trial,self.p())
    def test_wireguard_patch_keeps_keys_endpoint_address_and_port(self):
        new=tp.patch_wg(WG)
        for line in ['PrivateKey = PRIVATE-DO-NOT-CHANGE','PublicKey = PUBLIC-UNCHANGED','ListenPort = 51801','Endpoint = 10.30.1.1:51801','Address = 10.20.1.2/30']:
            self.assertIn(line,new)
        self.assertIn('Table = off',new); self.assertIn('AllowedIPs = 0.0.0.0/0',new)
        self.assertEqual(tp.patch_wg(new),new)
    def test_multiple_wireguard_peers_are_rejected(self):
        with self.assertRaises(tp.Error): tp.patch_wg(WG+'\n[Peer]\nPublicKey = other\nAllowedIPs = 10.1.1.1/32\n')
    def test_marks_differ_per_iran_and_preserve_other_bits(self):
        marks=[]
        for slot,p in [(1,self.p()),(2,self.p('greplus3','10.30.3.1','10.30.3.2'))]:
            r=dict(slot=slot,role='outside',phase='ready',plan=p)
            rules=tp.rules_for(r); setting=rules[0][rules[0].index('--set-xmark')+1]; marks.append(setting)
            self.assertIn('NEW',rules[0]); self.assertIn('--ctdir',rules[0]); self.assertIn(p['iface'],rules[0])
            self.assertIn(p['outside'],rules[1]); self.assertIn('--sport',rules[1]); self.assertIn('2044',rules[1])
            self.assertIn('--nfmask',rules[1]); self.assertEqual(setting.split('/')[1],'0xffff0000')
        self.assertNotEqual(*marks)
    def test_real_server_interface_validation(self):
        p=self.p()
        with patch.object(tp,'interfaces',return_value=[dict(iface='greplus1',kind='gre',address='10.30.1.1',prefix=30,up=True)]),patch.object(tp,'jrun',return_value=[dict(dev='greplus1')]):
            self.assertTrue(tp.check_interface(p,'iran'))
            with self.assertRaises(tp.Error):tp.check_interface(p,'outside')
        with patch.object(tp,'interfaces',return_value=[dict(iface='greplus1',kind='gre',address='10.30.1.1',prefix=30,up=True)]),patch.object(tp,'jrun',return_value=[dict(dev='eth0')]):
            with self.assertRaises(tp.Error):tp.check_interface(p,'iran')
    def test_off_subnet_peer_is_rejected(self):
        p=self.p(outside='10.30.9.2')
        with patch.object(tp,'interfaces',return_value=[dict(iface='greplus1',kind='gre',address='10.30.1.1',prefix=30,up=True)]):
            with self.assertRaises(tp.Error):tp.check_interface(p,'iran')

    def test_iran_divert_matches_only_transparent_reply_sockets(self):
        rules=tp.rules_for(dict(plan=self.p(),role='iran',phase='trial',slot=1))
        self.assertIn('--transparent',rules[0]); self.assertIn('10.30.1.2',rules[0]); self.assertIn('--sport',rules[0])
        self.assertTrue(any(r[0]=='nat' and '-o' in r and '-d' in r for r in rules))
    def test_draining_keeps_return_rules_but_removes_trial_and_new_marks(self):
        r=dict(plan=self.p(),role='iran',phase='draining',slot=1)
        rules=tp.rules_for(r)
        self.assertTrue(any('--transparent' in r for r in rules))
        self.assertFalse(any(r[-1].endswith(':track') or r[-1].endswith(':trial') for r in rules))

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.state=self.root/'state'; self.cfg=self.root/'haproxy.cfg'; self.cfg.write_text(CONFIG)
        self.k=Kernel(); self.rpf={}
        def rp(iface):
            p=self.root/(iface+'.rp')
            if not p.exists(): p.write_text('1')
            return p
        self.rp=rp
        self.patches=[patch.object(tp,'STATE',self.state),patch.object(tp,'CONFIG',self.cfg),
            patch.object(tp,'MODULE',self.root/'installed.py'),patch.object(tp,'UNIT',self.root/'transparent.service'),patch.object(tp,'SYSTEMD',self.root/'systemd'),
            patch.object(tp,'accept_local_path',lambda iface:rp(iface+'.accept')),patch.object(tp,'run',self.k),patch.object(tp,'rp_path',rp),patch.object(tp,'root_checks',lambda role:None),
            patch.object(tp,'check_interface',lambda p,role:dict(iface=p['iface'],up=True)),patch.object(tp,'jrun',self.jrun)]
        for item in self.patches: item.start()
        self.state.mkdir()
        self.quiet=contextlib.redirect_stdout(io.StringIO()); self.quiet.__enter__()
    def tearDown(self):
        self.quiet.__exit__(None,None,None)
        for item in reversed(self.patches): item.stop()
        self.temp.cleanup()
    def jrun(self,*args):
        if 'rule' in args: return self.k.policy
        raise AssertionError(args)
    def plan(self,which=1):
        return tp.make_plan('greplus'+str(which),f'10.30.{which}.1',f'10.30.{which}.2',2044,2044,12044,'gre')
    def test_outside_two_irans_get_distinct_return_tables(self):
        a,b=self.plan(1),self.plan(3)
        tp.stage(a,'outside'); tp.stage(b,'outside')
        self.assertEqual(len(self.k.policy),2)
        self.assertIn('10.30.1.1',self.k.routes['45001']); self.assertIn('10.30.3.1',self.k.routes['45002'])
        self.assertEqual(self.cfg.read_text(),CONFIG)
        self.assertFalse(any('main' in cmd or cmd[:3]==('systemctl','restart','haproxy') for cmd in self.k.calls))
    def test_iran_trial_then_promote_then_drain(self):
        p=self.plan(); tp.stage(p,'iran')
        self.assertEqual(tp.load(p['id'])['phase'],'trial')
        self.assertIn('local',self.k.routes['45001'])
        self.assertIn('default_backend ws_2044_out',tp.block(self.cfg.read_text(),'frontend','ws_2044_in'))
        tp.promote(p['id']); self.assertEqual(tp.load(p['id'])['phase'],'active')
        self.k.connections=2; tp.drain(p['id']); self.assertEqual(tp.load(p['id'])['phase'],'draining')
        self.assertEqual(self.cfg.read_text().strip(),CONFIG.strip())
        with self.assertRaises(tp.Error): tp.cleanup(p['id'])
        self.assertTrue(self.k.routes)
        self.k.connections=0; tp.cleanup(p['id'])
        self.assertFalse(self.k.routes); self.assertFalse(self.k.policy); self.assertFalse(self.k.iptables)
        self.assertEqual(self.rp('greplus1').read_text(),'1')
    def test_repeat_network_restore_is_idempotent(self):
        tp.stage(self.plan(),'outside'); before=set(self.k.iptables)
        tp.restore(); tp.restore()
        self.assertEqual(before,self.k.iptables); self.assertEqual(len(self.k.policy),1)
    def test_failed_reload_restores_config_and_owned_network_resources(self):
        self.k.reload_fails=1
        with self.assertRaises(tp.Error): tp.stage(self.plan(),'iran')
        self.assertEqual(self.cfg.read_text(),CONFIG)
        self.assertFalse(self.k.routes); self.assertFalse(self.k.policy); self.assertFalse(self.k.iptables)
        self.assertFalse(tp.records()); self.assertEqual(self.rp('greplus1').read_text(),'1')
    def test_firewall_failure_rolls_back_before_touching_live_config(self):
        def failure(cmd): return cmd[0]=='iptables' and '-I' in cmd
        self.k.failure=failure
        with self.assertRaises(tp.Error): tp.stage(self.plan(),'iran')
        self.assertEqual(self.cfg.read_text(),CONFIG); self.assertFalse(self.k.routes); self.assertFalse(tp.records())
    def test_cleanup_never_flushes_global_state(self):
        tp.stage(self.plan(),'outside'); tp.drain(self.plan()['id']); tp.cleanup(self.plan()['id'])
        self.assertFalse(any('flush' in a or '-F' in a or '-X' in a or a[0]=='conntrack' and '-D' in a for a in self.k.calls))
    def test_same_tunnel_backend_pair_cannot_steal_existing_profile(self):
        tp.stage(self.plan(),'outside')
        with self.assertRaises(tp.Error): tp.stage(self.plan(),'outside')
        self.assertEqual(len(tp.records()),1)
    def test_conflicting_main_route_slot_is_skipped(self):
        self.k.routes['45001']=('owned-by-another-service',)
        tp.stage(self.plan(),'outside')
        self.assertEqual(tp.records()[0]['slot'],2)
        self.assertEqual(self.k.routes['45001'],('owned-by-another-service',))
    def test_empty_table_referenced_by_other_policy_is_not_claimed(self):
        self.k.policy.append(dict(priority=10000,table=45001))
        tp.stage(self.plan(),'outside')
        self.assertEqual(tp.records()[0]['slot'],2)
    def test_one_incomplete_profile_does_not_block_restoring_others(self):
        p=self.plan();q=self.plan(3);tp.stage(p,'outside');tp.stage(q,'outside')
        r=tp.load(p['id']);r['phase']='preparing';tp.save(r)
        self.k.iptables.clear();self.k.routes.clear();self.k.policy.clear()
        with self.assertRaises(tp.Error):tp.restore()
        self.assertIn('45002',self.k.routes)
        self.assertTrue(any('greplus3' in rule for rule in self.k.iptables))

    def test_slot_policy_mask_collision_is_not_accepted(self):
        tp.stage(self.plan(),'outside'); r=tp.records()[0]
        self.k.policy[0]['fwmask']=0xffffffff
        with self.assertRaises(tp.Error): tp.apply_network(r)
    def test_changed_config_prevents_rollback_overwrite(self):
        with self.assertRaises(tp.Error): tp.reload_config('not-the-real-config',CONFIG+'\n# updated\n')
        self.assertEqual(self.cfg.read_text(),CONFIG)
    def test_failed_promotion_reload_does_not_mark_profile_active(self):
        p=self.plan(); tp.stage(p,'iran'); trial=self.cfg.read_text(); self.k.reload_fails=1
        with self.assertRaises(tp.Error): tp.promote(p['id'])
        self.assertEqual(self.cfg.read_text(),trial); self.assertEqual(tp.load(p['id'])['phase'],'trial')
    def test_failed_promotion_state_save_restores_live_config(self):
        p=self.plan();tp.stage(p,'iran');trial=self.cfg.read_text()
        with patch.object(tp,'save',side_effect=OSError('disk full')),self.assertRaises(OSError):tp.promote(p['id'])
        self.assertEqual(self.cfg.read_text(),trial);self.assertEqual(tp.load(p['id'])['phase'],'trial')

    def test_failed_drain_state_save_restores_live_config(self):
        p=self.plan();tp.stage(p,'iran');trial=self.cfg.read_text();rules=set(self.k.iptables)
        with patch.object(tp,'save',side_effect=OSError('disk full')),self.assertRaises(OSError):tp.drain(p['id'])
        self.assertEqual(self.cfg.read_text(),trial);self.assertEqual(tp.load(p['id'])['phase'],'trial')
        self.assertEqual(self.k.iptables,rules)
    def test_cleanup_removes_owned_rules_left_by_interrupted_drain(self):
        p=self.plan();tp.stage(p,'iran');r=tp.load(p['id']);r['phase']='draining';tp.save(r)
        # Emulate config rollback already done and interruption before rule deletion.
        self.cfg.write_text(CONFIG)
        tp.cleanup(p['id'])
        self.assertFalse(self.k.iptables)

    def test_cleanup_refuses_live_config_even_if_phase_was_corrupted(self):
        p=self.plan();tp.stage(p,'iran');r=tp.load(p['id']);r['phase']='draining';tp.save(r)
        with self.assertRaises(tp.Error):tp.cleanup(p['id'])
        self.assertTrue(self.k.routes)

    def test_foreign_drain_retains_capture_until_iran_has_drained(self):
        p=self.plan(); tp.stage(p,'outside'); before=set(self.k.iptables); self.k.connections=1
        tp.drain(p['id'])
        self.assertEqual(before,self.k.iptables)
        with self.assertRaises(tp.Error): tp.cleanup(p['id'])
    def test_drain_requires_explicit_phase_before_cleanup(self):
        p=self.plan(); tp.stage(p,'outside')
        with self.assertRaises(tp.Error): tp.cleanup(p['id'])
    def test_conntrack_permission_error_refuses_cleanup(self):
        p=self.plan();tp.stage(p,'outside');tp.drain(p['id'])
        old=self.k
        def denied(*args,**kwargs):
            if args[0]=='conntrack':return subprocess.CompletedProcess(args,1,'','permission denied')
            return old(*args,**kwargs)
        with patch.object(tp,'run',denied),self.assertRaises(tp.Error):tp.cleanup(p['id'])
        self.assertTrue(self.k.routes)
    def test_shared_interface_rpf_is_restored_only_after_last_profile(self):
        p=self.plan(); q=tp.make_plan('greplus1','10.30.1.1','10.30.1.2',1030,1030,11030,'gre')
        # Both backend listeners must exist for staging.
        old=self.k
        def listeners(*args,**kw):
            if args[0]=='ss':return subprocess.CompletedProcess(args,0,'LISTEN 0 128 *:2044 *:*\nLISTEN 0 128 *:1030 *:*\n','')
            return old(*args,**kw)
        with patch.object(tp,'run',listeners):tp.stage(p,'outside');tp.stage(q,'outside')
        tp.drain(p['id']);tp.cleanup(p['id']);self.assertEqual(self.rp('greplus1').read_text(),'2')
        tp.drain(q['id']);tp.cleanup(q['id']);self.assertEqual(self.rp('greplus1').read_text(),'1')

class WireGuardLifecycle(LifecycleTests):
    def setUp(self):
        super().setUp()
        self.wgfile=self.root/'wgtun1.conf';self.wgfile.write_text(WG)
        self.wg_patch=patch.object(tp,'wireguard_path',lambda iface:self.wgfile);self.wg_patch.start()
        self.which_patch=patch.object(tp.shutil,'which',lambda name:'/usr/bin/'+name);self.which_patch.start()
    def tearDown(self):
        self.which_patch.stop();self.wg_patch.stop();super().tearDown()
    def plan(self,which=1):
        return tp.make_plan('wgtun1','10.20.1.1','10.20.1.2',2044,2044,12044,'wireguard')
    # Do not inherit the GRE-only scenarios with assumptions about greplus IPs/slots.
    def test_wireguard_foreign_setup_and_cleanup_keep_keys(self):
        p=self.plan();tp.stage(p,'outside')
        self.assertIn('AllowedIPs = 0.0.0.0/0',self.wgfile.read_text())
        self.assertIn('Table = off',self.wgfile.read_text())
        self.assertEqual(self.k.wg_allowed,'0.0.0.0/0')
        self.assertIn('PRIVATE-DO-NOT-CHANGE',self.wgfile.read_text())
        dropin=tp.SYSTEMD/'wg-quick@wgtun1.service.d/70-gretun-transparent.conf'
        self.assertIn('restore wgtun1',dropin.read_text())
        tp.restore()
        tp.drain(p['id']);tp.cleanup(p['id'])
        self.assertEqual(self.wgfile.read_text(),WG);self.assertEqual(self.k.wg_allowed,'10.20.1.1/32')
        self.assertFalse(dropin.exists())
    def test_wireguard_failure_before_change_restores_cleanly(self):
        self.k.failure=lambda cmd:cmd[:4]==('ip','-4','route','replace')
        with self.assertRaises(tp.Error):tp.stage(self.plan(),'outside')
        self.assertEqual(self.wgfile.read_text(),WG);self.assertFalse(tp.records())
    def test_wireguard_failure_after_change_restores_allowed_ips(self):
        self.k.failure=lambda cmd:cmd[0]=='iptables' and '-I' in cmd
        with self.assertRaises(tp.Error):tp.stage(self.plan(),'outside')
        self.assertEqual(self.wgfile.read_text(),WG);self.assertEqual(self.k.wg_allowed,'10.20.1.1/32')
    def test_wireguard_manual_changes_are_not_overwritten_on_cleanup(self):
        p=self.plan();tp.stage(p,'outside');self.wgfile.write_text(self.wgfile.read_text()+'# manual edit\n')
        tp.drain(p['id'])
        with self.assertRaises(tp.Error):tp.cleanup(p['id'])
        self.assertTrue(tp.records());self.assertIn('# manual edit',self.wgfile.read_text())
    def test_custom_allowedips_and_multipeer_not_automatically_expanded(self):
        self.wgfile.write_text(WG.replace('10.20.1.1/32','10.20.1.1/32, 192.168.0.0/16'))
        with self.assertRaises(tp.Error):tp.stage(self.plan(),'outside')
        self.assertEqual(self.k.wg_allowed,'10.20.1.1/32');self.assertFalse(tp.records())

# Share only the harness, not all inherited GRE assumptions.
for _name in list(LifecycleTests.__dict__):
    if _name.startswith('test_') and _name not in WireGuardLifecycle.__dict__:
        setattr(WireGuardLifecycle,_name,None)

class IntegrationGuards(unittest.TestCase):
    def test_shell_syntax_and_default_install_does_not_activate_transparent(self):
        for path in (ROOT/'GRETUN.sh',ROOT/'install-local.sh'):
            subprocess.run(['bash','-n',str(path)],check=True)
        installer=(ROOT/'install-local.sh').read_text()
        self.assertNotIn('transparent_forward.py outside',installer)
        self.assertNotIn('systemctl restart',installer)
    def test_backpack_bundles_unchanged(self):
        subprocess.run(['sha256sum','-c','BUNDLE-SHA256SUMS'],cwd=ROOT/'engines/backpack',check=True,capture_output=True)
    def test_panel_and_proxy_protocol_settings_never_modified(self):
        text=(ROOT/'transparent_forward.py').read_text()
        self.assertNotIn('/etc/x-ui',text);self.assertNotIn('send-proxy-v2',text)
    def test_privilege_guard_refuses_no_network_caps(self):
        with patch.object(tp.os,'geteuid',return_value=0),patch.object(Path,'read_text',return_value='CapEff:\t0000000000000000\n'):
            with self.assertRaises(tp.Error):tp.root_checks('iran')

class ManagerGuardTests(unittest.TestCase):
    def test_existing_manager_cannot_overwrite_active_transparent_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); profiles=root/'profiles';profiles.mkdir();(profiles/'profile-test.json').write_text('{}')
            functions=root/'functions.sh'
            functions.write_text((ROOT/'GRETUN.sh').read_text().split('### Script entry')[0].replace('/etc/gretun-transparent',str(profiles)))
            (root/'transparent_forward.py').write_text('# test module')
            shell=r'''source "$1"
python3() { return 1; }
for action in 'haproxy_write_entries_file ignored' 'wg_write_config 1' 'reset_all_tunnels' 'greplus_remove_one_tunnel 3'; do
 result=0; $action || result=$?
 [ "$result" -eq 1 ] || exit 1
done
'''
            result=subprocess.run(['bash','-c',shell,'test',str(functions)],capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
