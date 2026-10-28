import contextlib
import io
import json
import socket
import subprocess
import threading
import unittest
from unittest.mock import patch
import test_transparent as base
tp=base.tp
CONFIG=base.CONFIG
WG=base.WG


def link(name='any-gre',address='10.30.1.1',prefix=30,kind='gre',up=True,peer=None):
    return dict(iface=name,address=address,prefix=prefix,kind=kind,up=up,peer=peer)

class Discovery(unittest.TestCase):
    def test_gre_plus_and_wg_are_detected_by_kernel_type(self):
        data=[dict(ifname='custom_alpha',linkinfo=dict(info_kind='gre'),flags=['UP']),
              dict(ifname='unusual_wg',linkinfo=dict(info_kind='wireguard'),flags=['UP']),
              dict(ifname='eth0',linkinfo=dict(info_kind='veth'),flags=['UP'])]
        addresses=[dict(ifname=x['ifname'],addr_info=[dict(family='inet',local=f'10.1.{n}.1',prefixlen=30)]) for n,x in enumerate(data,1)]
        with patch.object(tp,'jrun',side_effect=[addresses,data]): found=tp.interfaces()
        self.assertEqual([x['iface'] for x in found],['custom_alpha','unusual_wg'])
    def test_peer_discovery_30_31_and_explicit_peer(self):
        with patch.object(tp,'records',return_value=[]):
            self.assertEqual(tp.inner_peer(link()),'10.30.1.2')
            self.assertEqual(tp.inner_peer(link(address='10.8.1.0',prefix=31)),'10.8.1.1')
            self.assertEqual(tp.inner_peer(link(prefix=32,peer='10.8.2.7/32')),'10.8.2.7')
    def test_unique_wg_peer_for_host_address(self):
        with patch.object(tp,'records',return_value=[]),patch.object(tp,'run',return_value=subprocess.CompletedProcess([],0,'KEY\t10.20.9.1/32\n','')):
            self.assertEqual(tp.inner_peer(link('customwg','10.20.9.2',32,'wireguard')),'10.20.9.1')
    def test_ambiguous_peer_is_skipped_instead_of_invented(self):
        with patch.object(tp,'records',return_value=[]),patch.object(tp,'jrun',return_value=[]),self.assertRaises(tp.Error):
            tp.inner_peer(link(prefix=24))
    def test_ready_record_reuses_peer_after_wg_broadening(self):
        p=tp.make_plan('customwg','10.20.9.1','10.20.9.2',2044,2044,12044,'wireguard')
        with patch.object(tp,'records',return_value=[dict(role='outside',plan=p)]):
            self.assertEqual(tp.inner_peer(link('customwg','10.20.9.2',32,'wireguard')),'10.20.9.1')
    def test_socket_parser_and_port_list(self):
        sample='LISTEN 0 4096 0.0.0.0:2044 0.0.0.0:* users:(("xray-linux",pid=1,fd=2))\nLISTEN 0 128 127.0.0.1:9999 0.0.0.0:*\n'
        with patch.object(tp,'run',return_value=subprocess.CompletedProcess([],0,sample,'')): listeners=tp.socket_listeners()
        self.assertEqual(listeners[0]['port'],2044);self.assertIn('xray',listeners[0]['process'])
        for raw in ['2044 1030','2044,1030,','2044,2044,1030']:
            self.assertEqual(tp.parse_ports(raw,[1030,2044]),[2044,1030])
        self.assertEqual(tp.parse_ports('0',[2044,1030]),[1030,2044])
        for raw in ['1','2044 0','bad','','99999']:
            with self.subTest(raw=raw),self.assertRaises(tp.Error):tp.parse_ports(raw,[2044,1030])
    def test_dual_stack_xray_listeners_are_discovered_but_pure_ipv6_is_not(self):
        text='LISTEN 0 4096 [::]:2044 [::]:* users:(("xray",pid=1,fd=3))\nLISTEN 0 128 [2001:db8::1]:443 [::]:*\n'
        with patch.object(tp,'run',return_value=subprocess.CompletedProcess([],0,text,'')):
            found=tp.socket_listeners()
        self.assertEqual([(x['address'],x['port']) for x in found],[('*',2044)])

    def test_trial_ports_avoid_busy_ports_and_duplicates(self):
        used={12044,12045}
        self.assertEqual(tp.free_trial_port(2044,used),12046)
        self.assertEqual(tp.free_trial_port(2044,used),12047)
    def test_32_wireguard_postup_retains_peer_route_without_default_route(self):
        original=WG.replace('10.20.1.2/30','10.20.1.2/32')
        for text in [original,original.replace('[Interface]','[Interface]\nTable=auto')]:
            result=tp.patch_wg(text)
            self.assertIn('PostUp = ip -4 route replace 10.20.1.1/32 dev %i',result)
            self.assertNotIn('route replace default',result)
            self.assertEqual(tp.patch_wg(result),result)

class AutoPlanning(unittest.TestCase):
    def setUp(self):
        base.LifecycleTests.setUp(self)
        probe=patch.object(tp,'backend_accepts_ipv4',return_value=True)
        probe.start(); self.patches.append(probe)
    tearDown=base.LifecycleTests.tearDown
    jrun=base.LifecycleTests.jrun
    def test_iran_interface_is_resolved_from_actual_backend_route(self):
        links=[link('wg_CUSTOM','10.20.1.1',30,'wireguard'),link('greUnused')]
        with patch.object(tp,'interfaces',return_value=links),patch.object(tp,'socket_listeners',return_value=[]),patch.object(tp,'jrun',return_value=[dict(dev='wg_CUSTOM',prefsrc='10.20.1.1')]):
            plans,skipped=tp.iran_plans([2044])
        self.assertFalse(skipped);self.assertEqual(plans[0]['iface'],'wg_CUSTOM');self.assertEqual(plans[0]['outside'],'10.20.1.2')
    def test_iran_bad_or_http_routes_are_not_activated(self):
        with patch.object(tp,'interfaces',return_value=[link()]),patch.object(tp,'socket_listeners',return_value=[]),patch.object(tp,'jrun',return_value=[dict(dev='eth0')]):
            plans,skipped=tp.iran_plans([2044,2095])
        self.assertFalse(plans);self.assertEqual(len(skipped),2)
    def test_outside_discovers_all_up_transport_types_without_fixed_names(self):
        links=[link('greNormal','10.10.4.2'),link('plus_CUSTOM','10.30.3.2'),link('wg_OTHER','10.20.7.2',kind='wireguard'),link('downOne','10.30.8.2',up=False)]
        with patch.object(tp,'interfaces',return_value=links),patch.object(tp,'socket_listeners',return_value=[dict(address='0.0.0.0',port=2044,process='xray')]):
            plans,skipped=tp.outside_plans([2044])
        self.assertEqual({p['iface'] for p in plans},{'greNormal','plus_CUSTOM','wg_OTHER'})
        self.assertEqual([p['iran'] for p in plans],['10.10.4.1','10.30.3.1','10.20.7.1']);self.assertEqual(len(skipped),1)
    def test_outside_is_not_tied_to_the_public_iran_port_or_interface_name(self):
        outside=tp.make_plan('outsideName','10.30.1.1','10.30.1.2',2044,2044,12044,'gre')
        iran=tp.make_plan('iranName','10.30.1.1','10.30.1.2',2044,443,10443,'gre')
        self.assertNotEqual(outside['id'],iran['id'])
        tp.stage(outside,'outside',automatic=True)
        with patch.object(tp,'jrun',return_value=[dict(dev='outsideName')]):
            response=tp.readiness_response('10.30.1.2','10.30.1.1',dict(version=1,backend_port=2044))
        self.assertTrue(response['ready'])
    def test_outside_not_ready_prevents_any_iran_config_change(self):
        p=tp.make_plan('greCustom','10.30.1.1','10.30.1.2',2044,2044,12044,'gre')
        before=self.cfg.read_text()
        with patch.object(tp,'outside_is_ready',return_value=False): successful,failed=tp.auto_apply([p],'iran')
        self.assertFalse(successful);self.assertEqual(len(failed),1);self.assertEqual(self.cfg.read_text(),before);self.assertFalse(tp.records())
    def test_repeat_auto_run_keeps_one_profile_and_does_not_restart_haproxy(self):
        p=tp.make_plan('greCustom','10.30.1.1','10.30.1.2',2044,2044,12044,'gre')
        with patch.object(tp,'outside_is_ready',return_value=True):
            tp.auto_apply([p],'iran');first=self.cfg.read_text();tp.auto_apply([p],'iran')
        self.assertEqual(len(tp.records()),1);self.assertEqual(self.cfg.read_text(),first)
        self.assertEqual(sum(c[:3]==('systemctl','reload','haproxy') for c in self.k.calls),1)
    def test_partial_failure_does_not_remove_other_ready_tunnels(self):
        a=tp.make_plan('greA','10.30.1.1','10.30.1.2',2044,2044,12044,'gre')
        b=tp.make_plan('greB','10.30.3.1','10.30.3.2',2044,2044,12044,'gre')
        real_stage=tp.stage
        def staged(p,role,automatic=False):
            if p['iface']=='greB':raise tp.Error('unsupported')
            return real_stage(p,role,automatic=automatic)
        with patch.object(tp,'stage',side_effect=staged),patch.object(tp,'ensure_readiness_service') as ready:
            successful,failed=tp.auto_apply([a,b],'outside')
        self.assertEqual(len(successful),1);self.assertEqual(len(failed),1);ready.assert_called_once()
        self.assertEqual(tp.records()[0]['plan']['iface'],'greA')
    def test_readiness_wrong_peer_address_port_and_missing_rules_rejected(self):
        p=tp.make_plan('greA','10.30.1.1','10.30.1.2',2044,2044,12044,'gre');tp.stage(p,'outside')
        self.assertFalse(tp.readiness_response('10.30.1.2','9.9.9.9',dict(version=1,backend_port=2044))['ready'])
        self.assertFalse(tp.readiness_response('10.30.1.2','10.30.1.1',dict(version=1,backend_port=9999))['ready'])
        self.k.iptables.clear()
        self.assertFalse(tp.readiness_response('10.30.1.2','10.30.1.1',dict(version=1,backend_port=2044))['ready'])
    def test_readiness_route_must_return_to_selected_interface(self):
        p=tp.make_plan('greA','10.30.1.1','10.30.1.2',2044,2044,12044,'gre');tp.stage(p,'outside')
        with patch.object(tp,'jrun',return_value=[dict(dev='eth0')]):
            self.assertFalse(tp.readiness_response('10.30.1.2','10.30.1.1',dict(version=1,backend_port=2044))['ready'])
    def test_outside_repeat_uses_existing_profile_despite_frontend_difference(self):
        p=tp.make_plan('greA','10.30.1.1','10.30.1.2',2044,443,10443,'gre');tp.stage(p,'outside')
        with patch.object(tp,'interfaces',return_value=[link('greA','10.30.1.2')]),patch.object(tp,'socket_listeners',return_value=[dict(address='*',port=2044,process='xray')]):
            plans,_=tp.outside_plans([2044])
        self.assertEqual(plans,[p])
    def test_outside_wizard_needs_no_interface_ip_or_token_input(self):
        links=[link('custom-name','10.30.1.2')]
        detected=[dict(address='*',port=2044,process='users:(("xray",pid=1))')]
        p=tp.make_plan('custom-name','10.30.1.1','10.30.1.2',2044,2044,12044,'gre')
        with patch.object(tp,'interfaces',return_value=links),patch.object(tp,'socket_listeners',return_value=detected),patch.object(tp,'auto_apply',return_value=([p],[])) as apply,patch('builtins.input',side_effect=['1','2','','','00']) as inputs:
            tp.auto_menu()
        apply.assert_called_once()
        self.assertEqual(apply.call_args[0][1],'outside')
        prompts=' '.join(str(c.args[0]) for c in inputs.call_args_list)
        self.assertNotIn('token',prompts.lower());self.assertNotIn('IPv4',prompts);self.assertNotIn('interface row',prompts.lower())
    def test_iran_wizard_detects_its_interface_from_forward_without_token(self):
        links=[link('custom-wire','10.20.1.1',kind='wireguard')]
        with patch.object(tp,'interfaces',return_value=links),patch.object(tp,'socket_listeners',return_value=[]),patch.object(tp,'jrun',return_value=[dict(dev='custom-wire')]),patch.object(tp,'auto_apply',return_value=([],[])) as apply,patch('builtins.input',side_effect=['1','1','','','00']):
            tp.auto_menu()
        plan=apply.call_args[0][0][0]
        self.assertEqual(plan['iface'],'custom-wire');self.assertEqual(plan['outside'],'10.20.1.2')
    def test_live_ipv4_backend_probe_is_required_for_ready(self):
        p=tp.make_plan('greA','10.30.1.1','10.30.1.2',2044,2044,12044,'gre');tp.stage(p,'outside')
        with patch.object(tp,'jrun',return_value=[dict(dev='greA')]),patch.object(tp,'backend_accepts_ipv4',return_value=False):
            self.assertFalse(tp.readiness_response('10.30.1.2','10.30.1.1',dict(version=1,backend_port=2044))['ready'])

    def test_readiness_unit_runs_only_read_only_responder(self):
        with patch.object(tp,'socket_listeners',return_value=[dict(port=45123)]): tp.ensure_readiness_service()
        text=(tp.SYSTEMD/tp.READY_UNIT).read_text()
        self.assertIn('serve-ready',text);self.assertNotIn(' outside ',text.split('ExecStart=')[1].split('\n')[0]);self.assertNotIn('promote',text)
        self.assertIn(('systemctl','restart',tp.READY_UNIT),self.k.calls)
        self.assertNotIn(('systemctl','restart','haproxy'),self.k.calls)

class ReadinessProtocol(unittest.TestCase):
    def test_real_loopback_exchange_and_wrong_peer_rejection(self):
        try: server=tp.ReadyServer(('127.0.0.1',0),tp.ReadyHandler)
        except PermissionError: self.skipTest('Loopback sockets denied by this environment')
        address=server.server_address;thread=threading.Thread(target=server.serve_forever,daemon=True)
        record=dict(role='outside',phase='ready',plan=dict(outside='127.0.0.1',iran='127.0.0.1'))
        try:
            with patch.object(tp,'records',return_value=[record]),patch.object(tp,'readiness_response',return_value=dict(ready=True,version=1)) as response:
                thread.start()
                with socket.create_connection(address,timeout=2) as client:
                    client.sendall(b'{"version":1,"backend_port":2044}\n')
                    with client.makefile('rb') as stream: answer=json.loads(stream.readline())
                self.assertTrue(answer['ready']);response.assert_called_once()
            bad=dict(role='outside',phase='ready',plan=dict(outside='127.0.0.1',iran='10.30.9.1'))
            with patch.object(tp,'records',return_value=[bad]),patch.object(tp,'readiness_response') as response:
                with socket.create_connection(address,timeout=2) as client:
                    client.sendall(b'{"version":1,"backend_port":2044}\n')
                    try: data=client.recv(1024)
                    except ConnectionResetError: data=b''
                self.assertFalse(data);response.assert_not_called()
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main(verbosity=2)
