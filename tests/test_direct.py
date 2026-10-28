import contextlib
import io
import socket
import unittest
from unittest.mock import patch,MagicMock
import test_transparent as base

tp=base.tp

class DirectLifecycle(unittest.TestCase):
    setUp=base.LifecycleTests.setUp
    tearDown=base.LifecycleTests.tearDown
    jrun=base.LifecycleTests.jrun
    plan=base.LifecycleTests.plan
    def test_direct_on_uses_original_port_without_trial_listener(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent') as probe:
            tp.stage(p,'iran',direct=True)
        self.assertEqual(tp.load(p['id'])['phase'],'active')
        self.assertTrue(tp.load(p['id'])['direct'])
        text=self.cfg.read_text()
        self.assertIn('bind *:2044',text)
        self.assertNotIn('12044',text)
        self.assertNotIn('_test',text)
        self.assertIn('usesrc clientip interface greplus1',text)
        self.assertFalse(any('12044' in rule for rule in self.k.iptables))
        probe.assert_called_once_with(p)
    def test_probe_runs_before_production_changes(self):
        p=self.plan()
        def probe(plan):self.assertEqual(self.cfg.read_text(),base.CONFIG)
        with patch.object(tp,'probe_transparent',side_effect=probe):tp.stage(p,'iran',direct=True)
    def test_failed_nonlocal_probe_leaves_production_and_no_new_resources(self):
        with patch.object(tp,'probe_transparent',side_effect=tp.Error('return path failed')):
            with self.assertRaises(tp.Error):tp.stage(self.plan(),'iran',direct=True)
        self.assertEqual(self.cfg.read_text(),base.CONFIG)
        self.assertFalse(tp.records());self.assertFalse(self.k.iptables);self.assertFalse(self.k.routes)
        self.assertFalse(any(c[:3]==('systemctl','reload','haproxy') for c in self.k.calls))
    def test_direct_off_restores_original_port_and_keeps_live_routes(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent'):tp.stage(p,'iran',direct=True)
        self.k.connections=5;tp.drain(p['id'])
        self.assertEqual(self.cfg.read_text().strip(),base.CONFIG.strip())
        with self.assertRaises(tp.Error):tp.cleanup(p['id'])
        self.assertTrue(self.k.routes)
        self.k.connections=0;tp.cleanup(p['id'])
        self.assertFalse(self.k.routes);self.assertFalse(self.k.iptables)
    def test_failed_reload_rolls_back_direct_activation(self):
        self.k.reload_fails=1
        with patch.object(tp,'probe_transparent'),self.assertRaises(tp.Error):tp.stage(self.plan(),'iran',direct=True)
        self.assertEqual(self.cfg.read_text(),base.CONFIG)
        self.assertFalse(tp.records());self.assertFalse(self.k.routes)
    def test_repeat_on_does_not_reload_or_duplicate_backend(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent'),patch.object(tp,'outside_is_ready',return_value=True):
            tp.auto_apply([p],'iran',direct=True);tp.auto_apply([p],'iran',direct=True)
        self.assertEqual(sum(c[:3]==('systemctl','reload','haproxy') for c in self.k.calls),1)
        self.assertEqual(len(tp.records()),1)
    def test_legacy_trial_migrates_to_direct_without_extra_listener(self):
        p=self.plan();tp.stage(p,'iran')
        with patch.object(tp,'probe_transparent'):tp.enable_existing(tp.load(p['id']),True)
        self.assertNotIn('12044',self.cfg.read_text());self.assertNotIn('_test',self.cfg.read_text())
        self.assertFalse(any('12044' in rule for rule in self.k.iptables))
        self.assertEqual(tp.load(p['id'])['phase'],'active')
    def test_legacy_active_migrates_and_off_restores_original(self):
        p=self.plan();tp.stage(p,'iran');tp.promote(p['id'])
        with patch.object(tp,'probe_transparent'):tp.enable_existing(tp.load(p['id']),True)
        tp.drain(p['id']);self.assertEqual(self.cfg.read_text().strip(),base.CONFIG.strip())
    def test_on_after_off_with_sessions_still_draining(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent'):
            tp.stage(p,'iran',direct=True);self.k.connections=2;tp.drain(p['id'])
            tp.enable_existing(tp.load(p['id']),True)
        self.assertEqual(tp.load(p['id'])['phase'],'active')
        self.assertEqual(len(tp.records()),1)
        self.assertIn('default_backend gtp_',self.cfg.read_text())
    def test_failed_reenable_preserves_draining_routes_and_phase(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent'):tp.stage(p,'iran',direct=True)
        self.k.connections=2;tp.drain(p['id']);rules=set(self.k.iptables)
        with patch.object(tp,'probe_transparent',side_effect=tp.Error('fail')),self.assertRaises(tp.Error):tp.enable_existing(tp.load(p['id']),True)
        self.assertEqual(tp.load(p['id'])['phase'],'draining')
        self.assertEqual(self.k.iptables,rules)
        self.assertEqual(self.cfg.read_text().strip(),base.CONFIG.strip())
    def test_direct_does_not_care_if_legacy_test_port_is_in_use(self):
        p=self.plan();before=base.CONFIG+'\nfrontend other\n    bind *:12044\n    mode tcp\n'
        self.cfg.write_text(before)
        with patch.object(tp,'probe_transparent'):tp.stage(p,'iran',direct=True)
        self.assertEqual(self.cfg.read_text().count('bind *:12044'),1)

class Probe(unittest.TestCase):
    def test_probe_uses_nonlocal_address_and_selected_interface(self):
        p=tp.make_plan('greplus3','10.30.3.1','10.30.3.2',2044,2044,12044,'gre')
        fake=MagicMock();sock=fake.__enter__.return_value
        with patch.object(tp,'interfaces',return_value=[]),patch.object(tp.socket,'socket',return_value=fake):tp.probe_transparent(p)
        sock.bind.assert_called_once_with(('198.18.255.254',0))
        sock.connect.assert_called_once_with(('10.30.3.2',2044))
        self.assertIn(((socket.SOL_IP,19,1),),[(x.args,) for x in sock.setsockopt.call_args_list])
    def test_probe_failure_has_actionable_error(self):
        p=tp.make_plan('greplus3','10.30.3.1','10.30.3.2',2044,2044,12044,'gre')
        fake=MagicMock();fake.__enter__.return_value.connect.side_effect=TimeoutError('timed out')
        with patch.object(tp,'interfaces',return_value=[]),patch.object(tp.socket,'socket',return_value=fake),self.assertRaisesRegex(tp.Error,'Production forward was not switched'):tp.probe_transparent(p)
    def test_simple_menu_only_two_actions(self):
        output=io.StringIO()
        with patch.object(tp,'display_port_status'),patch('builtins.input',return_value='00'),contextlib.redirect_stdout(output):tp.auto_menu()
        self.assertIn('1) ON',output.getvalue());self.assertIn('2) OFF',output.getvalue())
        self.assertNotIn('Activate',output.getvalue());self.assertNotIn('Advanced',output.getvalue())
