import unittest
from unittest.mock import patch
import test_transparent as base
tp=base.tp

class SourceValidation(unittest.TestCase):
    setUp=base.LifecycleTests.setUp
    tearDown=base.LifecycleTests.tearDown
    jrun=base.LifecycleTests.jrun
    plan=base.LifecycleTests.plan
    def test_local_accept_enabled_before_probe_and_restored_after_cleanup(self):
        p=self.plan();self.rp(p['iface']+'.accept').write_text('0')
        def probe(plan):self.assertEqual(tp.accept_local_path(plan['iface']).read_text(),'1')
        with patch.object(tp,'probe_transparent',side_effect=probe):tp.stage(p,'iran',direct=True)
        self.assertEqual(tp.load(p['id'])['original_accept_local'],'0')
        tp.drain(p['id']);tp.cleanup(p['id'])
        self.assertEqual(tp.accept_local_path(p['iface']).read_text(),'0')
    def test_failed_probe_restores_original_accept_local(self):
        p=self.plan();self.rp(p['iface']+'.accept').write_text('0')
        with patch.object(tp,'probe_transparent',side_effect=tp.Error('fail')),self.assertRaises(tp.Error):tp.stage(p,'iran',direct=True)
        self.assertEqual(tp.accept_local_path(p['iface']).read_text(),'0')
        self.assertFalse(tp.records())
    def test_legacy_profile_snapshots_before_changing_value(self):
        p=self.plan();tp.stage(p,'iran');r=tp.load(p['id']);r.pop('original_accept_local');tp.save(r)
        tp.accept_local_path(p['iface']).write_text('0')
        tp.apply_network(r)
        self.assertEqual(tp.load(p['id'])['original_accept_local'],'0')
        self.assertEqual(tp.accept_local_path(p['iface']).read_text(),'1')
    def test_outside_does_not_change_accept_local(self):
        p=self.plan();self.rp(p['iface']+'.accept').write_text('0');tp.stage(p,'outside')
        self.assertEqual(tp.accept_local_path(p['iface']).read_text(),'0')
