import unittest
import test_transparent as base
tp=base.tp

class PortStatus(unittest.TestCase):
    def profile(self,phase='active',role='iran'):
        return dict(role=role,phase=phase,plan=tp.make_plan('greplus3','10.30.3.1','10.30.3.2',2044,2044,12044,'gre'))
    def test_active_and_normal_forwards_are_distinct(self):
        r=self.profile();text=tp.direct_config(base.CONFIG,r['plan'])
        rows=tp.port_status_rows([r],text,[],[])
        self.assertIn(('iran',2044,'greplus3','ON'),rows)
        self.assertIn(('iran',2095,'-','OFF / normal forward'),rows)
    def test_config_drift_not_reported_on(self):
        rows=tp.port_status_rows([self.profile()],base.CONFIG,[],[])
        self.assertIn(('iran',2044,'greplus3','MISMATCH / check config'),rows)
    def test_draining_is_off_but_routes_retained(self):
        rows=tp.port_status_rows([self.profile('draining')],base.CONFIG,[],[])
        self.assertIn(('iran',2044,'greplus3','OFF / draining'),rows)
    def test_outside_different_interfaces_show_separate_states(self):
        r=self.profile('ready','outside')
        listeners=[dict(process='xray',port=2044,address='0.0.0.0')]
        links=[dict(iface='greplus3',up=True,address='10.30.3.2'),dict(iface='wgtun1',up=True,address='10.20.1.2')]
        rows=tp.port_status_rows([r],'',listeners,links,'outside')
        self.assertIn(('outside',2044,'greplus3','READY (outside)'),rows)
        self.assertIn(('outside',2044,'wgtun1','OFF / not prepared'),rows)
        self.assertEqual(len(rows),2)
    def test_role_filter(self):
        self.assertFalse(tp.port_status_rows([self.profile()],'',[],[],'outside'))
    def test_legacy_trial_never_marked_on(self):
        rows=tp.port_status_rows([self.profile('trial')],base.CONFIG,[],[])
        self.assertIn(('iran',2044,'greplus3','TRIAL (legacy)'),rows)
