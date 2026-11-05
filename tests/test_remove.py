import subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import test_transparent as base
tp=base.tp
ROOT=Path(__file__).resolve().parents[1]
class RemoveProfiles(unittest.TestCase):
    setUp=base.LifecycleTests.setUp
    tearDown=base.LifecycleTests.tearDown
    jrun=base.LifecycleTests.jrun
    plan=base.LifecycleTests.plan
    def deleting(self,*args,**kwargs):
        if args[:2]==('conntrack','-D'): self.k.connections=0
        return self.k(*args,**kwargs)
    def test_delete_active_profile_restores_frontend_and_removes_only_owned_flows(self):
        p=self.plan()
        with patch.object(tp,'probe_transparent'):tp.stage(p,'iran',direct=True)
        self.k.connections=4
        with patch.object(tp,'run',side_effect=self.deleting):tp.remove_interface(p['iface'])
        self.assertFalse(tp.records());self.assertEqual(self.cfg.read_text().strip(),base.CONFIG.strip())
        deletions=[c for c in self.k.calls if c[:2]==('conntrack','-D')]
        self.assertEqual(len(deletions),1);self.assertIn('--mark',deletions[0]);self.assertFalse(any('-F' in c for c in self.k.calls))
    def test_other_interface_is_preserved(self):
        a,b=self.plan(),self.plan(3);tp.stage(a,'outside');tp.stage(b,'outside')
        tp.remove_interface(a['iface'])
        self.assertEqual([x['plan']['id'] for x in tp.records()],[b['id']])
        self.assertIn('45002',self.k.routes)
    def test_incomplete_profile_blocks_destructive_removal(self):
        p=self.plan();tp.stage(p,'outside');r=tp.load(p['id']);r['phase']='recovery-needed';tp.save(r)
        with self.assertRaises(tp.Error):tp.remove_interface(p['iface'])
        self.assertTrue(tp.records());self.assertFalse(any(c[:2]==('conntrack','-D') for c in self.k.calls))

class DeleteShell(unittest.TestCase):
    def run_script(self,override='',kind='gre'):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cfg=root/'tunnel.conf';cfg.write_text('old config');live=root/'live';live.touch()
            prefix=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0]
            stubs='''
remove_transport_dependency_check(){ :; }; transparent_remove_interface(){ :; }
gre_config_file(){ echo CFG; }; greplus_config_file(){ echo CFG; }
greplus_remove_firewall(){ :; }; systemctl(){ return 0; }
ip(){ if [ "$1 $2" = "link show" ]; then [ -f LIVE ]; elif [ "$1 $2" = "tunnel del" ]; then rm -f LIVE; fi; }
err_msg(){ echo ERROR "$@"; }; ok_msg(){ echo OK "$@"; }
'''.replace('CFG',str(cfg)).replace('LIVE',str(live))
            script=root/'run.sh';script.write_text(prefix+'\n'+stubs+'\n'+override+f'\nset +e\n{kind}_remove_one_tunnel 3\nrc=$?\necho RESULT=$rc\n')
            result=subprocess.run(['bash',str(script)],capture_output=True,text=True)
            return result.stdout+result.stderr,cfg.exists(),live.exists()
    def test_gre_remove_verifies_interface_and_deletes_config(self):
        out,cfg,live=self.run_script();self.assertIn('RESULT=0',out);self.assertFalse(cfg);self.assertFalse(live)
    def test_greplus_remove_verifies_interface(self):
        out,cfg,live=self.run_script(kind='greplus');self.assertIn('RESULT=0',out);self.assertFalse(cfg)
    def test_failed_kernel_delete_keeps_saved_config(self):
        out,cfg,live=self.run_script('ip(){ if [ "$1 $2" = "link show" ]; then return 0; fi; return 1; }')
        self.assertIn('RESULT=1',out);self.assertTrue(cfg);self.assertTrue(live)
    def test_active_service_stop_failure_keeps_config_and_interface(self):
        out,cfg,live=self.run_script('systemctl(){ if [ "$1" = disable ]; then return 1; fi; return 0; }')
        self.assertIn('RESULT=1',out);self.assertTrue(cfg);self.assertTrue(live)
    def test_remaining_wireguard_dependency_blocks_parent_removal(self):
        out,cfg,live=self.run_script('remove_transport_dependency_check(){ return 1; }')
        self.assertIn('RESULT=1',out);self.assertTrue(cfg);self.assertTrue(live)

    def test_remove_all_reports_partial_failure_and_orders_wireguard_first(self):
        with tempfile.TemporaryDirectory() as d:
            script=Path(d)/'run.sh';prefix=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0]
            stubs="""
show_header(){ :; }; print_tunnel_inventory(){ :; }; confirm_yes(){ return 0; }
build_tunnel_inventory(){ INV_TYPE=(gre wireguard); INV_ID=(3 3); INV_IFACE=(gre3 wgtun3); INV_TARGET=(10.10.3.2 10.20.3.2); }
remove_selection_dependency_guard(){ return 0; }; heal_remaining_tunnels_after_remove(){ :; }
remove_inventory_item(){ echo REMOVE_ROW:$1; [ "$1" != 2 ]; }
warn_msg(){ echo WARN "$@"; }; err_msg(){ echo ERROR "$@"; }; ok_msg(){ echo OK "$@"; }
set +e
remove_tun
result=$?
echo RESULT=$result
"""
            script.write_text(prefix+'\n'+stubs)
            result=subprocess.run(['bash',str(script)],input='88\n',capture_output=True,text=True)
            self.assertIn('RESULT=1',result.stdout)
            self.assertLess(result.stdout.index('REMOVE_ROW:2'),result.stdout.index('REMOVE_ROW:1'))
            self.assertIn('Removal incomplete',result.stdout)
            self.assertNotIn('All tunnels removed.',result.stdout)
