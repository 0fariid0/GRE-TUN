import subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Reset(unittest.TestCase):
    def run_reset(self,override=''):
        with tempfile.TemporaryDirectory() as d:
            conf=Path(d)/'wg.conf';conf.write_text('preserved-key-and-allowedips')
            script=Path(d)/'test.sh'
            prefix=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0]
            stubs='''
install_manager_binary(){ :; }; show_header(){ :; }; confirm_yes(){ return 0; }; diagnostic_event(){ :; }
transparent_guard(){ echo BLOCKED; return 1; }
transparent_reset_check(){ echo PREFLIGHT; }
transparent_reset_restore(){ echo RESTORED; }
gre_collect_ids(){ echo 1; }; greplus_collect_ids(){ echo 3; }; wg_collect_ids(){ echo 1; }; bp_collect_ids(){ :; }
gre_load_config(){ :; }; greplus_load_config(){ :; }; wg_load_meta(){ REMOTE_WG_PUBLIC_KEY=present; }
gre_create_tunnel(){ echo GRE_CREATED; }; greplus_create_tunnel(){ echo PLUS_CREATED; }
gre_install_service(){ :; }; greplus_install_service(){ :; }
wg_ensure_tools(){ :; }; wg_ensure_transport_ready(){ echo TRANSPORT_READY; }; wg_apply_firewall_rules(){ :; }
transparent_repair_routes(){ echo WG_RESTORED; }
wg_write_config(){ echo BAD_REWRITE; return 1; }; wg_generate_keys(){ echo BAD_KEYGEN; return 1; }
wg_config_file(){ echo CONF_PATH; }
systemctl(){ echo SYSTEMCTL "$@"; }; ip(){ echo IP "$@"; }; wg-quick(){ echo WGQUICK "$@"; }
err_msg(){ echo ERROR "$@"; }
'''.replace('CONF_PATH',str(conf))
            script.write_text(prefix+'\n'+stubs+'\n'+override+'\nset +e\nreset_all_tunnels\nresult=$?\necho RESULT=$result\n')
            r=subprocess.run(['bash',str(script)],capture_output=True,text=True)
            self.assertEqual(conf.read_text(),'preserved-key-and-allowedips')
            return r.stdout+r.stderr
    def test_transparent_profiles_no_longer_block_reset(self):
        out=self.run_reset();self.assertIn('RESULT=0',out);self.assertNotIn('BLOCKED',out)
        self.assertNotIn('BAD_REWRITE',out);self.assertNotIn('BAD_KEYGEN',out)
        self.assertLess(out.index('PLUS_CREATED'),out.index('SYSTEMCTL restart wg-quick@wgtun1.service'))
        self.assertLess(out.index('GRE_CREATED'),out.index('PLUS_CREATED'))
        self.assertIn('RESTORED',out)
    def test_preflight_failure_never_stops_tunnels(self):
        out=self.run_reset('transparent_reset_check(){ return 1; }')
        self.assertIn('RESULT=1',out);self.assertNotIn('SYSTEMCTL stop',out)
    def test_failed_config_load_is_counted(self):
        out=self.run_reset('gre_load_config(){ return 1; }')
        self.assertIn('RESULT=1',out);self.assertIn('nothing stopped',out);self.assertNotIn('SYSTEMCTL stop',out)
    def test_restore_failure_not_reported_as_success(self):
        out=self.run_reset('transparent_reset_restore(){ return 1; }')
        self.assertIn('RESULT=1',out);self.assertNotIn('[OK] Reset all finished.',out)
    def test_pending_peer_not_restarted(self):
        out=self.run_reset('wg_load_meta(){ REMOTE_WG_PUBLIC_KEY=""; }')
        self.assertIn('pending peer key',out);self.assertNotIn('SYSTEMCTL restart wg-quick@',out)
