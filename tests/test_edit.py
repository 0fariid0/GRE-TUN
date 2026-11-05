import subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class EditPublicIPs(unittest.TestCase):
    def edit(self,kind='gre',local='',remote='',cancel=False,fail=False,role=1):
        with tempfile.TemporaryDirectory() as d:
            cfg=Path(d)/'tunnel.conf';cfg.write_text(f'ROLE={role}\nLOCAL_PUBLIC_IP=109.70.77.5\nREMOTE_PUBLIC_IP=91.107.243.71\n')
            script=Path(d)/'run.sh';prefix=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0]
            stubs='''
gre_config_file(){ echo CFG; }; greplus_config_file(){ echo CFG; }
gre_load_config(){ source CFG; TUNNEL_ID=3; }; greplus_load_config(){ gre_load_config "$@"; }
prompt_local_tunnel_ip(){ echo LOCAL_DEFAULT=$1; LOCAL_PUBLIC_IP=NEWLOCAL; }
prompt_remote_public_ip(){ echo REMOTE_DEFAULT=$1; REMOTE_PUBLIC_IP=NEWREMOTE; }
install_manager_binary(){ :; }; transparent_repair_routes(){ echo RESTORE:$1; }
transparent_guard(){ echo BAD_GUARD; return 1; }
ok_msg(){ echo "$@"; }; warn_msg(){ echo "$@"; }
gre_create_tunnel(){ echo APPLY:$1:$LOCAL_PUBLIC_IP:$REMOTE_PUBLIC_IP; if [ "$1" = 1 ]; then printf 'ROLE=%s\\nLOCAL_PUBLIC_IP=%s\\nREMOTE_PUBLIC_IP=%s\\n' "$ROLE" "$LOCAL_PUBLIC_IP" "$REMOTE_PUBLIC_IP" > CFG; FAIL; fi; }
greplus_create_tunnel(){ gre_create_tunnel "$@"; }
'''.replace('CFG',str(cfg)).replace('NEWLOCAL',local or '109.70.77.5').replace('NEWREMOTE',remote or '91.107.243.71').replace('FAIL','return 1' if fail else ':')
            if cancel: stubs+='\nprompt_remote_public_ip(){ return 99; }\n'
            script.write_text(prefix+'\n'+stubs+f'\nset +e\ntunnel_edit_public_ips {kind} 3\nrc=$?\necho RESULT=$rc\n')
            result=subprocess.run(['bash',str(script)],capture_output=True,text=True)
            return result.stdout+result.stderr,cfg.read_text()
    def test_enter_keeps_old_ips_without_recreate(self):
        out,cfg=self.edit();self.assertIn('No IP changes',out);self.assertNotIn('APPLY:',out)
        self.assertIn('LOCAL_DEFAULT=109.70.77.5',out);self.assertIn('REMOTE_DEFAULT=91.107.243.71',out)
    def test_remote_only_updates_same_gre_number(self):
        out,cfg=self.edit(remote='116.203.167.232');self.assertIn('RESULT=0',out)
        self.assertIn('LOCAL_PUBLIC_IP=109.70.77.5',cfg);self.assertIn('REMOTE_PUBLIC_IP=116.203.167.232',cfg)
        self.assertIn('RESTORE:gre3',out);self.assertNotIn('BAD_GUARD',out)
    def test_local_only_updates_and_keeps_remote(self):
        out,cfg=self.edit(local='188.213.67.220');self.assertIn('LOCAL_PUBLIC_IP=188.213.67.220',cfg)
        self.assertIn('REMOTE_PUBLIC_IP=91.107.243.71',cfg)
    def test_greplus_has_same_edit_behavior(self):
        out,cfg=self.edit('greplus',remote='116.203.167.232');self.assertIn('RESTORE:greplus3',out)
        self.assertIn('REMOTE_PUBLIC_IP=116.203.167.232',cfg)
    def test_failed_apply_restores_file_and_attempts_old_runtime(self):
        out,cfg=self.edit(remote='116.203.167.232',fail=True)
        self.assertIn('RESULT=1',out);self.assertIn('REMOTE_PUBLIC_IP=91.107.243.71',cfg)
        self.assertIn('APPLY:0:109.70.77.5:91.107.243.71',out)
    def test_cancel_leaves_existing_tunnel_untouched(self):
        out,cfg=self.edit(cancel=True);self.assertIn('RESULT=99',out);self.assertNotIn('APPLY:',out)
    def test_outside_role_labels_reverse_public_addresses(self):
        out,cfg=self.edit(role=2);self.assertIn('Iran IP: 91.107.243.71 | Outside IP: 109.70.77.5',out)
