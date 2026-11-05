from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[1]
class Update(unittest.TestCase):
    def test_regular_file_installs_exact_running_source(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'manager.sh'
            cmd=f'source "{ROOT}/GRETUN.sh"; INSTALL_BIN="{target}"; install_manager_binary'
            r=subprocess.run(['bash','-c',cmd],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(target.read_bytes(),(ROOT/'GRETUN.sh').read_bytes())
    def test_pipe_download_of_wrong_release_keeps_existing_install(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'manager.sh';target.write_text('old manager')
            cmd=f'''source <(cat "{ROOT}/GRETUN.sh")
INSTALL_BIN="{target}"
curl() {{ printf 'APP_VERSION="0.0.0"\\n' > "${{@: -1}}"; }}
install_manager_binary
'''
            r=subprocess.run(['bash','-c',cmd],capture_output=True,text=True)
            self.assertNotEqual(r.returncode,0);self.assertIn('version mismatch',r.stderr)
            self.assertEqual(target.read_text(),'old manager')
    def test_pipe_download_of_matching_release_installs(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d)/'manager.sh'
            cmd=f'''source <(cat "{ROOT}/GRETUN.sh")
INSTALL_BIN="{target}"
curl() {{ cp "{ROOT}/GRETUN.sh" "${{@: -1}}"; }}
install_manager_binary
'''
            r=subprocess.run(['bash','-c',cmd],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(target.read_bytes(),(ROOT/'GRETUN.sh').read_bytes())
    def test_full_local_installer_updates_manager_and_module(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);installer=root/'install.sh'
            text=(ROOT/'install-local.sh').read_text().replace('package_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"',f'package_dir="{ROOT}"').replace('/usr/local/',str(root)+'/usr/local/')
            text=text.replace('[ "$(id -u)" = 0 ]','[ 0 = 0 ]')
            installer.write_text(text)
            r=subprocess.run(['bash',str(installer)],input='',capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            manager=root/'usr/local/bin/gretun-manager.sh'
            self.assertEqual(manager.read_bytes(),(ROOT/'GRETUN.sh').read_bytes())
            self.assertEqual((root/'usr/local/lib/gretun/transparent_forward.py').read_bytes(),(ROOT/'transparent_forward.py').read_bytes())
            version=subprocess.run(['bash',str(manager),'--version'],capture_output=True,text=True)
            self.assertEqual(version.stdout.strip(),'12.5.5')
