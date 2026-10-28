import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import test_transparent as base

tp=base.tp
ROOT=Path(__file__).resolve().parents[1]

class Installer(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.lib=self.root/'lib';self.lib.mkdir()
        self.target=self.lib/'transparent_forward.py'
        source=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0]
        source=source.replace('/usr/local/lib/gretun',str(self.lib))
        self.script=self.root/'GRETUN.sh';self.script.write_text(source)
    def execute(self,extra='',pipe=False):
        quote=lambda p:"'"+str(p).replace("'","'\\''")+"'"
        source='source '+quote(self.script)
        if pipe: source='source <(cat '+quote(self.script)+')'
        return subprocess.run(['bash','-c',source+'\n'+extra+'\ntransparent_install_module'],capture_output=True,text=True)
    def test_local_bundle_installs_and_matches_hash(self):
        (self.root/'transparent_forward.py').write_bytes((ROOT/'transparent_forward.py').read_bytes())
        result=self.execute('curl() { return 88; }')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_bytes(),(ROOT/'transparent_forward.py').read_bytes())
    def test_matching_installed_module_does_not_download(self):
        self.target.write_bytes((ROOT/'transparent_forward.py').read_bytes())
        self.assertEqual(self.execute('curl() { return 88; }').returncode,0)
    def test_process_substitution_downloads_without_reading_script_pipe(self):
        command="curl() { cp '"+str(ROOT/'transparent_forward.py')+"' \"${@: -1}\"; }"
        result=self.execute(command,pipe=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.target.read_bytes(),(ROOT/'transparent_forward.py').read_bytes())
    def test_bad_checksum_preserves_old_installed_helper(self):
        self.target.write_text('old helper')
        result=self.execute('curl() { echo corrupt > "${@: -1}"; }')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.target.read_text(),'old helper')
        self.assertFalse(list(self.lib.glob('.transparent.*')))
    def test_download_failure_preserves_old_installed_helper(self):
        self.target.write_text('old helper')
        self.assertNotEqual(self.execute('curl() { return 22; }').returncode,0)
        self.assertEqual(self.target.read_text(),'old helper')
    def test_main_menu_has_direct_outside_entry(self):
        main=(ROOT/'GRETUN.sh').read_text().split('### Script entry')[0].rsplit('main_menu()',1)[-1]
        self.assertIn('9) transparent_menu || true',main)

class Toggle(unittest.TestCase):
    def setUp(self):
        self.rows=[dict(role='iran',phase='active',plan=dict(id='a',iface='wga',frontend_port=443,backend_port=2044)),dict(role='outside',phase='ready',plan=dict(id='b',iface='greb',frontend_port=2044,backend_port=2044))]
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(patch.object(tp,'records',return_value=self.rows))
        self.stack.enter_context(patch.object(tp,'locked',side_effect=contextlib.nullcontext))
        self.stack.enter_context(patch.object(tp,'load',return_value=self.rows[0]))
        self.drain=self.stack.enter_context(patch.object(tp,'drain'))
        self.cleanup=self.stack.enter_context(patch.object(tp,'cleanup'))
    def test_iran_selects_public_port_and_removes_only_drained_role(self):
        with patch('builtins.input',return_value='443,'),patch.object(tp,'marked_connections',return_value=0):tp.auto_disable('iran')
        self.drain.assert_called_once_with('a');self.cleanup.assert_called_once_with('a')
    def test_active_sessions_keep_return_routes(self):
        with patch('builtins.input',return_value='0'),patch.object(tp,'marked_connections',return_value=4):tp.auto_disable('iran')
        self.drain.assert_called_once_with('a');self.cleanup.assert_not_called()
    def test_outside_has_no_confirmation_prompt(self):
        with patch('builtins.input',side_effect=['2044']) as ask,patch.object(tp,'marked_connections',return_value=0):tp.auto_disable('outside')
        self.assertEqual(ask.call_count,1)
        self.drain.assert_called_once_with('b');self.cleanup.assert_called_once_with('b')
    def test_cancel_leaves_profiles_unchanged(self):
        with patch('builtins.input',return_value='00'):tp.auto_disable('iran')
        self.drain.assert_not_called()
