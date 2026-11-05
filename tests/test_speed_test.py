#!/usr/bin/env python3
"""Speed-test menu regressions; fake iperf3/services, no root or network required."""
import unittest
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import test_wg_transport

SETUP = r'''
ensure_feature_dependencies() { :; }
show_header() { :; }
print_tunnel_inventory() { :; }
build_tunnel_inventory() {
 INV_TYPE=(gre greplus wireguard)
 INV_ID=(1 1 1)
 INV_IFACE=(gre1 greplus1 wgtun1)
 INV_LOCAL=(10.10.1.1/30 10.30.1.1/30 10.20.1.1/30)
 INV_TARGET=(10.10.1.2 10.30.1.2 10.20.1.2)
 INV_STATE=(active active active)
}
tunnel_iface_is_up() { [ "$1" != "${DOWN_IFACE:-}" ]; }
iperf3() {
 if [ "$1" = --help ]; then echo --connect-timeout; return 0; fi
 printf '%s\n' "$*" >> "$WG_META_DIR/iperf-calls"
 return 0
}
timeout() {
 printf '%s\n' "$*" >> "$WG_META_DIR/timeout-calls"
 shift 3
 "$@"
}
'''

class SpeedTests(unittest.TestCase):
    run_shell = test_wg_transport.TransportTests.run_shell

    def test_selection_formats_single_multiple_all(self):
        for selection, expected in (
            ('1 2 3','1 2 3'), ('1,2,3,','1 2 3'),
            (' 3, 1 , 2, ','3 1 2'), ('2','2'), ('0','1 2 3'),
            ('2 2 1,2','2 1'), ('03,01','3 1'),
        ):
            with self.subTest(selection=selection):
                self.run_shell(f'speed_test_parse_selection "{selection}" 3; [ "${{SPEED_TEST_SELECTION[*]}}" = "{expected}" ]')

    def test_invalid_selection_rejects_whole_batch(self):
        for selection in ('','1 4','1 nope','0,1','-1','9999999999999999'):
            with self.subTest(selection=selection):
                self.run_shell(f'''SPEED_TEST_SELECTION=(1 2)
status=0; speed_test_parse_selection "{selection}" 3 || status=$?
[ "$status" -eq 1 ]; [ "${{#SPEED_TEST_SELECTION[@]}}" -eq 0 ]
''')

    def test_outside_does_not_ask_for_tunnel_or_duration(self):
        self.run_shell(SETUP + r'''
build_tunnel_inventory() { echo unwanted > "$WG_META_DIR/inventory-called"; return 1; }
tunnel_speed_test_menu
[ ! -f "$WG_META_DIR/inventory-called" ]
[ "$(cat "$WG_META_DIR/iperf-calls")" = '-s -4 -p 5201' ]
if grep -q -- '-1\|-B' "$WG_META_DIR/iperf-calls"; then exit 1; fi
''', '2\n')

    def test_outside_firewall_covers_all_managed_ranges(self):
        self.run_shell(r'''
iperf3_prepare_firewall
for subnet in 10.10.0.0/16 10.20.0.0/16 10.30.0.0/16; do
 grep -q -- "-I INPUT -s $subnet -p tcp --dport 5201 -j ACCEPT" "$WG_META_DIR/firewall.log"
 grep -q -- "allow from $subnet to any port 5201 proto tcp" "$WG_META_DIR/ufw.log"
done
''')

    def test_each_selected_row_uses_its_own_ips(self):
        self.run_shell(SETUP + r'''
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 3 ]
sed -n '1p' "$WG_META_DIR/iperf-calls" | grep -q -- '-c 10.20.1.2 -B 10.20.1.1'
sed -n '2p' "$WG_META_DIR/iperf-calls" | grep -q -- '-c 10.10.1.2 -B 10.10.1.1'
sed -n '3p' "$WG_META_DIR/iperf-calls" | grep -q -- '-c 10.30.1.2 -B 10.30.1.1'
grep -q -- '-t 15 -P 4 --connect-timeout 5000' "$WG_META_DIR/iperf-calls"
grep -q -- '35s iperf3' "$WG_META_DIR/timeout-calls"
''', '1\n3,1,2,\n15\n')

    def test_single_row_finishes(self):
        self.run_shell(SETUP + r'''
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 1 ]
grep -q -- '-c 10.30.1.2 -B 10.30.1.1 -p 5201 -t 10 -P 4' "$WG_META_DIR/iperf-calls"
''', '1\n2\n\n')

    def test_all_rows_complete_and_server_is_never_stopped(self):
        out = self.run_shell(SETUP + r'''
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 3 ]
[ ! -f "$WG_META_DIR/systemctl.log" ]
''', '1\n0\n\n')
        self.assertIn('completed=3 ok=3 failed=0 skipped=0', out)

    def test_failure_continues_to_remaining_rows(self):
        out = self.run_shell(SETUP + r'''
iperf3() {
 if [ "$1" = --help ]; then return 0; fi
 printf '%s\n' "$*" >> "$WG_META_DIR/iperf-calls"
 [[ "$*" != *'-c 10.30.1.2 '* ]]
}
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 3 ]
''', '1\n1 2 3\n\n')
        self.assertIn('completed=3 ok=2 failed=1 skipped=0', out)

    def test_inactive_row_skipped_without_restart(self):
        out = self.run_shell(SETUP + r'''
DOWN_IFACE=greplus1
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 2 ]
[ ! -f "$WG_META_DIR/cleanup.log" ]; [ ! -f "$WG_META_DIR/systemctl.log" ]
''', '1\n1 2 3\n\n')
        self.assertIn('completed=3 ok=2 failed=0 skipped=1', out)

    def test_timeout_does_not_abort_batch(self):
        out = self.run_shell(SETUP + r'''
timeout() {
 shift 3
 if [[ "$*" == *'-c 10.10.1.2 '* ]]; then return 124; fi
 "$@"
}
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 2 ]
''', '1\n1 2 3\n\n')
        self.assertIn('FAILED(124)', out)
        self.assertIn('completed=3 ok=2 failed=1 skipped=0', out)

    def test_interrupt_stops_remaining_client_rows(self):
        out = self.run_shell(SETUP + r'''
iperf3() {
 if [ "$1" = --help ]; then return 0; fi
 printf '%s\n' "$*" >> "$WG_META_DIR/iperf-calls"
 return 130
}
tunnel_speed_test_menu
[ "$(wc -l < "$WG_META_DIR/iperf-calls")" -eq 1 ]
''', '1\n1 2 3\n\n')
        self.assertIn('INTERRUPTED', out)
        self.assertIn('NOT-RUN', out)

    def test_server_manual_stop_restores_signal_handler(self):
        self.run_shell(SETUP + r'''
trap ':' INT
before="$(trap -p INT)"
iperf3() { return 130; }
tunnel_speed_test_menu
[ "$(trap -p INT)" = "$before" ]
''', '2\n')

    def test_cancel_invalid_rows_and_duration_do_not_start_iperf(self):
        for inputs in ('00\n', '1\n00\n', '1\n1 4\n', '1\n1\n0\n', '1\n1\n3601\n', '1\n1\n00\n'):
            with self.subTest(inputs=inputs):
                self.run_shell(SETUP + r'''
status=0; tunnel_speed_test_menu || status=$?
[ "$status" -ne 0 ]; [ ! -f "$WG_META_DIR/iperf-calls" ]
''', inputs)

    def test_real_ctrl_c_closes_server_and_returns_to_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            functions = root / 'functions.sh'
            functions.write_text(test_wg_transport.SOURCE.read_text().split('### Script entry', 1)[0])
            ready = root / 'ready'
            script = r'''source "$1"
iperf3_prepare_firewall() { :; }
iperf3() { touch "$TEST_READY_PATH"; sleep 60; }
trap ':' INT
before="$(trap -p INT)"
speed_test_outside_server
[ "$(trap -p INT)" = "$before" ] || exit 1
echo RETURNED_TO_CALLER
'''
            environment = dict(os.environ, TEST_READY_PATH=str(ready))
            process = subprocess.Popen(['bash','-c',script,'test',str(functions)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=True, env=environment)
            try:
                deadline = time.monotonic() + 3
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), 'server did not become ready')
                os.killpg(process.pid, signal.SIGINT)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 0, stdout + stderr)
                self.assertIn('RETURNED_TO_CALLER', stdout)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()

if __name__ == '__main__':
    unittest.main(verbosity=2)
