#!/usr/bin/env python3
"""Failure, socket parsing, metadata isolation, and repair regression tests."""
import unittest
import test_wg_transport

class RuntimeRegressions(unittest.TestCase):
    run_shell = test_wg_transport.TransportTests.run_shell
    def test_ss_checks_local_udp_socket(self):
        self.run_shell('''ss() { echo 'UNCONN 0 0 0.0.0.0:51807 0.0.0.0:*'; }
# Use the production implementation instead of the setup's simple busy-port stub.
eval "$(sed -n '/^udp_port_is_listening() {/,/^}/p' "$1")"
udp_port_is_listening 51807
if udp_port_is_listening 51808; then exit 1; fi
''')

    def test_dependency_check_does_not_overwrite_parent(self):
        self.run_shell('''printf 'TUNNEL_ID=8\\nROLE=2\\nREMOTE_PUBLIC_IP=203.0.113.8\\nWG_ENDPOINT_MODE=greplus\\nWG_TRANSPORT_IFACE=greplus8\\n' > "$(wg_meta_file 8)"
TUNNEL_ID=7; ROLE=1; REMOTE_PUBLIC_IP=198.51.100.2
wg_uses_transport_tunnel 8 greplus 8
[ "$TUNNEL_ID" = 7 ]; [ "$ROLE" = 1 ]; [ "$REMOTE_PUBLIC_IP" = 198.51.100.2 ]
''')

    def test_old_meta_does_not_inherit_peer_or_ports(self):
        self.run_shell('''REMOTE_WG_PUBLIC_KEY=old; LOCAL_WG_PORT=60000; REMOTE_WG_PORT=60001
printf 'TUNNEL_ID=8\\nROLE=2\\nREMOTE_PUBLIC_IP=203.0.113.8\\n' > "$(wg_meta_file 8)"
wg_load_meta 8
[ -z "$REMOTE_WG_PUBLIC_KEY" ]; [ "$LOCAL_WG_PORT" = 51808 ]; [ "$REMOTE_WG_PORT" = 51808 ]
''')

    def test_config_write_failure_stops_creation(self):
        self.run_shell('''WG_ENDPOINT_MODE=public; WG_ENDPOINT_IP=198.51.100.2
REMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
wg_ensure_tools() { :; }
wg_generate_keys() { printf 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\\n' > "$(wg_public_key_file 7)"; }
wg_write_config() { return 1; }
wg_save_meta() { touch "$WG_META_DIR/saved-after-failure"; }
status=0; wg_create_tunnel 0 || status=$?
[ "$status" -ne 0 ]; [ ! -f "$WG_META_DIR/saved-after-failure" ]
''')

    def test_menu_propagates_creation_failure(self):
        self.run_shell('''GRE_UP=1
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=7; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=192.0.2.1; }
auto_select_udp_port() { echo 51807; }
wg_prompt_remote_port() { REMOTE_WG_PORT=51807; }
wg_create_tunnel() { return 1; }
status=0; wg_menu_config_tunnel || status=$?
[ "$status" -eq 1 ]
''', 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n')

    def test_peer_key_cancel_does_not_stop_existing_wg(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1
printf 'ROLE=1\\nLOCAL_PUBLIC_IP=192.0.2.1\\nREMOTE_PUBLIC_IP=198.51.100.2\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\nLOCAL_WG_PORT=51807\\n' > "$(wg_meta_file 7)"
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=7; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=192.0.2.1; }
auto_select_udp_port() { echo 51807; }
wg_prompt_remote_port() { REMOTE_WG_PORT=51807; }
status=0; wg_menu_config_tunnel || status=$?
[ "$status" -eq 99 ]; [ ! -f "$WG_META_DIR/cleanup.log" ]
''', '2\n00\n')

    def test_failed_key_generation_is_reported(self):
        self.run_shell('''wg() { return 1; }
status=0; wg_generate_keys 7 || status=$?
[ "$status" -eq 1 ]; [ ! -s "$(wg_private_key_file 7)" ]
''')

    def test_stale_public_key_is_rederived(self):
        self.run_shell('''printf 'private\\n' > "$(wg_private_key_file 7)"
printf 'stale-public\\n' > "$(wg_public_key_file 7)"
wg_generate_keys 7
[ "$(cat "$(wg_public_key_file 7)")" = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE= ]
''')

    def test_service_success_without_interface_is_failure(self):
        self.run_shell('''WG_UP=0
printf 'ROLE=1\\nWG_ENDPOINT_MODE=public\\nREMOTE_WG_PUBLIC_KEY=peer\\nLOCAL_WG_PORT=51807\\n' > "$(wg_meta_file 7)"
mkdir -p "$WG_CONFIG_DIR"; touch "$(wg_config_file 7)"
status=0; wg_install_service 7 || status=$?
[ "$status" -eq 1 ]
''')

    def test_transport_waits_then_pins_correct_inner_route(self):
        self.run_shell('''PLUS_UP=0; WG_ENDPOINT_MODE=greplus; WG_TRANSPORT_IFACE=greplus7; WG_ENDPOINT_IP=10.30.7.2
mkdir -p "$GREPLUS_CONFIG_DIR"; touch "$(greplus_config_file 7)"
sleep() { PLUS_UP=1; }
wg_ensure_transport_ready 7
grep -q -- '-4 route replace 10.30.7.2/32 dev greplus7 src 10.30.7.1' "$WG_META_DIR/routes.log"
''')

    def test_missing_transport_fails_start(self):
        self.run_shell('''PLUS_UP=0; WG_ENDPOINT_MODE=greplus; WG_TRANSPORT_IFACE=greplus7; WG_ENDPOINT_IP=10.30.7.2
sleep() { :; }
status=0; wg_ensure_transport_ready 7 || status=$?
[ "$status" -eq 1 ]; [ ! -f "$WG_META_DIR/routes.log" ]
''')

    def test_remote_port_is_independent_of_local_port(self):
        self.run_shell('''LOCAL_WG_PORT=51808
wg_prompt_remote_port 51807
[ "$REMOTE_WG_PORT" = 60000 ]; [ "$LOCAL_WG_PORT" = 51808 ]
''', '60000\n')

    def test_existing_wg_socket_keeps_its_own_port(self):
        self.run_shell('''wg() { echo 51807; }
udp_port_in_saved_configs() { return 1; }
auto_select_udp_port() { return 1; }
[ "$(wg_select_local_port 7 51807)" = 51807 ]
''')

    def test_failed_update_restores_previous_files(self):
        self.run_shell('''mkdir -p "$WG_CONFIG_DIR"
printf 'old-config\\n' > "$(wg_config_file 7)"
printf 'TUNNEL_ID=7\\nROLE=1\\nWG_ENDPOINT_MODE=public\\nREMOTE_WG_PUBLIC_KEY=old\\n' > "$(wg_meta_file 7)"
wg_write_config() { printf 'new-config\\n' > "$(wg_config_file 7)"; }
wg_save_meta() { printf 'new-meta\\n' > "$(wg_meta_file 7)"; }
wg_apply_firewall_rules() { :; }
wg_start_runtime() { [ "$(cat "$(wg_config_file 7)")" = old-config ]; }
status=0; wg_commit_and_start 7 || status=$?
[ "$status" -eq 1 ]
[ "$(cat "$(wg_config_file 7)")" = old-config ]
grep -q 'REMOTE_WG_PUBLIC_KEY=old' "$(wg_meta_file 7)"
''')

    def test_shared_greplus_peer_rule_is_kept_on_remove(self):
        self.run_shell('''printf 'TUNNEL_TYPE=greplus\\nROLE=1\\nLOCAL_PUBLIC_IP=192.0.2.1\\nREMOTE_PUBLIC_IP=198.51.100.2\\nREMOTE_GREPLUS_IP=10.30.7.2\\n' > "$(greplus_config_file 7)"
cp "$(greplus_config_file 7)" "$(greplus_config_file 8)"
greplus_remove_firewall 7
if grep -q -- '-p gre' "$WG_META_DIR/firewall.log"; then exit 1; fi
''')

    def test_repair_regenerates_missing_config(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1
printf 'TUNNEL_ID=7\\nROLE=1\\nLOCAL_PUBLIC_IP=192.0.2.1\\nREMOTE_PUBLIC_IP=198.51.100.2\\nLOCAL_WG_IP=10.20.7.1/30\\nREMOTE_WG_IP=10.20.7.2\\nLOCAL_WG_PORT=51807\\nREMOTE_WG_PORT=51807\\nWG_ENDPOINT_MODE=greplus\\nWG_ENDPOINT_IP=10.30.7.2\\nWG_TRANSPORT_IFACE=greplus7\\nWG_MTU=1380\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\n' > "$(wg_meta_file 7)"
wg_check_one_tunnel() { :; }
wg_restart_one_tunnel 7
grep -q 'Endpoint = 10.30.7.2:51807' "$(wg_config_file 7)"
grep -q 'MTU = 1380' "$(wg_config_file 7)"
''')

    def test_gre_and_greplus_roundtrip(self):
        self.run_shell('''TUN_IFACE=gre7; TUN_KEY=7; LOCAL_GRE_IP=10.10.7.1/30; REMOTE_GRE_IP=10.10.7.2
gre_save_config
ROLE=2; TUN_KEY=99; gre_load_config 7
[ "$ROLE" = 1 ]; [ "$TUN_KEY" = 7 ]; [ "$REMOTE_GRE_IP" = 10.10.7.2 ]
LOCAL_GREPLUS_IP=10.30.7.1/30; REMOTE_GREPLUS_IP=10.30.7.2
GREPLUS_MTU=1440; GREPLUS_TUN_KEY=100007; GREPLUS_TXQUEUELEN=10000
greplus_save_config
ROLE=2; GREPLUS_TUN_KEY=99; greplus_load_config 7
[ "$ROLE" = 1 ]; [ "$GREPLUS_TUN_KEY" = 100007 ]; [ "$REMOTE_GREPLUS_IP" = 10.30.7.2 ]
''')

    def test_reported_tunnel_three_on_greplus(self):
        self.run_shell('''eval "$(declare -f ip | sed 's/7/3/g')"
GRE_UP=1; PLUS_UP=1; TUNNEL_ID=3
printf 'TUNNEL_TYPE=gre\\nTUNNEL_ID=3\\nROLE=1\\nLOCAL_PUBLIC_IP=109.70.77.5\\nREMOTE_PUBLIC_IP=116.203.167.232\\n' > "$(gre_config_file 3)"
printf 'TUNNEL_TYPE=greplus\\nTUNNEL_ID=3\\nROLE=1\\nLOCAL_PUBLIC_IP=109.70.77.5\\nREMOTE_PUBLIC_IP=116.203.167.232\\nLOCAL_GREPLUS_IP=10.30.3.1/30\\nREMOTE_GREPLUS_IP=10.30.3.2\\n' > "$(greplus_config_file 3)"
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=3; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=109.70.77.5; }
wg_menu_config_tunnel
grep -q 'Endpoint = 10.30.3.2:51803' "$(wg_config_file 3)"
grep -q 'Address = 10.20.3.1/30' "$(wg_config_file 3)"
wg_load_meta 3
[ "$WG_TRANSPORT_IFACE" = greplus3 ]; [ "$REMOTE_PUBLIC_IP" = 116.203.167.232 ]; [ "$WG_PENDING" = 0 ]
''', '2\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\n')

    def test_new_tunnel_one_does_not_inherit_tunnel_three_port(self):
        for role in (1, 2):
            with self.subTest(role=role):
                self.run_shell(f'''eval "$(declare -f ip | sed 's/7/1/g')"
PLUS_UP=1; REMOTE_WG_PORT=51803; LOCAL_WG_PORT=51803; WG_REMOTE_PORT_CONFIRMED=1
show_header() {{ :; }}; prompt_role() {{ ROLE={role}; }}; prompt_tunnel_id() {{ TUNNEL_ID=1; }}
prompt_local_tunnel_ip() {{ LOCAL_PUBLIC_IP=192.0.2.1; }}
wg_create_tunnel() {{ [ "$LOCAL_WG_PORT" = 51801 ] && [ "$REMOTE_WG_PORT" = 51801 ]; }}
wg_menu_config_tunnel
''', 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\n')

    def test_unconfirmed_legacy_port_is_not_the_edit_default(self):
        self.run_shell('''eval "$(declare -f ip | sed 's/7/1/g')"; PLUS_UP=1
printf 'TUNNEL_ID=1\\nROLE=1\\nLOCAL_WG_PORT=51801\\nREMOTE_WG_PORT=51803\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\n' > "$(wg_meta_file 1)"
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=1; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=192.0.2.1; }
wg_create_tunnel() { [ "$LOCAL_WG_PORT" = 51801 ] && [ "$REMOTE_WG_PORT" = 51801 ]; }
wg_menu_config_tunnel
''', '\n\n')

    def test_confirmed_custom_remote_port_survives_edit(self):
        self.run_shell('''eval "$(declare -f ip | sed 's/7/1/g')"; PLUS_UP=1
printf 'TUNNEL_ID=1\\nROLE=1\\nLOCAL_WG_PORT=51801\\nREMOTE_WG_PORT=55001\\nWG_REMOTE_PORT_CONFIRMED=1\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\n' > "$(wg_meta_file 1)"
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=1; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=192.0.2.1; }
wg_create_tunnel() { [ "$REMOTE_WG_PORT" = 55001 ]; }
wg_menu_config_tunnel
''', '\n\n')

    def test_port_repair_persists_endpoint_without_regenerating_keys(self):
        for role in (1, 2):
            remote = '10.30.1.2' if role == 1 else '10.30.1.1'
            local = '10.20.1.1/30' if role == 1 else '10.20.1.2/30'
            peer = '10.20.1.2' if role == 1 else '10.20.1.1'
            with self.subTest(role=role):
                self.run_shell(f'''eval "$(declare -f ip | sed 's/7/1/g')"
mkdir -p "$WG_CONFIG_DIR"
printf 'original-private-key\\n' > "$(wg_private_key_file 1)"
printf 'original-public-key\\n' > "$(wg_public_key_file 1)"
printf 'original-config\\n' > "$(wg_config_file 1)"
printf 'TUNNEL_ID=1\\nROLE={role}\\nLOCAL_PUBLIC_IP=192.0.2.1\\nREMOTE_PUBLIC_IP=198.51.100.2\\nLOCAL_WG_IP={local}\\nREMOTE_WG_IP={peer}\\nLOCAL_WG_PORT=51801\\nREMOTE_WG_PORT=51803\\nWG_ENDPOINT_MODE=greplus\\nWG_ENDPOINT_IP={remote}\\nWG_TRANSPORT_IFACE=greplus1\\nWG_MTU=1312\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\n' > "$(wg_meta_file 1)"
wg() {{
 [ "$1" = set ] || return 1
 printf '%s\\n' "$*" > "$WG_META_DIR/live-update"
}}
wg_fix_peer_port 1 51801
grep -q 'Endpoint = {remote}:51801' "$(wg_config_file 1)"
grep -q 'REMOTE_WG_PORT=51801' "$(wg_meta_file 1)"
grep -q 'WG_REMOTE_PORT_CONFIRMED=1' "$(wg_meta_file 1)"
grep -q 'endpoint {remote}:51801' "$WG_META_DIR/live-update"
[ "$(cat "$(wg_private_key_file 1)")" = original-private-key ]
[ "$(cat "$(wg_public_key_file 1)")" = original-public-key ]
[ ! -f "$WG_META_DIR/cleanup.log" ]
''')

    def test_port_repair_runtime_failure_restores_previous_files(self):
        self.run_shell('''eval "$(declare -f ip | sed 's/7/1/g')"
mkdir -p "$WG_CONFIG_DIR"; printf 'original-conf\\n' > "$(wg_config_file 1)"
printf 'private\\n' > "$(wg_private_key_file 1)"
printf 'TUNNEL_ID=1\\nROLE=1\\nLOCAL_PUBLIC_IP=192.0.2.1\\nREMOTE_PUBLIC_IP=198.51.100.2\\nLOCAL_WG_IP=10.20.1.1/30\\nREMOTE_WG_IP=10.20.1.2\\nLOCAL_WG_PORT=51801\\nREMOTE_WG_PORT=51803\\nWG_ENDPOINT_MODE=greplus\\nWG_ENDPOINT_IP=10.30.1.2\\nWG_TRANSPORT_IFACE=greplus1\\nREMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\\n' > "$(wg_meta_file 1)"
wg() { return 1; }
status=0; wg_fix_peer_port 1 51801 || status=$?
[ "$status" -eq 1 ]; [ "$(cat "$(wg_config_file 1)")" = original-conf ]
grep -q 'REMOTE_WG_PORT=51803' "$(wg_meta_file 1)"
''')

if __name__ == '__main__':
    unittest.main(verbosity=2)
