#!/usr/bin/env python3
"""Regression tests with fake network/services; no root or live tunnels required."""
import pathlib
import subprocess
import tempfile
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'GRETUN.sh'

class TransportTests(unittest.TestCase):
    def run_shell(self, code, stdin=''):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = SOURCE.read_text().split('### Script entry', 1)[0]
            # Keep even accidental writes inside this temporary test sandbox.
            for prefix in ('/etc/', '/proc/sys/', '/usr/local/', '/var/', '/run/'):
                source = source.replace(prefix, str(root) + prefix)
            script = root / 'functions.sh'
            script.write_text(source)
            setup = r'''
source "$1"
GRE_UP=0; PLUS_UP=0; WG_UP=1; GRE_MTU=1390; PLUS_MTU=1440
REMOTE_PUBLIC_IP=198.51.100.2; LOCAL_PUBLIC_IP=192.0.2.1
ROLE=1; TUNNEL_ID=7
mkdir -p "$GRE_CONFIG_DIR" "$GREPLUS_CONFIG_DIR" "$WG_META_DIR" "$WG_KEY_DIR"
ip() {
  if [[ "$*" == '-o link show dev '* ]]; then
    local dev="${5}" up=0 mtu=1500
    case "$dev" in gre7) up=$GRE_UP; mtu=$GRE_MTU ;; greplus7) up=$PLUS_UP; mtu=$PLUS_MTU ;; wgtun7) up=$WG_UP ;; esac
    [ "$up" -eq 1 ] || return 1
    echo "7: $dev: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu $mtu state UNKNOWN"
  elif [[ "$*" == '-o -4 addr show dev '* ]]; then
    case "$6" in
      gre7) echo '7: gre7 inet 10.10.7.1/30 scope global' ;;
      greplus7) echo '7: greplus7 inet 10.30.7.1/30 scope global' ;;
    esac
  else
    printf '%s\n' "$*" >> "$WG_META_DIR/routes.log"
    return 0
  fi
}
wg() {
 case "$1" in
   genkey) echo 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=' ;;
   pubkey) cat >/dev/null; echo 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=' ;;
 esac
}
wg_ensure_tools() { return 0; }
diagnostic_prepare_logs() { return 0; }
systemctl() { printf '%s\n' "$*" >> "$WG_META_DIR/systemctl.log"; return 0; }
install_manager_binary() { return 0; }
install_health_monitor() { return 0; }
wg_safe_cleanup_runtime() { echo cleanup >> "$WG_META_DIR/cleanup.log"; }
udp_port_is_listening() { return 1; }
firewall_allow_udp_port_and_ip() { return 0; }
firewall_allow_ip_peer() { return 0; }
iptables() { printf '%s\n' "$*" >> "$WG_META_DIR/firewall.log"; [[ "$1" != -C ]]; }
ufw() { printf '%s\n' "$*" >> "$WG_META_DIR/ufw.log"; }
firewall-cmd() { return 0; }
'''
            result = subprocess.run(['bash', '-c', setup + '\n' + code, 'test', str(script)],
                                    input=stdin, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

    def test_selection_matrix(self):
        for gre, plus, choice, mode, iface, endpoint in (
            (1,0,'','gre','gre7','10.10.7.2'),
            (0,1,'','greplus','greplus7','10.30.7.2'),
            (1,1,'1\n','gre','gre7','10.10.7.2'),
            (1,1,'2\n','greplus','greplus7','10.30.7.2'),
            (0,0,'','public','','198.51.100.2'),
        ):
            for role in (1,2):
                expected = endpoint if role == 1 or mode == 'public' else endpoint[:-1] + '1'
                with self.subTest(gre=gre, plus=plus, choice=choice, role=role):
                    self.run_shell(f'''GRE_UP={gre}; PLUS_UP={plus}; ROLE={role}
wg_choose_auto_endpoint 7 "$ROLE" 1
[ "$WG_ENDPOINT_MODE" = "{mode}" ]
[ "$WG_TRANSPORT_IFACE" = "{iface}" ]
[ "$WG_ENDPOINT_IP" = "{expected}" ]
''', choice)

    def test_invalid_choice_retry(self):
        self.run_shell('GRE_UP=1; PLUS_UP=1; wg_choose_auto_endpoint 7 1 1; [ "$WG_ENDPOINT_MODE" = greplus ]', 'x\n\n2\n')

    def test_noninteractive_does_not_prompt(self):
        self.run_shell('GRE_UP=1; PLUS_UP=1; wg_choose_auto_endpoint 7 1; [ "$WG_ENDPOINT_MODE" = gre ]')

    def test_cancel_leaves_old_tunnel_running(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=7; }
status=0; wg_menu_config_tunnel || status=$?
[ "$status" -eq 99 ]; [ ! -f "$WG_META_DIR/cleanup.log" ]
''', '00\n')

    def test_role_mismatch(self):
        self.run_shell('''PLUS_UP=1
printf 'ROLE=2\nREMOTE_PUBLIC_IP=203.0.113.2\n' > "$(greplus_config_file 7)"
status=0; wg_choose_auto_endpoint 7 1 1 || status=$?
[ "$status" -eq 1 ]
''')

    def test_selected_peer_and_state_isolation(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1; REMOTE_WG_PUBLIC_KEY=keep
printf 'ROLE=1\nTUNNEL_ID=99\nREMOTE_PUBLIC_IP=203.0.113.10\n' > "$(gre_config_file 7)"
printf 'ROLE=1\nTUNNEL_ID=88\nREMOTE_PUBLIC_IP=203.0.113.20\n' > "$(greplus_config_file 7)"
wg_choose_auto_endpoint 7 1 1
[ "$REMOTE_PUBLIC_IP" = 203.0.113.20 ]; [ "$TUNNEL_ID" = 7 ]; [ "$REMOTE_WG_PUBLIC_KEY" = keep ]
''', '2\n')

    def test_mtu_uses_selected_parent(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1
WG_TRANSPORT_IFACE=gre7; [ "$(wg_mtu_for_gre 7)" = 1330 ]
WG_TRANSPORT_IFACE=greplus7; [ "$(wg_mtu_for_gre 7)" = 1380 ]
PLUS_MTU=1500; [ "$(wg_mtu_for_gre 7)" = 1420 ]
''')

    def test_persist_config_firewall_service_and_removal(self):
        for mode, iface, endpoint, service in (
            ('gre','gre7','10.10.7.2','gre-tunnel@7.service'),
            ('greplus','greplus7','10.30.7.2','greplus-tunnel@7.service'),
            ('public','','198.51.100.2','network-online.target'),
        ):
            with self.subTest(mode=mode):
                self.run_shell(fr'''
GRE_UP=1; PLUS_UP=1
WG_IFACE=wgtun7; SERVER_ROLE=IRAN; LOCAL_WG_IP=10.20.7.1/30; REMOTE_WG_IP=10.20.7.2
LOCAL_WG_PORT=51807; REMOTE_WG_PORT=51807; EXTRA_ALLOWED_IPS=''; REMOTE_WG_PUBLIC_KEY=peer
WG_ENDPOINT_MODE={mode}; WG_ENDPOINT_IP={endpoint}; WG_TRANSPORT_IFACE={iface!r}; WG_MTU=1380
printf 'private\n' > "$(wg_private_key_file 7)"
wg_save_meta; wg_write_config 7
WG_ENDPOINT_MODE=wrong; WG_TRANSPORT_IFACE=wrong; wg_load_meta 7
[ "$WG_ENDPOINT_MODE" = {mode} ]; [ "$WG_TRANSPORT_IFACE" = {iface!r} ]
grep -q 'Endpoint = {endpoint}:51807' "$(wg_config_file 7)"
wg_apply_firewall_rules 7
wg_install_service 7
grep -q '{service}' "$(dirname "$GRE_SERVICE_TEMPLATE")/wg-quick@wgtun7.service.d/10-gretun-firewall.conf"
if [ {mode} != public ]; then
  grep -q -- '-i {iface} -p udp --dport 51807' "$WG_META_DIR/firewall.log"
  grep -q 'in on {iface} to any port 51807 proto udp' "$WG_META_DIR/ufw.log"
  wg_uses_transport_tunnel 7 {mode} 7
  if wg_uses_transport_tunnel 7 {mode} 8; then exit 1; fi
  INV_TYPE=({mode} wireguard); INV_ID=(7 7)
  wg_collect_ids() {{ echo 7; }}
  if remove_selection_dependency_guard 1; then exit 1; fi
  remove_selection_dependency_guard 1 2
fi
''')

    def test_menu_uses_selection(self):
        self.run_shell('''GRE_UP=1; PLUS_UP=1
show_header() { :; }; prompt_role() { ROLE=1; }; prompt_tunnel_id() { TUNNEL_ID=7; }
prompt_local_tunnel_ip() { LOCAL_PUBLIC_IP=192.0.2.1; }
auto_select_udp_port() { echo 51807; }
wg_create_tunnel() {
 [ "$WG_ENDPOINT_MODE" = greplus ] && [ "$WG_ENDPOINT_IP" = 10.30.7.2 ] &&
 [ "$WG_TRANSPORT_IFACE" = greplus7 ] && [ "$WG_MTU" = 1380 ] &&
 touch "$WG_META_DIR/created"
}
wg_menu_config_tunnel
[ -f "$WG_META_DIR/created" ]
''', '2\nAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\n')

    def test_old_metadata_does_not_inherit_transport(self):
        self.run_shell('''WG_ENDPOINT_MODE=greplus; WG_TRANSPORT_IFACE=greplus7; WG_MTU=1380
printf 'TUNNEL_ID=8\\nREMOTE_PUBLIC_IP=203.0.113.8\\n' > "$(wg_meta_file 8)"
wg_load_meta 8
[ "$WG_ENDPOINT_MODE" = public ]; [ -z "$WG_TRANSPORT_IFACE" ]; [ "$WG_ENDPOINT_IP" = 203.0.113.8 ]
[ -z "${WG_MTU:-}" ]
''')

    def test_create_tunnel_with_selected_transport(self):
        for mode in ('gre', 'greplus'):
            with self.subTest(mode=mode):
                self.run_shell(f'''GRE_UP=1; PLUS_UP=1
wg_choose_auto_endpoint 7 1 1
WG_MTU="$(wg_mtu_for_gre 7)"; LOCAL_WG_PORT=51807; REMOTE_WG_PORT=51807; EXTRA_ALLOWED_IPS=''
REMOTE_WG_PUBLIC_KEY=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
wg_ensure_tools() {{ :; }}
enable_ip_forward() {{ :; }}
wg_generate_keys() {{
 printf 'private\\n' > "$(wg_private_key_file 7)"
 printf 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\\n' > "$(wg_public_key_file 7)"
}}
wg_create_tunnel 0
[ "$WG_ENDPOINT_MODE" = {mode} ]; [ "$WG_PENDING" = 0 ]
grep -q "Endpoint = $WG_ENDPOINT_IP:51807" "$(wg_config_file 7)"
grep -q 'restart wg-quick@wgtun7.service' "$WG_META_DIR/systemctl.log"
''', '1\n' if mode == 'gre' else '2\n')

if __name__ == '__main__':
    unittest.main(verbosity=2)
