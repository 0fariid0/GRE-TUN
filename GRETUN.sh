#!/bin/bash
set -euo pipefail

# Tunnel Manager v9.0-safe-hybrid
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - WireGuard can use public UDP or automatically ride over an existing GRE tunnel as transport
# - Local tunnel/bind IPv4 can be selected manually for servers with multiple IPs
# - v9 adds isolated secure overlays, hybrid failover, optional low-CPU health checks, and WSS/TCP fallback
# - Normal GRE implementation is preserved unchanged for backward compatibility

GRE_CONFIG_DIR="/etc/gre-tunnels"
GRE_LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gretun-manager.sh"
GRE_SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
GRE_LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"

WG_META_DIR="/etc/wgtun-tunnels"
WG_KEY_DIR="$WG_META_DIR/keys"
WG_CONFIG_DIR="/etc/wireguard"
WG_IFACE_PREFIX="wgtun"

VIRA7_CONFIG_DIR="/etc/vira7-tunnels"
VIRA7_BINARY="/usr/local/bin/vira7-engine"
VIRA7_SOURCE="$VIRA7_CONFIG_DIR/vira7_engine.c"
VIRA7_SERVICE_TEMPLATE="/etc/systemd/system/vira7-tunnel@.service"
VIRA7_IFACE_PREFIX="vira7"
VIRA7_DEFAULT_MTU=1400
VIRA7_DEFAULT_PORT_BASE=5571
VIRA7_DEFAULT_KEEPALIVE=5
VIRA7_DEFAULT_BUFFER_SIZE=2097152
VIRA7_DEFAULT_QUEUE_LEN=1000
# Vira7 CPU optimization defaults:
# checksum=1 keeps packet format compatible with older engines.
# verify_checksum=0 trusts UDP checksum and skips expensive userspace checksum validation on receive.
# batch=128 drains packet bursts per select() wakeup and reduces syscall/loop overhead.
VIRA7_DEFAULT_CHECKSUM=1
VIRA7_DEFAULT_VERIFY_CHECKSUM=0
VIRA7_DEFAULT_BATCH=128

HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
HAPROXY_BACKUP_DIR="/etc/haproxy/gretun-backups"
HAPROXY_MAXCONN=500000
HAPROXY_NOFILE_LIMIT=1048576

# Color/theme helpers
if [ -t 1 ]; then
  C_RESET='\033[0m'
  C_BOLD='\033[1m'
  C_DIM='\033[2m'
  C_RED='\033[31m'
  C_GREEN='\033[32m'
  C_YELLOW='\033[33m'
  C_BLUE='\033[34m'
  C_MAGENTA='\033[35m'
  C_CYAN='\033[36m'
  C_WHITE='\033[37m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_MAGENTA=''; C_CYAN=''; C_WHITE=''
fi

ok_msg() { echo -e "${C_GREEN}[OK]${C_RESET} $*"; }
warn_msg() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err_msg() { echo -e "${C_RED}[ERR]${C_RESET} $*"; }
info_msg() { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }

is_main_menu_token() { [ "${1:-}" = "00" ]; }
return_main_msg() { echo -e "${C_CYAN}Returning to main menu...${C_RESET}"; }

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
  fi
}

detect_local_public_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'
}

validate_ipv4() {
  local ip="${1:-}"
  local IFS=.
  local -a octets
  [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  read -r -a octets <<< "$ip"
  [ "${#octets[@]}" -eq 4 ] || return 1
  local o
  for o in "${octets[@]}"; do
    [[ "$o" =~ ^[0-9]+$ ]] || return 1
    [ "$o" -ge 0 ] && [ "$o" -le 255 ] || return 1
  done
}

list_local_ipv4s() {
  ip -o -4 addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print "  - " a[1] " on " $2}' || true
}

local_ipv4_is_assigned() {
  local want="$1"
  ip -o -4 addr show scope global 2>/dev/null | awk -v want="$want" '{split($4,a,"/"); if (a[1] == want) found=1} END{exit found ? 0 : 1}'
}

prompt_local_tunnel_ip() {
  local default_ip="${1:-}"
  local prompt_label="${2:-LOCAL server IPv4 for this tunnel}"
  local input detected listed_ips

  detected="$(detect_local_public_ip || true)"
  [ -n "$default_ip" ] || default_ip="$detected"

  echo "Available local IPv4 addresses on this server:"
  listed_ips="$(list_local_ipv4s)"
  if [ -n "$listed_ips" ]; then
    echo "$listed_ips"
  else
    echo "  none detected by iproute2"
  fi
  echo "Detected default IPv4: ${detected:-UNKNOWN}"
  echo

  if [ -n "$default_ip" ]; then
    read -rp "$prompt_label [$default_ip] (00=menu): " input
    if is_main_menu_token "$input"; then return_main_msg; return 99; fi
    input="${input:-$default_ip}"
  else
    read -rp "$prompt_label (00=menu): " input
    if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  fi

  if ! validate_ipv4 "$input"; then
    echo "Invalid IPv4 address: $input"
    return 1
  fi

  LOCAL_PUBLIC_IP="$input"
}

prompt_remote_public_ip() {
  local default_ip="${1:-}"
  local input
  if [ -n "$default_ip" ]; then
    read -rp "Enter REMOTE server Public IPv4 [$default_ip] (00=menu): " input
    if is_main_menu_token "$input"; then return_main_msg; return 99; fi
    REMOTE_PUBLIC_IP="${input:-$default_ip}"
  else
    read -rp "Enter REMOTE server Public IPv4 (00=menu): " REMOTE_PUBLIC_IP
    if is_main_menu_token "$REMOTE_PUBLIC_IP"; then return_main_msg; return 99; fi
  fi
  if ! validate_ipv4 "$REMOTE_PUBLIC_IP"; then
    echo "Invalid remote IPv4 address: ${REMOTE_PUBLIC_IP:-empty}"
    return 1
  fi
}

show_header() {
  local title="${1:-Tunnel Management}"
  local ip_addr
  ip_addr="$(detect_local_public_ip || true)"
  clear 2>/dev/null || true
  echo -e "${C_CYAN}${C_BOLD}╔══════════════════════════════════════════════════════╗${C_RESET}"
  printf "${C_CYAN}${C_BOLD}║${C_RESET} %-52s ${C_CYAN}${C_BOLD}║${C_RESET}
" "$title"
  printf "${C_CYAN}${C_BOLD}║${C_RESET} Local public IP: %-35s ${C_CYAN}${C_BOLD}║${C_RESET}
" "${ip_addr:-UNKNOWN}"
  echo -e "${C_CYAN}${C_BOLD}╚══════════════════════════════════════════════════════╝${C_RESET}"
  echo
}

pause() {
  read -rp "Press Enter to continue..." _
}

validate_tunnel_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[0-9]+$ ]] || return 1
  [ "$id" -ge 1 ] && [ "$id" -le 254 ]
}

validate_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

prompt_tunnel_id() {
  local prompt="${1:-Enter tunnel number [1-254]: }"
  read -rp "$prompt" TUNNEL_ID
  if is_main_menu_token "$TUNNEL_ID"; then return_main_msg; return 99; fi
  if ! validate_tunnel_id "$TUNNEL_ID"; then
    echo "Invalid tunnel number. Use a number from 1 to 254."
    return 1
  fi
}

prompt_role() {
  echo "1) Iran / local-side role"
  echo "2) Kharej / remote-side role"
  echo
  read -rp "Select server role [1-2] (00=menu): " ROLE
  if is_main_menu_token "$ROLE"; then return_main_msg; return 99; fi
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "Invalid selection"
    return 1
  fi
}

ask_tunnel_type() {
  echo "Select tunnel type:"
  echo "1) Normal GRE tunnel"
  echo "2) WireGuard tunnel"
  echo "3) Vira7 UDP-TUN tunnel"
  echo
  read -rp "Choose [1-3] (00=menu): " TUNNEL_TYPE_CHOICE
  if is_main_menu_token "$TUNNEL_TYPE_CHOICE"; then return_main_msg; return 99; fi
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE="gre" ;;
    2) SELECTED_TUNNEL_TYPE="wireguard" ;;
    3) SELECTED_TUNNEL_TYPE="vira7" ;;
    *) echo "Invalid tunnel type"; return 1 ;;
  esac
}

confirm_yes() {
  local prompt="$1"
  local answer
  read -rp "$prompt [y/N] (00=menu): " answer
  if is_main_menu_token "$answer"; then return_main_msg; return 99; fi
  case "$answer" in
    [Yy]*) return 0 ;;
    *) return 1 ;;
  esac
}

confirm_default_yes() {
  local prompt="$1"
  local answer
  read -rp "$prompt [Y/n] (00=menu): " answer
  if is_main_menu_token "$answer"; then return_main_msg; return 99; fi
  case "$answer" in
    [Nn]*) return 1 ;;
    *) return 0 ;;
  esac
}

write_var() {
  local name="$1"
  local value="${2:-}"
  printf '%s=%q\n' "$name" "$value"
}

# -----------------------------
# Shared UDP port + firewall helpers
# -----------------------------
udp_port_is_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "(^|[:.])$port$"
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:.])$port$"
    return $?
  fi
  return 1
}

udp_port_in_saved_configs() {
  local want="$1"
  local current_type="${2:-}"
  local current_id="${3:-}"
  local f id

  if [ -d "$WG_META_DIR" ]; then
    for f in "$WG_META_DIR"/tunnel-*.conf; do
      [ -e "$f" ] || continue
      id="${f##*/tunnel-}"; id="${id%.conf}"
      [ "$current_type" = "wireguard" ] && [ "$id" = "$current_id" ] && continue
      (
        # shellcheck disable=SC1090
        source "$f" 2>/dev/null || exit 1
        [ "${LOCAL_WG_PORT:-}" = "$want" ]
      ) && return 0
    done
  fi

  if [ -d "$VIRA7_CONFIG_DIR" ]; then
    for f in "$VIRA7_CONFIG_DIR"/tunnel-*.conf; do
      [ -e "$f" ] || continue
      id="${f##*/tunnel-}"; id="${id%.conf}"
      [ "$current_type" = "vira7" ] && [ "$id" = "$current_id" ] && continue
      (
        # shellcheck disable=SC1090
        source "$f" 2>/dev/null || exit 1
        [ "${VIRA7_PORT:-${port:-}}" = "$want" ]
      ) && return 0
    done
  fi

  return 1
}

auto_select_udp_port() {
  local base_port="$1"
  local existing_port="${2:-}"
  local current_type="${3:-}"
  local current_id="${4:-}"
  local candidate

  # If this tunnel already had a saved port, keep it only when it is really free.
  # This prevents WireGuard "Address already in use" when a stale process/interface still owns the old port.
  if [ -n "$existing_port" ]; then
    if ! udp_port_in_saved_configs "$existing_port" "$current_type" "$current_id" && ! udp_port_is_listening "$existing_port"; then
      echo "$existing_port"
      return 0
    fi
    warn_msg "Saved UDP port $existing_port is busy; selecting the next free UDP port..." >&2
  fi

  candidate="$base_port"
  while [ "$candidate" -le 65535 ]; do
    if ! udp_port_in_saved_configs "$candidate" "$current_type" "$current_id" && ! udp_port_is_listening "$candidate"; then
      echo "$candidate"
      return 0
    fi
    candidate=$((candidate + 1))
  done

  echo "No free UDP port found from base $base_port" >&2
  return 1
}

firewall_allow_udp_port_and_ip() {
  local label="$1"
  local port="$2"
  local peer_ip="${3:-}"
  local peer_port="${4:-$port}"
  local ifc="${5:-}"

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$port" -j ACCEPT || true
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      iptables -C INPUT -s "$peer_ip" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$peer_ip" -p udp --dport "$port" -j ACCEPT || true
      iptables -C OUTPUT -d "$peer_ip" -p udp --dport "$peer_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -p udp --dport "$peer_port" -j ACCEPT || true
      # Also allow the peer IP generally, because some providers/firewalls filter before interface rules.
      iptables -C INPUT -s "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$peer_ip" -j ACCEPT || true
      iptables -C OUTPUT -d "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -j ACCEPT || true
    fi
    if [ -n "$ifc" ]; then
      iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -j ACCEPT || true
      iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -j ACCEPT || true
      iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ifc" -j ACCEPT || true
      iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$ifc" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port/udp" >/dev/null 2>&1 || true
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      ufw allow from "$peer_ip" >/dev/null 2>&1 || true
      ufw allow out to "$peer_ip" port "$peer_port" proto udp >/dev/null 2>&1 || true
    fi
    if [ -n "$ifc" ]; then
      ufw allow in on "$ifc" >/dev/null 2>&1 || true
    fi
  fi

  echo "Firewall opened for $label: UDP $port, peer ${peer_ip:-any}, interface ${ifc:-none}"
}

firewall_allow_ip_peer() {
  local label="$1"
  local peer_ip="${2:-}"
  local ifc="${3:-}"
  peer_ip="${peer_ip%%/*}"
  [ -n "$peer_ip" ] || return 0
  validate_ipv4 "$peer_ip" || return 0

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -s "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$peer_ip" -j ACCEPT || true
    iptables -C OUTPUT -d "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -j ACCEPT || true
    if [ -n "$ifc" ]; then
      iptables -C INPUT -i "$ifc" -s "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -s "$peer_ip" -j ACCEPT || true
      iptables -C OUTPUT -o "$ifc" -d "$peer_ip" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -d "$peer_ip" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow from "$peer_ip" >/dev/null 2>&1 || true
    ufw allow out to "$peer_ip" >/dev/null 2>&1 || true
    if [ -n "$ifc" ]; then
      ufw allow in on "$ifc" from "$peer_ip" >/dev/null 2>&1 || true
    fi
  fi

  echo "Firewall opened for $label IP: $peer_ip, interface ${ifc:-none}"
}

# -----------------------------
# GRE helpers
# -----------------------------
gre_iface() {
  echo "gre$1"
}

gre_config_file() {
  echo "$GRE_CONFIG_DIR/tunnel-$1.conf"
}

gre_service_name() {
  echo "gre-tunnel@$1.service"
}

gre_print_service_failure() {
  local id="$1"
  local svc
  svc="$(gre_service_name "$id")"
  echo "GRE service failed to start: $svc" >&2
  echo "Useful debug commands:" >&2
  echo "  systemctl status $svc --no-pager -l" >&2
  echo "  journalctl -xeu $svc --no-pager" >&2
  echo >&2
  systemctl status "$svc" --no-pager -l 2>/dev/null || true
  journalctl -u "$svc" -n 30 --no-pager 2>/dev/null || true
}

gre_print_ip_plan() {
  local id="$1"
  echo "Normal GRE tunnel $id plan:"
  echo "  Interface       : gre$id"
  echo "  Config file     : $GRE_CONFIG_DIR/tunnel-$id.conf"
  echo "  Service         : gre-tunnel@$id.service"
  echo "  GRE key         : $id"
  echo "  Iran role IP    : 10.10.$id.1/30"
  echo "  Kharej role IP  : 10.10.$id.2/30"
}

gre_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.10.$id.1"
  else
    echo "10.10.$id.2"
  fi
}

gre_remote_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.10.$id.2"
  else
    echo "10.10.$id.1"
  fi
}

gre_save_config() {
  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Cannot save GRE config: invalid tunnel number" >&2
    return 1
  fi

  mkdir -p "$GRE_CONFIG_DIR"
  local file
  file="$(gre_config_file "$TUNNEL_ID")"

  {
    write_var TUNNEL_TYPE "gre"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var TUN_IFACE "$TUN_IFACE"
    write_var TUN_KEY "$TUN_KEY"
    write_var ROLE "$ROLE"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_GRE_IP "$LOCAL_GRE_IP"
    write_var REMOTE_GRE_IP "$REMOTE_GRE_IP"
  } > "$file"
  chmod 600 "$file"
  echo "Saved GRE tunnel $TUNNEL_ID configuration to $file"
}

gre_load_config() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    return 1
  fi

  # Do not let values loaded for a previous GRE tunnel leak into this one.
  # This was especially dangerous for TUN_KEY: selecting gre3 after gre1
  # could incorrectly reuse key 1 and make the kernel report "File exists".
  TUN_IFACE=""
  TUN_KEY=""
  ROLE=""
  LOCAL_PUBLIC_IP=""
  REMOTE_PUBLIC_IP=""
  LOCAL_GRE_IP=""
  REMOTE_GRE_IP=""

  local file
  file="$(gre_config_file "$id")"
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    TUN_IFACE="$(gre_iface "$id")"
    # GRE keys are intentionally fixed to the tunnel number in this manager.
    # Ignore stale/incorrect values from older config files.
    TUN_KEY="$id"
    return 0
  fi

  # Backward compatibility for old single-tunnel installs.
  if [ "$id" = "1" ] && [ -f "$GRE_LEGACY_CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$GRE_LEGACY_CONF_FILE"
    TUNNEL_ID="1"
    TUN_IFACE="gre1"
    TUN_KEY="1"
    return 0
  fi

  return 1
}

gre_collect_ids() {
  {
    if [ -d "$GRE_CONFIG_DIR" ]; then
      local f id
      for f in "$GRE_CONFIG_DIR"/tunnel-*.conf; do
        [ -e "$f" ] || continue
        id="${f##*/tunnel-}"
        id="${id%.conf}"
        validate_tunnel_id "$id" && echo "$id"
      done
    fi
    if [ -f "$GRE_LEGACY_CONF_FILE" ]; then
      echo "1"
    fi
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^gre[0-9]+$' | sed 's/^gre//' || true
  } | sort -n -u
}

gre_list_tunnels() {
  echo "Normal GRE tunnels:"
  local ids id ifc file service_state remote
  ids="$(gre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "  none"
    return 0
  fi

  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(gre_iface "$id")"
    file="$(gre_config_file "$id")"
    service_state="not-installed"
    remote="unknown"

    if gre_load_config "$id"; then
      remote="${REMOTE_PUBLIC_IP:-unknown}"
    fi

    if command -v systemctl >/dev/null 2>&1; then
      if [ -f "$GRE_SERVICE_TEMPLATE" ]; then
        service_state="template-installed"
      fi
      if systemctl is-enabled --quiet "$(gre_service_name "$id")" 2>/dev/null; then
        service_state="enabled"
      fi
      if systemctl is-active --quiet "$(gre_service_name "$id")" 2>/dev/null; then
        service_state="active"
      fi
    fi

    if ip link show "$ifc" >/dev/null 2>&1; then
      echo "  - tunnel $id | iface $ifc | active | remote public: $remote | config: $file | service: $service_state"
    else
      echo "  - tunnel $id | iface $ifc | inactive | remote public: $remote | config: $file | service: $service_state"
    fi
  done <<< "$ids"
}

gre_create_tunnel() {
  local interactive=${1:-0}

  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Invalid tunnel number. Use 1 to 254." >&2
    return 1
  fi

  TUN_IFACE="$(gre_iface "$TUNNEL_ID")"
  # Always use the tunnel number as the GRE key. Never inherit a key from
  # another tunnel that was loaded earlier in the same manager session.
  TUN_KEY="$TUNNEL_ID"

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  if [ -z "${LOCAL_PUBLIC_IP:-}" ]; then
    echo "Failed to detect local public IPv4" >&2
    return 1
  fi

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
    LOCAL_GRE_IP="10.10.$TUNNEL_ID.1/30"
    REMOTE_GRE_IP="10.10.$TUNNEL_ID.2"
  else
    SERVER_ROLE="KHAREJ"
    LOCAL_GRE_IP="10.10.$TUNNEL_ID.2/30"
    REMOTE_GRE_IP="10.10.$TUNNEL_ID.1"
  fi

  echo "[*] Local server public IP: $LOCAL_PUBLIC_IP"
  echo "[*] Tunnel type: Normal GRE"
  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $TUN_IFACE"
  echo "[*] GRE key: $TUN_KEY"
  echo "[*] Server role: $SERVER_ROLE"
  echo "[*] Remote server public IP: $REMOTE_PUBLIC_IP"

  if ! local_ipv4_is_assigned "$LOCAL_PUBLIC_IP"; then
    echo "Selected GRE local/bind IP is not assigned on this server: $LOCAL_PUBLIC_IP" >&2
    echo "Available local IPv4 addresses:" >&2
    list_local_ipv4s >&2
    return 1
  fi

  modprobe gre || true
  modprobe ip_gre || true

  # Remove only this GRE interface so other GRE/WireGuard tunnels stay intact.
  ip link set "$TUN_IFACE" down 2>/dev/null || true
  ip tunnel del "$TUN_IFACE" 2>/dev/null || true

  if ! ip tunnel add "$TUN_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$TUN_KEY" ttl 255; then
    echo "Failed to create $TUN_IFACE (local=$LOCAL_PUBLIC_IP remote=$REMOTE_PUBLIC_IP key=$TUN_KEY)." >&2
    echo "Another GRE interface may already use the same local/remote/key tuple." >&2
    echo "Current GRE interfaces:" >&2
    ip -d tunnel show 2>/dev/null >&2 || true
    return 1
  fi

  if ! ip addr replace "$LOCAL_GRE_IP" dev "$TUN_IFACE"; then
    echo "Failed to assign $LOCAL_GRE_IP to $TUN_IFACE" >&2
    ip tunnel del "$TUN_IFACE" 2>/dev/null || true
    return 1
  fi

  if ! ip link set "$TUN_IFACE" mtu 1390 || ! ip link set "$TUN_IFACE" up; then
    echo "Failed to bring $TUN_IFACE up" >&2
    ip tunnel del "$TUN_IFACE" 2>/dev/null || true
    return 1
  fi

  if ! ip link show "$TUN_IFACE" >/dev/null 2>&1; then
    echo "GRE interface creation failed" >&2
    ip tunnel del "$TUN_IFACE" 2>/dev/null || true
    return 1
  fi

  enable_ip_forward

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -s "$REMOTE_PUBLIC_IP" -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -s "$REMOTE_PUBLIC_IP" -j ACCEPT
    iptables -C OUTPUT -p gre -d "$REMOTE_PUBLIC_IP" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -d "$REMOTE_PUBLIC_IP" -j ACCEPT
  fi
  firewall_allow_ip_peer "GRE tunnel $TUNNEL_ID remote public" "$REMOTE_PUBLIC_IP" "$TUN_IFACE"
  firewall_allow_ip_peer "GRE tunnel $TUNNEL_ID remote inner" "$REMOTE_GRE_IP" "$TUN_IFACE"

  echo "[OK] GRE tunnel created as $TUN_IFACE"
  echo "Local GRE IP : $LOCAL_GRE_IP"
  echo "Remote GRE IP: $REMOTE_GRE_IP"

  if [ "$interactive" -eq 1 ]; then
    # Fewer questions: save and enable persistence automatically.
    gre_save_config
    if [ -f "$(gre_config_file "$TUNNEL_ID")" ] && command -v systemctl >/dev/null 2>&1; then
      if gre_install_service "$TUNNEL_ID"; then
        echo "GRE persistence enabled for $(gre_service_name "$TUNNEL_ID")."
      else
        echo "Failed to enable GRE persistence. Tunnel is currently created, but it may not survive reboot." >&2
      fi
    fi
  fi
}

gre_menu_config_tunnel() {
  show_header "Configure Normal GRE Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter GRE tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  if gre_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
  fi
  ROLE="$selected_role"

  echo
  gre_print_ip_plan "$TUNNEL_ID"
  echo
  echo "For servers with multiple IP addresses, choose the exact LOCAL IPv4 that should be used by this tunnel."
  echo "GRE will bind to this address with: ip tunnel ... local <LOCAL_IP>"
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for GRE bind" || return
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return

  echo
  gre_create_tunnel 1 || echo "GRE tunnel creation failed"
}

gre_check_one_tunnel() {
  local id="$1"
  local ifc
  ifc="$(gre_iface "$id")"

  echo
  echo "GRE tunnel $id ($ifc) status"
  echo "--------------------------------"
  if ip link show "$ifc" >/dev/null 2>&1; then
    echo "$ifc: exists"
    ip -br addr show "$ifc" 2>/dev/null || true
    local remote_public_of_tun
    remote_public_of_tun=$(ip tunnel show "$ifc" 2>/dev/null | awk -F'remote ' '{print $2}' | awk '{print $1}') || true
    if [ -n "$remote_public_of_tun" ]; then
      echo "Tunnel remote public IP: $remote_public_of_tun"
      if gre_load_config "$id" && [ -n "${LOCAL_PUBLIC_IP:-}" ]; then echo "Tunnel local public IP : $LOCAL_PUBLIC_IP"; fi
      echo "Pinging remote public IP (1 try)..."
      ping -c 1 -W 1 "$remote_public_of_tun" 2>&1 || true
    fi

    if gre_load_config "$id" && [ -n "${REMOTE_GRE_IP:-}" ]; then
      echo "Pinging remote GRE inner IP $REMOTE_GRE_IP (4 tries)..."
      if ping -c 4 "$REMOTE_GRE_IP" >/tmp/gre_ping_$$.log 2>&1; then
        cat /tmp/gre_ping_$$.log
        echo "GRE inner tunnel is UP"
      else
        cat /tmp/gre_ping_$$.log
        echo "GRE inner tunnel seems DOWN"
      fi
      rm -f /tmp/gre_ping_$$.log
    else
      echo "No saved inner GRE IP for tunnel $id; save config first for inner ping test."
    fi
  else
    echo "$ifc interface not found"
  fi
}

gre_status_check() {
  show_header "Normal GRE Tunnel Status"
  gre_list_tunnels
  echo
  read -rp "Enter GRE tunnel number to check, leave empty for all, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi

  if [ -n "$selected_id" ]; then
    if ! validate_tunnel_id "$selected_id"; then
      echo "Invalid tunnel number. Use 1 to 254."
      return
    fi
    gre_check_one_tunnel "$selected_id"
    return
  fi

  local ids id
  ids="$(gre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No GRE tunnels found."
    return
  fi
  while IFS= read -r id; do
    [ -n "$id" ] && gre_check_one_tunnel "$id"
  done <<< "$ids"
}

gre_remove_one_tunnel() {
  local id="$1"
  local ifc file
  ifc="$(gre_iface "$id")"
  file="$(gre_config_file "$id")"

  echo "Removing GRE tunnel $id ($ifc)..."

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$(gre_service_name "$id")" 2>/dev/null || true
  fi

  ip link set dev "$ifc" down 2>/dev/null || true
  if ip tunnel del "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip tunnel del'"
  elif ip link delete "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip link delete'"
  else
    echo "- $ifc was not found or could not be removed automatically."
  fi

  rm -f "$file"
  if [ "$id" = "1" ]; then
    rm -f "$GRE_LEGACY_CONF_FILE"
  fi
  echo "- Config removed: $file"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
  echo "[OK] GRE tunnel $id removed."
}

gre_remove_menu() {
  show_header "Remove Normal GRE Tunnel"
  gre_list_tunnels
  echo
  local ids selected_id
  ids="$(gre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No GRE tunnels found."
    return
  fi
  read -rp "Enter GRE tunnel number to remove, for example 1, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "GRE tunnel $selected_id was not found in the list."
    return
  fi
  if confirm_yes "Are you sure you want to remove GRE tunnel $selected_id completely?"; then
    gre_remove_one_tunnel "$selected_id"
  else
    echo "Cancelled."
  fi
}

gre_install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "Cannot install GRE service: invalid tunnel number" >&2
    return 1
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available on this system; cannot install GRE service." >&2
    return 1
  fi

  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"

  cat > "$GRE_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=Normal GRE Tunnel %i Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start-gre %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SERVICE

  if [ -f "$GRE_LEGACY_SERVICE_UNIT" ]; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$GRE_LEGACY_SERVICE_UNIT"
  fi

  systemctl daemon-reload
  systemctl enable "$(gre_service_name "$id")" || return 1
  if systemctl restart "$(gre_service_name "$id")"; then
    echo "GRE service installed, enabled, and started for boot ($(gre_service_name "$id"))"
    return 0
  fi
  gre_print_service_failure "$id"
  return 1
}

gre_service_start() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "GRE service start needs a tunnel number, e.g. --service start-gre 1" >&2
    return 1
  fi

  if gre_load_config "$id"; then
    echo "Starting GRE tunnel $id from saved config..."
    gre_create_tunnel 0
  else
    echo "No saved GRE configuration for tunnel $id at $(gre_config_file "$id")." >&2
    return 1
  fi
}

# -----------------------------
# WireGuard helpers
# -----------------------------
wg_iface_name() {
  echo "${WG_IFACE_PREFIX}$1"
}

wg_meta_file() {
  echo "$WG_META_DIR/tunnel-$1.conf"
}

wg_config_file() {
  echo "$WG_CONFIG_DIR/$(wg_iface_name "$1").conf"
}

wg_private_key_file() {
  echo "$WG_KEY_DIR/tunnel-$1.private"
}

wg_public_key_file() {
  echo "$WG_KEY_DIR/tunnel-$1.public"
}

wg_default_port() {
  local id="$1"
  echo $((51800 + id))
}

wg_transport_iface() {
  local id="$1"
  echo "gre$id"
}

wg_default_public_endpoint_ip() {
  printf '%s' "${REMOTE_PUBLIC_IP:-}"
}

wg_auto_endpoint_ip() {
  case "${WG_ENDPOINT_MODE:-public}" in
    gre|vira7) printf '%s' "${WG_ENDPOINT_IP:-}" ;;
    *) wg_default_public_endpoint_ip ;;
  esac
}

wg_service_name() {
  echo "wg-quick@$(wg_iface_name "$1").service"
}

normalize_wg_public_key() {
  local key="${1:-}"
  # Accept either the raw key or a copied config line like: PublicKey = xxx=
  key="$(printf '%s' "$key" | sed -E 's/^[[:space:]]*[Pp]ublic[Kk]ey[[:space:]]*=[[:space:]]*//; s/[[:space:]]*$//')"
  # WireGuard keys never contain whitespace; remove accidental pasted spaces, tabs, or CR/LF.
  key="$(printf '%s' "$key" | tr -d '[:space:]')"
  printf '%s' "$key"
}

validate_wg_public_key() {
  local key
  key="$(normalize_wg_public_key "${1:-}")"
  # WireGuard public keys are 44-character base64 strings that normally end with '='.
  [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

wg_print_service_failure() {
  local id="$1"
  local svc
  svc="$(wg_service_name "$id")"
  echo "WireGuard service failed to start: $svc" >&2
  echo "Useful debug commands:" >&2
  echo "  systemctl status $svc --no-pager -l" >&2
  echo "  journalctl -xeu $svc --no-pager" >&2
  echo >&2
  if command -v systemctl >/dev/null 2>&1; then
    systemctl status "$svc" --no-pager -l 2>/dev/null || true
  fi
}

wg_print_ip_plan() {
  local id="$1"
  local port
  port="$(wg_default_port "$id")"
  echo "WireGuard tunnel $id plan:"
  echo "  Interface       : $(wg_iface_name "$id")"
  echo "  WG config file  : $(wg_config_file "$id")"
  echo "  Meta file       : $(wg_meta_file "$id")"
  echo "  Service         : $(wg_service_name "$id")"
  echo "  Default UDP port: $port (auto-increments if busy)"
  echo "  Iran role IP    : 10.20.$id.1/30"
  echo "  Kharej role IP  : 10.20.$id.2/30"
  echo "  GRE transport   : if gre$id is up/reachable, WireGuard can use 10.10.$id.x"
  echo "  Vira7 transport : if vira7$id is up/reachable, WireGuard can use 10.71.$id.x"
  echo
  echo "GRE uses 10.10.N.x, WireGuard uses 10.20.N.x, Vira7 uses 10.71.N.x, so they do not conflict."
}

wg_ensure_tools() {
  if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
    return 0
  fi

  echo "WireGuard tools are not installed. Installing automatically..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard wireguard-tools iproute2 iptables
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools iproute iptables
  elif command -v yum >/dev/null 2>&1; then
    yum install -y wireguard-tools iproute iptables
  else
    echo "No supported package manager found. Install WireGuard manually and run the script again." >&2
    return 1
  fi

  command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1
}

wg_generate_keys() {
  local id="$1"
  mkdir -p "$WG_KEY_DIR"
  chmod 700 "$WG_META_DIR" "$WG_KEY_DIR" 2>/dev/null || true

  local private public
  private="$(wg_private_key_file "$id")"
  public="$(wg_public_key_file "$id")"

  if [ ! -s "$private" ]; then
    umask 077
    wg genkey > "$private"
    wg pubkey < "$private" > "$public"
    chmod 600 "$private"
    chmod 644 "$public"
    echo "Generated new WireGuard key pair for tunnel $id."
  elif [ ! -s "$public" ]; then
    wg pubkey < "$private" > "$public"
    chmod 644 "$public"
  fi
}

wg_save_meta() {
  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Cannot save WireGuard meta: invalid tunnel number" >&2
    return 1
  fi

  mkdir -p "$WG_META_DIR"
  chmod 700 "$WG_META_DIR" 2>/dev/null || true
  local file
  file="$(wg_meta_file "$TUNNEL_ID")"

  {
    write_var TUNNEL_TYPE "wireguard"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var WG_IFACE "$WG_IFACE"
    write_var ROLE "$ROLE"
    write_var SERVER_ROLE "${SERVER_ROLE:-}"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_WG_IP "$LOCAL_WG_IP"
    write_var REMOTE_WG_IP "$REMOTE_WG_IP"
    write_var LOCAL_WG_PORT "$LOCAL_WG_PORT"
    write_var REMOTE_WG_PORT "$REMOTE_WG_PORT"
    write_var WG_ENDPOINT_MODE "${WG_ENDPOINT_MODE:-public}"
    write_var WG_ENDPOINT_IP "${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-}}"
    write_var WG_TRANSPORT_IFACE "${WG_TRANSPORT_IFACE:-}"
    write_var WG_MTU "${WG_MTU:-1420}"
    write_var REMOTE_WG_PUBLIC_KEY "$REMOTE_WG_PUBLIC_KEY"
    write_var WG_PENDING "${WG_PENDING:-0}"
    write_var EXTRA_ALLOWED_IPS "$EXTRA_ALLOWED_IPS"
    write_var WG_CONFIG_FILE "$(wg_config_file "$TUNNEL_ID")"
    write_var WG_PRIVATE_KEY_FILE "$(wg_private_key_file "$TUNNEL_ID")"
    write_var WG_PUBLIC_KEY_FILE "$(wg_public_key_file "$TUNNEL_ID")"
  } > "$file"
  chmod 600 "$file"
  echo "Saved WireGuard tunnel $TUNNEL_ID metadata to $file"
}

wg_load_meta() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    return 1
  fi
  local file
  file="$(wg_meta_file "$id")"
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    WG_IFACE="${WG_IFACE:-$(wg_iface_name "$id")}"
    return 0
  fi
  return 1
}

wg_collect_ids() {
  {
    if [ -d "$WG_META_DIR" ]; then
      local f id
      for f in "$WG_META_DIR"/tunnel-*.conf; do
        [ -e "$f" ] || continue
        id="${f##*/tunnel-}"
        id="${id%.conf}"
        validate_tunnel_id "$id" && echo "$id"
      done
    fi
    if [ -d "$WG_CONFIG_DIR" ]; then
      local cf base id2
      for cf in "$WG_CONFIG_DIR"/${WG_IFACE_PREFIX}*.conf; do
        [ -e "$cf" ] || continue
        base="${cf##*/}"
        base="${base%.conf}"
        id2="${base#$WG_IFACE_PREFIX}"
        validate_tunnel_id "$id2" && echo "$id2"
      done
    fi
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${WG_IFACE_PREFIX}[0-9]+$" | sed "s/^${WG_IFACE_PREFIX}//" || true
  } | sort -n -u
}

wg_list_tunnels() {
  echo "WireGuard tunnels:"
  local ids id ifc meta conf service_state remote port local_ip peer_state link_state endpoint_mode endpoint_ip
  ids="$(wg_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "  none"
    return 0
  fi

  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(wg_iface_name "$id")"
    meta="$(wg_meta_file "$id")"
    conf="$(wg_config_file "$id")"
    service_state="not-installed"
    remote="unknown"
    endpoint_mode="public"
    endpoint_ip="unknown"
    port="$(wg_default_port "$id")"
    local_ip="unknown"
    peer_state="peer-key: unknown"

    if wg_load_meta "$id"; then
      remote="${REMOTE_PUBLIC_IP:-unknown}"
      endpoint_mode="${WG_ENDPOINT_MODE:-public}"
      endpoint_ip="${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-unknown}}"
      port="${LOCAL_WG_PORT:-$port}"
      local_ip="${LOCAL_WG_IP:-unknown}"
      if [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
        peer_state="peer-key: set"
      else
        peer_state="peer-key: pending"
      fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-enabled --quiet "$(wg_service_name "$id")" 2>/dev/null; then
        service_state="enabled"
      fi
      if systemctl is-active --quiet "$(wg_service_name "$id")" 2>/dev/null; then
        service_state="active"
      fi
    fi

    if ip link show "$ifc" >/dev/null 2>&1; then
      link_state="active"
    else
      link_state="inactive"
    fi
    echo "  - tunnel $id | iface $ifc | $link_state | $peer_state | local IP: $local_ip | UDP: $port | endpoint: $endpoint_mode/$endpoint_ip | remote public: $remote | config: $conf | service: $service_state"
  done <<< "$ids"
}

wg_write_config() {
  local id="$1"
  local private_file conf allowed_ips private_key endpoint_ip endpoint_mode_note mtu_value
  private_file="$(wg_private_key_file "$id")"
  conf="$(wg_config_file "$id")"
  private_key="$(cat "$private_file")"
  allowed_ips="$REMOTE_WG_IP/32"
  endpoint_ip="$(wg_auto_endpoint_ip)"
  endpoint_mode_note="${WG_ENDPOINT_MODE:-public}"
  mtu_value="${WG_MTU:-1420}"
  case "$endpoint_mode_note" in
    gre|vira7) mtu_value="${WG_MTU:-1280}" ;;
  esac
  if [ -z "$endpoint_ip" ]; then
    echo "WireGuard endpoint IP is empty. Cannot write config." >&2
    return 1
  fi
  if [ -n "${EXTRA_ALLOWED_IPS:-}" ]; then
    allowed_ips="$allowed_ips, $EXTRA_ALLOWED_IPS"
  fi

  mkdir -p "$WG_CONFIG_DIR"
  chmod 700 "$WG_CONFIG_DIR" 2>/dev/null || true

  cat > "$conf" <<EOF_CONF
[Interface]
PrivateKey = $private_key
Address = $LOCAL_WG_IP
ListenPort = $LOCAL_WG_PORT
MTU = $mtu_value

[Peer]
PublicKey = $REMOTE_WG_PUBLIC_KEY
Endpoint = $endpoint_ip:$REMOTE_WG_PORT
AllowedIPs = $allowed_ips
PersistentKeepalive = 25
EOF_CONF
  chmod 600 "$conf"
  echo "WireGuard config written: $conf"
  echo "WireGuard endpoint mode: $endpoint_mode_note -> $endpoint_ip:$REMOTE_WG_PORT"
  echo "WireGuard MTU: $mtu_value"
}

wg_create_tunnel() {
  local interactive=${1:-0}

  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Invalid tunnel number. Use 1 to 254." >&2
    return 1
  fi

  wg_ensure_tools || return 1
  WG_IFACE="$(wg_iface_name "$TUNNEL_ID")"

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  if [ -z "${LOCAL_PUBLIC_IP:-}" ]; then
    echo "Failed to detect local public IPv4" >&2
    return 1
  fi

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
    LOCAL_WG_IP="10.20.$TUNNEL_ID.1/30"
    REMOTE_WG_IP="10.20.$TUNNEL_ID.2"
  else
    SERVER_ROLE="KHAREJ"
    LOCAL_WG_IP="10.20.$TUNNEL_ID.2/30"
    REMOTE_WG_IP="10.20.$TUNNEL_ID.1"
  fi

  LOCAL_WG_PORT="${LOCAL_WG_PORT:-$(wg_default_port "$TUNNEL_ID")}"
  REMOTE_WG_PORT="${REMOTE_WG_PORT:-$LOCAL_WG_PORT}"
  WG_ENDPOINT_MODE="${WG_ENDPOINT_MODE:-public}"
  WG_ENDPOINT_IP="${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-}}"
  WG_TRANSPORT_IFACE="${WG_TRANSPORT_IFACE:-}"
  if [ -z "${WG_MTU:-}" ]; then
    case "$WG_ENDPOINT_MODE" in
      gre|vira7) WG_MTU="1280" ;;
      *) WG_MTU="1420" ;;
    esac
  fi
  EXTRA_ALLOWED_IPS="${EXTRA_ALLOWED_IPS:-}"
  REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "${REMOTE_WG_PUBLIC_KEY:-}")"
  WG_PENDING=0

  wg_generate_keys "$TUNNEL_ID"
  local local_pub
  local_pub="$(cat "$(wg_public_key_file "$TUNNEL_ID")")"

  echo "[*] Local server public IP: $LOCAL_PUBLIC_IP"
  echo "[*] Tunnel type: WireGuard"
  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $WG_IFACE"
  echo "[*] Server role: $SERVER_ROLE"
  echo "[*] Local WireGuard IP: $LOCAL_WG_IP"
  echo "[*] Remote WireGuard IP: $REMOTE_WG_IP"
  echo "[*] Local UDP ListenPort: $LOCAL_WG_PORT"
  echo "[*] WireGuard endpoint mode: ${WG_ENDPOINT_MODE:-public}"
  echo "[*] WireGuard endpoint: ${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-UNKNOWN}}:$REMOTE_WG_PORT"
  echo "[*] WireGuard MTU: ${WG_MTU:-1420}"
  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
    echo "[*] WireGuard transport: inside GRE interface ${WG_TRANSPORT_IFACE:-gre$TUNNEL_ID}"
  elif [ "${WG_ENDPOINT_MODE:-public}" = "vira7" ]; then
    echo "[*] WireGuard transport: inside Vira7 interface ${WG_TRANSPORT_IFACE:-vira7$TUNNEL_ID}"
  fi
  echo
  echo "Your LOCAL WireGuard public key for tunnel $TUNNEL_ID:"
  echo "$local_pub"
  echo

  if [ "$interactive" -eq 1 ] && [ -z "$REMOTE_WG_PUBLIC_KEY" ]; then
    echo "Paste the OTHER server public key here."
    echo "If you do not have it yet, press Enter; this tunnel will be saved as pending."
    read -rp "REMOTE WireGuard public key (00=menu): " REMOTE_WG_PUBLIC_KEY
    if is_main_menu_token "$REMOTE_WG_PUBLIC_KEY"; then return_main_msg; return 99; fi
    REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "$REMOTE_WG_PUBLIC_KEY")"
    echo
  fi

  if [ -z "$REMOTE_WG_PUBLIC_KEY" ]; then
    WG_PENDING=1
    echo "Remote public key is empty."
    echo "Saved as PENDING. Nothing will be started yet, so ping will not work until you add the peer key."
    wg_save_meta
    echo
    echo "Next step on the OTHER server: create the same WireGuard tunnel number and copy its public key."
    echo "Then run this script again on this server with the same tunnel number and paste that peer key."
    echo "Local public key file: $(wg_public_key_file "$TUNNEL_ID")"
    return 0
  fi

  if ! validate_wg_public_key "$REMOTE_WG_PUBLIC_KEY"; then
    WG_PENDING=1
    echo "The remote public key you entered is not valid after cleanup." >&2
    echo "Detected length: ${#REMOTE_WG_PUBLIC_KEY}. Expected: 44 characters, ending with '='." >&2
    echo "Saved as PENDING. Paste only the peer public key, or a line like: PublicKey = xxxxx=" >&2
    REMOTE_WG_PUBLIC_KEY=""
    wg_save_meta
    return 0
  fi

  if [ "$REMOTE_WG_PUBLIC_KEY" = "$local_pub" ]; then
    WG_PENDING=1
    echo "You pasted this server's own public key, not the OTHER server public key." >&2
    echo "Saved as PENDING. Run the script on the other server and paste its public key here." >&2
    REMOTE_WG_PUBLIC_KEY=""
    wg_save_meta
    return 0
  fi

  wg_write_config "$TUNNEL_ID"
  wg_save_meta
  enable_ip_forward
  wg_apply_firewall_rules "$TUNNEL_ID"

  # Start through one path only. Prefer systemd for persistence; otherwise use wg-quick directly.
  if command -v systemctl >/dev/null 2>&1; then
    if wg_install_service "$TUNNEL_ID"; then
      echo "[OK] WireGuard tunnel created and started as $WG_IFACE"
    else
      wg_print_service_failure "$TUNNEL_ID"
      return 1
    fi
  else
    wg-quick down "$WG_IFACE" >/dev/null 2>&1 || true
    wg-quick up "$WG_IFACE"
    echo "[OK] WireGuard tunnel created and started as $WG_IFACE"
  fi

  echo "Local WG IP : $LOCAL_WG_IP"
  echo "Remote WG IP: $REMOTE_WG_IP"
  echo
  echo "After both sides are started, test:"
  echo "  ping $REMOTE_WG_IP"
}

wg_choose_auto_endpoint() {
  local id="$1"
  local role="$2"
  local gre_ifc gre_remote_ip gre_ok
  local vira_ifc vira_remote_ip vira_ok
  local choice

  gre_ifc="$(wg_transport_iface "$id")"
  gre_remote_ip="$(gre_remote_inner_ip_for_role "$id" "$role")"
  vira_ifc="$(vira7_iface_name "$id")"
  vira_remote_ip="$(vira7_remote_inner_ip_for_role "$id" "$role")"

  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="${REMOTE_PUBLIC_IP:-}"
  WG_TRANSPORT_IFACE=""

  gre_ok=0
  if ip link show "$gre_ifc" >/dev/null 2>&1; then
    gre_ok=1
  fi

  vira_ok=0
  if ip link show "$vira_ifc" >/dev/null 2>&1; then
    vira_ok=1
  fi

  if [ "$gre_ok" -eq 1 ] && [ "$vira_ok" -eq 1 ]; then
    echo "Same-number GRE and Vira7 tunnels both exist."
    echo "1) Use GRE as WireGuard transport ($gre_ifc -> $gre_remote_ip)"
    echo "2) Use Vira7 as WireGuard transport ($vira_ifc -> $vira_remote_ip)"
    echo "00) Back to main menu"
    read -rp "Choose WireGuard transport [1-2] (00=menu): " choice
    if is_main_menu_token "$choice"; then return_main_msg; return 99; fi
    case "$choice" in
      1) WG_ENDPOINT_MODE="gre"; WG_ENDPOINT_IP="$gre_remote_ip"; WG_TRANSPORT_IFACE="$gre_ifc"; return 0 ;;
      2) WG_ENDPOINT_MODE="vira7"; WG_ENDPOINT_IP="$vira_remote_ip"; WG_TRANSPORT_IFACE="$vira_ifc"; return 0 ;;
      *) warn_msg "Invalid transport choice. Using GRE by default."; WG_ENDPOINT_MODE="gre"; WG_ENDPOINT_IP="$gre_remote_ip"; WG_TRANSPORT_IFACE="$gre_ifc"; return 0 ;;
    esac
  fi

  if [ "$gre_ok" -eq 1 ]; then
    WG_ENDPOINT_MODE="gre"
    WG_ENDPOINT_IP="$gre_remote_ip"
    WG_TRANSPORT_IFACE="$gre_ifc"
    return 0
  fi

  if [ "$vira_ok" -eq 1 ]; then
    WG_ENDPOINT_MODE="vira7"
    WG_ENDPOINT_IP="$vira_remote_ip"
    WG_TRANSPORT_IFACE="$vira_ifc"
    return 0
  fi

  # Keep previous transport choice only if its interface still exists.
  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ] && ip link show "$gre_ifc" >/dev/null 2>&1; then
    WG_ENDPOINT_IP="$gre_remote_ip"
    WG_TRANSPORT_IFACE="$gre_ifc"
  elif [ "${WG_ENDPOINT_MODE:-public}" = "vira7" ] && ip link show "$vira_ifc" >/dev/null 2>&1; then
    WG_ENDPOINT_IP="$vira_remote_ip"
    WG_TRANSPORT_IFACE="$vira_ifc"
  fi
}

wg_menu_config_tunnel() {
  show_header "Configure WireGuard Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_peer_key remote_ip_input
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter WireGuard tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  existing_peer_key=""
  local previous_endpoint_mode previous_endpoint_ip previous_transport_iface gre_saved_remote vira_saved_remote
  previous_endpoint_mode=""
  previous_endpoint_ip=""
  previous_transport_iface=""
  gre_saved_remote=""
  vira_saved_remote=""
  local existing_wg_port
  existing_wg_port=""
  if wg_load_meta "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_peer_key="${REMOTE_WG_PUBLIC_KEY:-}"
    existing_wg_port="${LOCAL_WG_PORT:-}"
    previous_endpoint_mode="${WG_ENDPOINT_MODE:-}"
    previous_endpoint_ip="${WG_ENDPOINT_IP:-}"
    previous_transport_iface="${WG_TRANSPORT_IFACE:-}"
  fi
  ROLE="$selected_role"
  REMOTE_WG_PUBLIC_KEY="$existing_peer_key"

  # Try to reuse the remote public IP saved by same-number GRE or Vira7 tunnel.
  # Run these in subshells so tunnel variables do not overwrite the selected WireGuard role.
  gre_saved_remote="$(bash -c 'set -e; f="'"$GRE_CONFIG_DIR""'/tunnel-'"$TUNNEL_ID""'.conf"; [ -f "$f" ] && . "$f" && printf "%s" "${REMOTE_PUBLIC_IP:-}"' 2>/dev/null || true)"
  vira_saved_remote="$(bash -c 'set -e; f="'"$VIRA7_CONFIG_DIR""'/tunnel-'"$TUNNEL_ID""'.conf"; [ -f "$f" ] && . "$f" && printf "%s" "${REMOTE_PUBLIC_IP:-${remote_ip:-}}"' 2>/dev/null || true)"
  if [ -z "$existing_remote_ip" ] && [ -n "$gre_saved_remote" ]; then
    existing_remote_ip="$gre_saved_remote"
  fi
  if [ -z "$existing_remote_ip" ] && [ -n "$vira_saved_remote" ]; then
    existing_remote_ip="$vira_saved_remote"
  fi

  echo
  wg_print_ip_plan "$TUNNEL_ID"
  echo
  echo "For servers with multiple IP addresses, choose the exact LOCAL IPv4 that the other side should use as this server endpoint."
  echo "WireGuard listens on the generated UDP port; this value is saved and shown so the peer can use the correct IP."
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for WireGuard endpoint" || return
  echo "Use this IP as the REMOTE server Public IPv4 on the other server: $LOCAL_PUBLIC_IP"
  echo

  # Safely stop/delete only this old wgtunN before choosing a port.
  # This prevents stale WireGuard sockets from causing "Address already in use".
  wg_safe_cleanup_runtime "$TUNNEL_ID" >/dev/null 2>&1 || true

  # Fewer questions: port and AllowedIPs are generated automatically.
  # Default is UDP 51800+N; if that port is already used by another tunnel/process,
  # the next free UDP port is selected automatically.
  LOCAL_WG_PORT="$(auto_select_udp_port "$(wg_default_port "$TUNNEL_ID")" "$existing_wg_port" "wireguard" "$TUNNEL_ID")" || return
  REMOTE_WG_PORT="$LOCAL_WG_PORT"
  EXTRA_ALLOWED_IPS=""

  REMOTE_PUBLIC_IP="$existing_remote_ip"
  WG_ENDPOINT_MODE="$previous_endpoint_mode"
  WG_ENDPOINT_IP="$previous_endpoint_ip"
  WG_TRANSPORT_IFACE="$previous_transport_iface"
  wg_choose_auto_endpoint "$TUNNEL_ID" "$ROLE" || return

  if [ "${WG_ENDPOINT_MODE:-public}" = "public" ]; then
    prompt_remote_public_ip "$existing_remote_ip" || return
    WG_ENDPOINT_MODE="public"
    WG_ENDPOINT_IP="$REMOTE_PUBLIC_IP"
    WG_TRANSPORT_IFACE=""
  else
    echo "Same-number ${WG_ENDPOINT_MODE} tunnel exists."
    echo "WireGuard will automatically use ${WG_ENDPOINT_MODE} as transport to avoid public UDP/WireGuard blocking."
    echo "No remote public IP is needed for the WireGuard endpoint in this mode."
    # Keep the public IP in metadata if it was previously known, but do not require it for the endpoint.
    REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-$existing_remote_ip}"
  fi

  case "${WG_ENDPOINT_MODE:-public}" in
    gre|vira7) WG_MTU="1280" ;;
    *) WG_MTU="1420" ;;
  esac

  echo
  echo "Auto WireGuard values for tunnel $TUNNEL_ID:"
  echo "  Local public/endpoint IP: $LOCAL_PUBLIC_IP"
  echo "  Local UDP ListenPort   : $LOCAL_WG_PORT"
  echo "  Remote endpoint port   : $REMOTE_WG_PORT"
  echo "  Endpoint mode          : ${WG_ENDPOINT_MODE:-public}"
  echo "  Endpoint IP            : ${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-UNKNOWN}}"
  echo "  MTU                    : $WG_MTU"
  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
    echo "  Transport interface    : ${WG_TRANSPORT_IFACE:-gre$TUNNEL_ID}"
  elif [ "${WG_ENDPOINT_MODE:-public}" = "vira7" ]; then
    echo "  Transport interface    : ${WG_TRANSPORT_IFACE:-vira7$TUNNEL_ID}"
  fi
  echo "  AllowedIPs             : peer /32 only"
  if [ -n "$REMOTE_WG_PUBLIC_KEY" ]; then
    echo "  Remote public key      : already saved"
    echo
    echo "Saved remote peer key found."
    echo "Press Enter to keep it, paste a new peer public key to replace it, or type CLEAR to reset this tunnel to pending."
    local peer_key_input
    read -rp "REMOTE WireGuard public key [keep/CLEAR/new] (00=menu): " peer_key_input
    if is_main_menu_token "$peer_key_input"; then return_main_msg; return 99; fi
    if [ "${peer_key_input^^}" = "CLEAR" ]; then
      REMOTE_WG_PUBLIC_KEY=""
    elif [ -n "$peer_key_input" ]; then
      REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "$peer_key_input")"
    fi
  fi
  echo

  wg_create_tunnel 1 || echo "WireGuard tunnel creation failed"
}

wg_check_one_tunnel() {
  local id="$1"
  local ifc svc last age now endpoint_line transfer_line
  ifc="$(wg_iface_name "$id")"
  svc="$(wg_service_name "$id")"

  echo
  echo "WireGuard tunnel $id ($ifc) status"
  echo "------------------------------------"

  if wg_load_meta "$id"; then
    echo "Saved role           : ${SERVER_ROLE:-unknown}"
    echo "Local public IP     : ${LOCAL_PUBLIC_IP:-unknown}"
    echo "Local WG IP         : ${LOCAL_WG_IP:-unknown}"
    echo "Remote WG IP        : ${REMOTE_WG_IP:-unknown}"
    echo "Endpoint mode       : ${WG_ENDPOINT_MODE:-public}"
    echo "Remote endpoint     : ${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-unknown}}:${REMOTE_WG_PORT:-$(wg_default_port "$id")}" 
    case "${WG_ENDPOINT_MODE:-public}" in
      gre|vira7) echo "Transport interface : ${WG_TRANSPORT_IFACE:-}" ;;
    esac
    echo "Local UDP port      : ${LOCAL_WG_PORT:-$(wg_default_port "$id")}" 
    echo "WireGuard MTU       : ${WG_MTU:-unknown}" 
    if [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
      echo "Remote peer key     : set"
    else
      echo "Remote peer key     : PENDING"
    fi
  else
    echo "No metadata found for tunnel $id."
  fi

  if command -v systemctl >/dev/null 2>&1; then
    echo "Systemd service     : $(systemctl is-active "$svc" 2>/dev/null || true) / $(systemctl is-enabled "$svc" 2>/dev/null || true)"
  fi

  if ip link show "$ifc" >/dev/null 2>&1; then
    echo "$ifc interface      : exists"
    ip -br addr show "$ifc" 2>/dev/null || true

    if command -v wg >/dev/null 2>&1; then
      echo
      echo "wg show summary:"
      wg show "$ifc" || true
      endpoint_line="$(wg show "$ifc" endpoints 2>/dev/null || true)"
      transfer_line="$(wg show "$ifc" transfer 2>/dev/null || true)"
      last="$(wg show "$ifc" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}' || true)"
      echo
      echo "Endpoint       : ${endpoint_line:-unknown}"
      echo "Transfer       : ${transfer_line:-unknown}"
      if [ -z "$last" ] || [ "$last" = "0" ]; then
        echo "Latest handshake: never"
      else
        now="$(date +%s)"
        age=$((now - last))
        echo "Latest handshake: ${age}s ago"
      fi
    fi

    if wg_load_meta "$id" && [ -n "${REMOTE_WG_IP:-}" ]; then
      echo
      echo "Pinging remote WireGuard inner IP $REMOTE_WG_IP (4 tries)..."
      if ping -c 4 "$REMOTE_WG_IP" >/tmp/wg_ping_$$.log 2>&1; then
        cat /tmp/wg_ping_$$.log
        echo "[OK] WireGuard inner tunnel is UP"
      else
        cat /tmp/wg_ping_$$.log
        echo "[WARN] WireGuard inner ping failed"
        last="$(wg show "$ifc" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}' || true)"
        if [ -z "$last" ] || [ "$last" = "0" ]; then
          if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ] || [ "${WG_ENDPOINT_MODE:-public}" = "vira7" ]; then
            echo "Diagnosis: no WireGuard handshake yet. WireGuard is using ${WG_ENDPOINT_MODE} transport. Check that transport tunnel $id still pings, the peer public key is correct, and UDP $(wg_default_port "$id") is allowed over ${WG_TRANSPORT_IFACE:-transport interface} on both servers."
          else
            echo "Diagnosis: no WireGuard handshake yet. Check the peer public key, remote public IP, UDP port $(wg_default_port "$id"), and firewall/NAT on both servers. If public UDP/WireGuard is blocked but GRE works, re-run create/update after GRE is up; v6 will auto-use GRE as WireGuard transport."
          fi
        else
          now="$(date +%s)"
          age=$((now - last))
          if [ "$age" -gt 180 ]; then
            echo "Diagnosis: last handshake is old (${age}s). The UDP path or endpoint may have changed, or the peer service may be down."
          else
            echo "Diagnosis: handshake exists but ping failed. Check AllowedIPs, firewall on the WireGuard interface, and rp_filter. The repair option can re-apply firewall rules and restart the service."
          fi
        fi
      fi
      rm -f /tmp/wg_ping_$$.log
    else
      echo "No saved WireGuard metadata for tunnel $id; save config first for inner ping test."
    fi
  else
    echo "$ifc interface      : not found"
    if wg_load_meta "$id" && [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
      echo "This tunnel is PENDING because the remote peer public key has not been added yet."
      echo "Ping will not work until both sides have each other's public keys and the service starts."
    fi
    if [ -f "$(wg_config_file "$id")" ]; then
      echo "Config exists: $(wg_config_file "$id")"
    fi
    if command -v systemctl >/dev/null 2>&1; then
      echo
      echo "Last service log lines:"
      journalctl -u "$svc" -n 20 --no-pager 2>/dev/null || true
    fi
  fi
}

wg_status_check() {
  show_header "WireGuard Tunnel Status"
  wg_list_tunnels
  echo
  read -rp "Enter WireGuard tunnel number to check, leave empty for all, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi

  if [ -n "$selected_id" ]; then
    if ! validate_tunnel_id "$selected_id"; then
      echo "Invalid tunnel number. Use 1 to 254."
      return
    fi
    wg_check_one_tunnel "$selected_id"
    return
  fi

  local ids id
  ids="$(wg_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No WireGuard tunnels found."
    return
  fi
  while IFS= read -r id; do
    [ -n "$id" ] && wg_check_one_tunnel "$id"
  done <<< "$ids"
}


wg_safe_cleanup_runtime() {
  local id="$1"
  local ifc svc
  validate_tunnel_id "$id" || return 1
  ifc="$(wg_iface_name "$id")"
  svc="$(wg_service_name "$id")"

  # Safe cleanup only for this WireGuard tunnel. Never flush main routing table.
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$svc" >/dev/null 2>&1 || true
  fi
  if command -v wg-quick >/dev/null 2>&1; then
    wg-quick down "$ifc" >/dev/null 2>&1 || true
  fi
  ip link delete "$ifc" 2>/dev/null || true

  # Remove only stale routes that belong to this interface/this tunnel subnet.
  # This is intentionally narrow and cannot remove the server default route.
  ip route show 2>/dev/null | awk -v ifc="$ifc" -v pfx="10.20.$id." '$0 ~ "dev "ifc && $1 ~ "^"pfx {print $1}' | while read -r dst; do
    [ -n "$dst" ] && ip route del "$dst" dev "$ifc" 2>/dev/null || true
  done
  ip route del "10.20.$id.0/30" dev "$ifc" 2>/dev/null || true
  ip route del "10.20.$id.1/32" dev "$ifc" 2>/dev/null || true
  ip route del "10.20.$id.2/32" dev "$ifc" 2>/dev/null || true

  if command -v systemctl >/dev/null 2>&1; then
    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
  fi
}

wg_udp_port_busy_after_cleanup() {
  local id="$1"
  local port="$2"
  validate_tunnel_id "$id" || return 1
  [ -n "$port" ] || return 1
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true
  udp_port_is_listening "$port"
}

wg_install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  local ifc svc
  if ! validate_tunnel_id "$id"; then
    echo "Cannot enable WireGuard service: invalid tunnel number" >&2
    return 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available on this system; cannot enable WireGuard service." >&2
    return 1
  fi
  if [ ! -f "$(wg_config_file "$id")" ]; then
    echo "WireGuard config not found: $(wg_config_file "$id")" >&2
    return 1
  fi

  ifc="$(wg_iface_name "$id")"
  svc="$(wg_service_name "$id")"

  # Install this manager path so systemd can re-apply firewall rules on every boot/restart.
  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN" 2>/dev/null || true
  chmod 755 "$INSTALL_BIN" 2>/dev/null || true
  mkdir -p "/etc/systemd/system/wg-quick@$ifc.service.d"
  cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-wg $id
EOF_WG_FW

  systemctl daemon-reload

  # Avoid stale interface/socket/route bugs, but only touch this WireGuard tunnel.
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true

  if wg_load_meta "$id" && [ -n "${LOCAL_WG_PORT:-}" ] && udp_port_is_listening "$LOCAL_WG_PORT"; then
    err_msg "UDP port $LOCAL_WG_PORT is still busy after cleaning $ifc."
    echo "Check what owns it with: ss -lunp | grep ':$LOCAL_WG_PORT'" >&2
    echo "Then re-run create/update; the script can choose another free port if the saved one is cleared or changed." >&2
    return 1
  fi

  systemctl enable "$svc" || return 1
  if systemctl restart "$svc"; then
    echo "WireGuard service enabled and started ($svc)"
    return 0
  fi

  return 1
}



wg_restart_one_tunnel() {
  local id="$1"
  local ifc svc
  if ! validate_tunnel_id "$id"; then
    echo "Invalid WireGuard tunnel number." >&2
    return 1
  fi
  ifc="$(wg_iface_name "$id")"
  svc="$(wg_service_name "$id")"

  if ! wg_load_meta "$id"; then
    echo "No saved WireGuard metadata found for tunnel $id." >&2
    return 1
  fi
  if [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
    echo "Tunnel $id is pending. Add the OTHER server public key first." >&2
    return 1
  fi
  if [ ! -f "$(wg_config_file "$id")" ]; then
    echo "WireGuard config file is missing. Re-run create/update for tunnel $id." >&2
    return 1
  fi

  wg_ensure_tools || return 1
  enable_ip_forward
  wg_apply_firewall_rules "$id"

  echo "Restarting WireGuard tunnel $id ($ifc)..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true
    systemctl enable "$svc" >/dev/null 2>&1 || true
    if ! systemctl restart "$svc"; then
      wg_print_service_failure "$id"
      return 1
    fi
  else
    wg-quick down "$ifc" >/dev/null 2>&1 || true
    ip link delete "$ifc" 2>/dev/null || true
    wg-quick up "$ifc"
  fi

  echo "[OK] Restarted $ifc"
  wg_check_one_tunnel "$id"
}

wg_repair_menu() {
  show_header "WireGuard Repair / Restart"
  wg_list_tunnels
  echo
  local ids selected_id
  ids="$(wg_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No WireGuard tunnels found."
    return
  fi
  read -rp "Enter WireGuard tunnel number to repair/restart, for example 1, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "WireGuard tunnel $selected_id was not found in the list."
    return
  fi
  wg_restart_one_tunnel "$selected_id"
}

wg_apply_firewall_rules() {
  local id="$1"
  local port endpoint_ip remote_port ifc transport_ifc endpoint_mode
  port="$(wg_default_port "$id")"
  endpoint_ip=""
  remote_port=""
  ifc="$(wg_iface_name "$id")"
  transport_ifc=""
  endpoint_mode="public"

  if wg_load_meta "$id"; then
    port="${LOCAL_WG_PORT:-$port}"
    endpoint_mode="${WG_ENDPOINT_MODE:-public}"
    endpoint_ip="${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-}}"
    remote_port="${REMOTE_WG_PORT:-$port}"
    transport_ifc="${WG_TRANSPORT_IFACE:-}"
  fi

  firewall_allow_udp_port_and_ip "WireGuard tunnel $id" "$port" "$endpoint_ip" "${remote_port:-$port}" "$ifc"
  if wg_load_meta "$id"; then
    firewall_allow_ip_peer "WireGuard tunnel $id remote inner" "${REMOTE_WG_IP:-}" "$ifc"
    firewall_allow_ip_peer "WireGuard tunnel $id remote public" "${REMOTE_PUBLIC_IP:-}" "$ifc"
  fi

  # Linux reverse-path filtering can break asymmetric/encapsulated traffic on some providers.
  # Disable it for WireGuard and GRE-transport use.
  for rp in /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/default/rp_filter "/proc/sys/net/ipv4/conf/$ifc/rp_filter" "/proc/sys/net/ipv4/conf/$transport_ifc/rp_filter"; do
    [ -e "$rp" ] && echo 0 > "$rp" 2>/dev/null || true
  done

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p udp --dport "$port" -j ACCEPT || true
    iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -j ACCEPT || true
    iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -j ACCEPT || true
    if [ -n "$endpoint_ip" ] && [ -n "$remote_port" ]; then
      iptables -C OUTPUT -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || true
    fi
    if { [ "$endpoint_mode" = "gre" ] || [ "$endpoint_mode" = "vira7" ]; } && [ -n "$transport_ifc" ]; then
      iptables -C INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT || true
      if [ -n "$endpoint_ip" ]; then
        iptables -C OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || true
      fi
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port/udp" comment "wgtun$id" >/dev/null 2>&1 || true
    ufw allow in on "$ifc" >/dev/null 2>&1 || true
    if { [ "$endpoint_mode" = "gre" ] || [ "$endpoint_mode" = "vira7" ]; } && [ -n "$transport_ifc" ]; then
      ufw allow in on "$transport_ifc" to any port "$port" proto udp >/dev/null 2>&1 || true
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-interface="$ifc" >/dev/null 2>&1 || true
    if { [ "$endpoint_mode" = "gre" ] || [ "$endpoint_mode" = "vira7" ]; } && [ -n "$transport_ifc" ]; then
      firewall-cmd --permanent --add-interface="$transport_ifc" >/dev/null 2>&1 || true
    fi
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

wg_remove_firewall_rules() {
  local id="$1"
  local port endpoint_ip remote_port transport_ifc
  port="$(wg_default_port "$id")"
  endpoint_ip=""
  remote_port=""
  transport_ifc=""
  if wg_load_meta "$id"; then
    port="${LOCAL_WG_PORT:-$port}"
    endpoint_ip="${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-}}"
    remote_port="${REMOTE_WG_PORT:-}"
    transport_ifc="${WG_TRANSPORT_IFACE:-}"
  fi
  if command -v iptables >/dev/null 2>&1; then
    local ifc
    ifc="$(wg_iface_name "$id")"
    while iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do
      iptables -D INPUT -p udp --dport "$port" -j ACCEPT || break
    done
    while iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null; do
      iptables -D INPUT -i "$ifc" -j ACCEPT || break
    done
    while iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null; do
      iptables -D OUTPUT -o "$ifc" -j ACCEPT || break
    done
    if [ -n "$endpoint_ip" ] && [ -n "$remote_port" ]; then
      while iptables -C OUTPUT -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null; do
        iptables -D OUTPUT -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || break
      done
    fi
    if [ -n "$transport_ifc" ]; then
      while iptables -C INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT 2>/dev/null; do
        iptables -D INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT || break
      done
      if [ -n "$endpoint_ip" ] && [ -n "$remote_port" ]; then
        while iptables -C OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null; do
          iptables -D OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || break
        done
      fi
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "$port/udp" >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="$port/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

wg_remove_one_tunnel() {
  local id="$1"
  local ifc conf meta private public
  ifc="$(wg_iface_name "$id")"
  conf="$(wg_config_file "$id")"
  meta="$(wg_meta_file "$id")"
  private="$(wg_private_key_file "$id")"
  public="$(wg_public_key_file "$id")"

  echo "Removing WireGuard tunnel $id ($ifc)..."

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$(wg_service_name "$id")" 2>/dev/null || true
  fi

  # Safe cleanup only for this WireGuard tunnel. Do not touch the main route table.
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true
  wg_remove_firewall_rules "$id"

  rm -rf "/etc/systemd/system/wg-quick@$ifc.service.d"
  rm -f "$conf" "$meta" "$private" "$public"
  echo "- Config removed: $conf"
  echo "- Metadata removed: $meta"
  echo "- Key files removed: $private / $public"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
  echo "[OK] WireGuard tunnel $id removed."
}

wg_remove_menu() {
  show_header "Remove WireGuard Tunnel"
  wg_list_tunnels
  echo
  local ids selected_id
  ids="$(wg_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No WireGuard tunnels found."
    return
  fi
  read -rp "Enter WireGuard tunnel number to remove, for example 1, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "WireGuard tunnel $selected_id was not found in the list."
    return
  fi
  if confirm_yes "Are you sure you want to remove WireGuard tunnel $selected_id completely, including keys?"; then
    wg_remove_one_tunnel "$selected_id"
  else
    echo "Cancelled."
  fi
}

# -----------------------------
# Vira7 UDP-TUN helpers (type only, no Vira7 menu/status/log UI)
# -----------------------------
vira7_iface_name() {
  echo "${VIRA7_IFACE_PREFIX}$1"
}

vira7_config_file() {
  echo "$VIRA7_CONFIG_DIR/tunnel-$1.conf"
}

vira7_service_name() {
  echo "vira7-tunnel@$1.service"
}

vira7_default_port() {
  local id="$1"
  echo $((VIRA7_DEFAULT_PORT_BASE + id))
}

vira7_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.71.$id.1"
  else
    echo "10.71.$id.2"
  fi
}

vira7_remote_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.71.$id.2"
  else
    echo "10.71.$id.1"
  fi
}

vira7_ensure_deps() {
  if command -v gcc >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing Vira7 build/runtime dependencies..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential gcc iproute2 iptables kmod
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make iproute iptables kmod
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make iproute iptables kmod
  else
    echo "No supported package manager found. Install gcc, iproute2, iptables and kmod manually." >&2
    return 1
  fi
}

vira7_compile_engine() {
  vira7_ensure_deps || return 1
  mkdir -p "$VIRA7_CONFIG_DIR"
  cat > "$VIRA7_SOURCE" <<'ENGINEEOF'
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TUN_DEVICE "/dev/net/tun"
#define MAX_PKT_SIZE 2000
#define VIRA7_MAGIC 0x5637
#define PKT_DATA 1
#define PKT_KEEPALIVE 2
#define PKT_ACK 3

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint16_t type;
    uint32_t seq;
    uint16_t length;
    uint16_t checksum;
} v7_hdr_t;

typedef struct {
    char iface[IFNAMSIZ];
    char mode[16];
    char bind_ip[64];
    char remote_ip[64];
    char local_priv[64];
    char remote_priv[64];
    int port;
    int mtu;
    int keepalive;
    int buffer_size;
    int queue_len;
    int checksum;
    int verify_checksum;
    int batch;
} v7_config_t;

static volatile sig_atomic_t running = 1;
static uint32_t seqno = 1;
static int g_send_checksum = 1;
static int g_verify_checksum = 0;

static void on_signal(int sig) { (void)sig; running = 0; }

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = 0;
}

static uint16_t csum16(const uint8_t *buf, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += buf[i];
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return (uint16_t)(~sum & 0xffffU);
}

static int load_config(const char *path, v7_config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->iface, sizeof(c->iface), "vira7");
    snprintf(c->mode, sizeof(c->mode), "client");
    c->port = 5571;
    c->mtu = 1400;
    c->keepalive = 5;
    c->buffer_size = 2097152;
    c->queue_len = 1000;
    c->checksum = 1;
    c->verify_checksum = 0;
    c->batch = 128;

    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);
        if (!strcmp(key, "iface")) snprintf(c->iface, sizeof(c->iface), "%s", val);
        else if (!strcmp(key, "mode")) snprintf(c->mode, sizeof(c->mode), "%s", val);
        else if (!strcmp(key, "bind_ip")) snprintf(c->bind_ip, sizeof(c->bind_ip), "%s", val);
        else if (!strcmp(key, "remote_ip")) snprintf(c->remote_ip, sizeof(c->remote_ip), "%s", val);
        else if (!strcmp(key, "local_priv")) snprintf(c->local_priv, sizeof(c->local_priv), "%s", val);
        else if (!strcmp(key, "remote_priv")) snprintf(c->remote_priv, sizeof(c->remote_priv), "%s", val);
        else if (!strcmp(key, "port")) c->port = atoi(val);
        else if (!strcmp(key, "mtu")) c->mtu = atoi(val);
        else if (!strcmp(key, "keepalive")) c->keepalive = atoi(val);
        else if (!strcmp(key, "buffer_size")) c->buffer_size = atoi(val);
        else if (!strcmp(key, "queue_len")) c->queue_len = atoi(val);
        else if (!strcmp(key, "checksum")) c->checksum = atoi(val);
        else if (!strcmp(key, "verify_checksum")) c->verify_checksum = atoi(val);
        else if (!strcmp(key, "batch")) c->batch = atoi(val);
    }
    fclose(f);
    if (!c->local_priv[0] || !c->remote_priv[0] || c->port <= 0 || c->port > 65535) return -1;
    if (!strcmp(c->mode, "client") && !c->remote_ip[0]) return -1;
    if (c->mtu < 576 || c->mtu > 1600) c->mtu = 1400;
    if (c->keepalive < 1 || c->keepalive > 60) c->keepalive = 5;
    if (c->queue_len < 100) c->queue_len = 1000;
    if (c->buffer_size < 65536) c->buffer_size = 2097152;
    c->checksum = c->checksum ? 1 : 0;
    c->verify_checksum = c->verify_checksum ? 1 : 0;
    if (c->batch < 1) c->batch = 1;
    if (c->batch > 512) c->batch = 512;
    return 0;
}

static int tun_alloc_named(const char *dev) {
    struct ifreq ifr;
    int fd = open(TUN_DEVICE, O_RDWR);
    if (fd < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { close(fd); return -1; }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

static void cleanup_iface(const char *iface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", iface);
    system(cmd);
}

static int configure_tun(const v7_config_t *c) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up mtu %d txqueuelen %d", c->iface, c->mtu, c->queue_len);
    if (system(cmd) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "ip addr add %s/32 peer %s dev %s 2>/dev/null || true", c->local_priv, c->remote_priv, c->iface);
    return system(cmd) == 0 ? 0 : -1;
}

static int udp_socket_create(const v7_config_t *c) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &c->buffer_size, sizeof(c->buffer_size));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &c->buffer_size, sizeof(c->buffer_size));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)c->port);
    if (c->bind_ip[0]) {
        if (inet_pton(AF_INET, c->bind_ip, &addr.sin_addr) != 1) { close(fd); return -1; }
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

static int send_v7(int fd, const struct sockaddr_in *dst, uint16_t type, const uint8_t *payload, uint16_t len) {
    uint8_t buf[sizeof(v7_hdr_t) + MAX_PKT_SIZE];
    if (len > MAX_PKT_SIZE) return -1;
    v7_hdr_t *h = (v7_hdr_t *)buf;
    h->magic = htons(VIRA7_MAGIC);
    h->type = htons(type);
    h->seq = htonl(seqno++);
    h->length = htons(len);
    h->checksum = 0;
    if (payload && len) memcpy(buf + sizeof(v7_hdr_t), payload, len);
    if (g_send_checksum) {
        h->checksum = htons(csum16(buf, sizeof(v7_hdr_t) + len));
    } else {
        h->checksum = 0;
    }
    ssize_t n = sendto(fd, buf, sizeof(v7_hdr_t) + len, 0, (const struct sockaddr *)dst, sizeof(*dst));
    return n == (ssize_t)(sizeof(v7_hdr_t) + len) ? 0 : -1;
}

static int verify_packet(uint8_t *buf, ssize_t n, uint16_t *type, uint8_t **payload, uint16_t *len) {
    if (n < (ssize_t)sizeof(v7_hdr_t)) return -1;
    v7_hdr_t *h = (v7_hdr_t *)buf;
    if (ntohs(h->magic) != VIRA7_MAGIC) return -1;
    *len = ntohs(h->length);
    if ((ssize_t)(sizeof(v7_hdr_t) + *len) != n || *len > MAX_PKT_SIZE) return -1;
    uint16_t got = ntohs(h->checksum);
    if (got != 0 && g_verify_checksum) {
        h->checksum = 0;
        uint16_t calc = csum16(buf, (size_t)n);
        if (got != calc) return -1;
    }
    *type = ntohs(h->type);
    *payload = buf + sizeof(v7_hdr_t);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || getuid() != 0) return 1;
    v7_config_t cfg;
    if (load_config(argv[1], &cfg) != 0) return 1;
    g_send_checksum = cfg.checksum ? 1 : 0;
    g_verify_checksum = cfg.verify_checksum ? 1 : 0;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    mkdir("/dev/net", 0755);
    if (access(TUN_DEVICE, F_OK) != 0) system("mknod /dev/net/tun c 10 200 2>/dev/null || true");
    system("modprobe tun 2>/dev/null || true");
    cleanup_iface(cfg.iface);
    int tun_fd = tun_alloc_named(cfg.iface);
    if (tun_fd < 0) return 1;
    if (configure_tun(&cfg) != 0) { cleanup_iface(cfg.iface); close(tun_fd); return 1; }
    int udp_fd = udp_socket_create(&cfg);
    if (udp_fd < 0) { cleanup_iface(cfg.iface); close(tun_fd); return 1; }

    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_port = htons((uint16_t)cfg.port);
    int remote_known = 0;
    if (!strcmp(cfg.mode, "client")) {
        if (inet_pton(AF_INET, cfg.remote_ip, &remote.sin_addr) != 1) {
            close(udp_fd); close(tun_fd); cleanup_iface(cfg.iface); return 1;
        }
        remote_known = 1;
    }

    char pidfile[128];
    snprintf(pidfile, sizeof(pidfile), "/var/run/%s.pid", cfg.iface);
    FILE *pf = fopen(pidfile, "w");
    if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }

    uint8_t tun_buf[MAX_PKT_SIZE];
    uint8_t udp_buf[sizeof(v7_hdr_t) + MAX_PKT_SIZE];
    time_t last_keepalive = 0;

    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tun_fd, &rfds);
        FD_SET(udp_fd, &rfds);
        int maxfd = tun_fd > udp_fd ? tun_fd : udp_fd;
        struct timeval tv = {1, 0};
        int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (rc < 0) { if (errno == EINTR) continue; break; }
        time_t now = time(NULL);
        if (remote_known && now - last_keepalive >= cfg.keepalive) {
            send_v7(udp_fd, &remote, PKT_KEEPALIVE, NULL, 0);
            last_keepalive = now;
        }
        if (FD_ISSET(tun_fd, &rfds)) {
            for (int i = 0; i < cfg.batch; i++) {
                ssize_t n = read(tun_fd, tun_buf, sizeof(tun_buf));
                if (n > 0) {
                    if (remote_known) send_v7(udp_fd, &remote, PKT_DATA, tun_buf, (uint16_t)n);
                    continue;
                }
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                break;
            }
        }
        if (FD_ISSET(udp_fd, &rfds)) {
            for (int i = 0; i < cfg.batch; i++) {
                struct sockaddr_in sender;
                socklen_t slen = sizeof(sender);
                ssize_t n = recvfrom(udp_fd, udp_buf, sizeof(udp_buf), 0, (struct sockaddr *)&sender, &slen);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }
                if (n == 0) break;
                uint16_t type, len;
                uint8_t *payload;
                if (verify_packet(udp_buf, n, &type, &payload, &len) != 0) continue;
                if (strcmp(cfg.mode, "server") == 0) {
                    memcpy(&remote, &sender, sizeof(remote));
                    remote_known = 1;
                }
                if (type == PKT_DATA && len > 0) write(tun_fd, payload, len);
                else if (type == PKT_KEEPALIVE && remote_known) send_v7(udp_fd, &remote, PKT_ACK, NULL, 0);
            }
        }
    }
    close(udp_fd);
    close(tun_fd);
    unlink(pidfile);
    cleanup_iface(cfg.iface);
    return 0;
}
ENGINEEOF
  gcc -O3 -flto -Wall -Wextra -o "$VIRA7_BINARY" "$VIRA7_SOURCE" 2>/dev/null || \
    gcc -O3 -Wall -Wextra -o "$VIRA7_BINARY" "$VIRA7_SOURCE"
  chmod 755 "$VIRA7_BINARY"
}

vira7_write_service_template() {
  cat > "$VIRA7_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=Vira7 UDP-TUN Tunnel %i Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-vira7 %i
ExecStart=$VIRA7_BINARY $VIRA7_CONFIG_DIR/tunnel-%i.conf
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  systemctl daemon-reload
}

vira7_save_config() {
  mkdir -p "$VIRA7_CONFIG_DIR"
  local file
  file="$(vira7_config_file "$TUNNEL_ID")"
  {
    # Shell metadata used by this manager.
    write_var TUNNEL_TYPE "vira7"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var VIRA7_IFACE "$VIRA7_IFACE"
    write_var ROLE "$ROLE"
    write_var SERVER_ROLE "$SERVER_ROLE"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_VIRA7_IP "$LOCAL_VIRA7_IP"
    write_var REMOTE_VIRA7_IP "$REMOTE_VIRA7_IP"
    write_var VIRA7_PORT "$VIRA7_PORT"
    write_var VIRA7_MTU "$VIRA7_MTU"
    write_var VIRA7_CHECKSUM "${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
    write_var VIRA7_VERIFY_CHECKSUM "${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
    write_var VIRA7_BATCH "${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"
    echo
    # Engine config used directly by vira7-engine systemd service.
    printf 'iface=%s
' "$VIRA7_IFACE"
    printf 'mode=%s
' "$VIRA7_MODE"
    printf 'bind_ip=%s
' "$LOCAL_PUBLIC_IP"
    printf 'remote_ip=%s
' "$REMOTE_PUBLIC_IP"
    printf 'local_priv=%s
' "$LOCAL_VIRA7_IP"
    printf 'remote_priv=%s
' "$REMOTE_VIRA7_IP"
    printf 'port=%s
' "$VIRA7_PORT"
    printf 'mtu=%s
' "$VIRA7_MTU"
    printf 'keepalive=%s
' "$VIRA7_DEFAULT_KEEPALIVE"
    printf 'buffer_size=%s
' "$VIRA7_DEFAULT_BUFFER_SIZE"
    printf 'queue_len=%s
' "$VIRA7_DEFAULT_QUEUE_LEN"
    printf 'checksum=%s
' "${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
    printf 'verify_checksum=%s
' "${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
    printf 'batch=%s
' "${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"
  } > "$file"
  chmod 600 "$file"
  echo "Saved Vira7 tunnel $TUNNEL_ID configuration to $file"
}

vira7_load_config() {
  local id="${1:-${TUNNEL_ID:-}}"
  validate_tunnel_id "$id" || return 1
  local file
  file="$(vira7_config_file "$id")"
  [ -f "$file" ] || return 1
  # shellcheck disable=SC1090
  source "$file"
  TUNNEL_ID="$id"
  VIRA7_IFACE="${VIRA7_IFACE:-${iface:-$(vira7_iface_name "$id")}}"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
  REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
  LOCAL_VIRA7_IP="${LOCAL_VIRA7_IP:-${local_priv:-}}"
  REMOTE_VIRA7_IP="${REMOTE_VIRA7_IP:-${remote_priv:-}}"
  VIRA7_PORT="${VIRA7_PORT:-${port:-$(vira7_default_port "$id")}}"
  VIRA7_MTU="${VIRA7_MTU:-${mtu:-$VIRA7_DEFAULT_MTU}}"
  VIRA7_CHECKSUM="${VIRA7_CHECKSUM:-${checksum:-$VIRA7_DEFAULT_CHECKSUM}}"
  VIRA7_VERIFY_CHECKSUM="${VIRA7_VERIFY_CHECKSUM:-${verify_checksum:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}}"
  VIRA7_BATCH="${VIRA7_BATCH:-${batch:-$VIRA7_DEFAULT_BATCH}}"
  if [ -z "${ROLE:-}" ]; then
    if [ "${LOCAL_VIRA7_IP:-}" = "10.71.$id.1" ]; then ROLE="1"; else ROLE="2"; fi
  fi
}

vira7_write_engine_config() {
  local id="$1"
  local file
  file="$(vira7_config_file "$id")"
  mkdir -p "$VIRA7_CONFIG_DIR"
  cat > "$file" <<EOF_CONF
iface=$VIRA7_IFACE
mode=$VIRA7_MODE
bind_ip=$LOCAL_PUBLIC_IP
remote_ip=$REMOTE_PUBLIC_IP
local_priv=$LOCAL_VIRA7_IP
remote_priv=$REMOTE_VIRA7_IP
port=$VIRA7_PORT
mtu=$VIRA7_MTU
keepalive=$VIRA7_DEFAULT_KEEPALIVE
buffer_size=$VIRA7_DEFAULT_BUFFER_SIZE
queue_len=$VIRA7_DEFAULT_QUEUE_LEN
checksum=${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}
verify_checksum=${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}
batch=${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}
EOF_CONF
  chmod 600 "$file"
}

vira7_apply_firewall_rules() {
  local id="$1"
  if ! vira7_load_config "$id"; then return 1; fi
  firewall_allow_udp_port_and_ip "Vira7 tunnel $id" "$VIRA7_PORT" "$REMOTE_PUBLIC_IP" "$VIRA7_PORT" "$VIRA7_IFACE"
  firewall_allow_ip_peer "Vira7 tunnel $id remote inner" "${REMOTE_VIRA7_IP:-${remote_priv:-}}" "$VIRA7_IFACE"
  firewall_allow_ip_peer "Vira7 tunnel $id remote public" "$REMOTE_PUBLIC_IP" "$VIRA7_IFACE"
}

vira7_install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  validate_tunnel_id "$id" || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  [ -x "$VIRA7_BINARY" ] || vira7_compile_engine || return 1
  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN" 2>/dev/null || true
  chmod 755 "$INSTALL_BIN" 2>/dev/null || true
  vira7_write_service_template
  systemctl enable "$(vira7_service_name "$id")" || return 1
  if systemctl restart "$(vira7_service_name "$id")"; then
    echo "Vira7 service enabled and started ($(vira7_service_name "$id"))"
    return 0
  fi
  systemctl status "$(vira7_service_name "$id")" --no-pager -l 2>/dev/null || true
  journalctl -u "$(vira7_service_name "$id")" -n 30 --no-pager 2>/dev/null || true
  return 1
}

vira7_create_tunnel() {
  local interactive=${1:-0}
  validate_tunnel_id "${TUNNEL_ID:-}" || { echo "Invalid tunnel number." >&2; return 1; }
  VIRA7_IFACE="$(vira7_iface_name "$TUNNEL_ID")"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  [ -n "${LOCAL_PUBLIC_IP:-}" ] || { echo "Failed to detect local public IPv4" >&2; return 1; }
  if ! local_ipv4_is_assigned "$LOCAL_PUBLIC_IP"; then
    echo "Selected Vira7 bind IP is not assigned on this server: $LOCAL_PUBLIC_IP" >&2
    list_local_ipv4s >&2
    return 1
  fi
  if [ "$ROLE" = "1" ]; then
    SERVER_ROLE="IRAN"
    VIRA7_MODE="server"
    LOCAL_VIRA7_IP="10.71.$TUNNEL_ID.1"
    REMOTE_VIRA7_IP="10.71.$TUNNEL_ID.2"
  else
    SERVER_ROLE="KHAREJ"
    VIRA7_MODE="client"
    LOCAL_VIRA7_IP="10.71.$TUNNEL_ID.2"
    REMOTE_VIRA7_IP="10.71.$TUNNEL_ID.1"
  fi
  VIRA7_PORT="${VIRA7_PORT:-$(vira7_default_port "$TUNNEL_ID")}" 
  VIRA7_MTU="${VIRA7_MTU:-$VIRA7_DEFAULT_MTU}"
  VIRA7_CHECKSUM="${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
  VIRA7_VERIFY_CHECKSUM="${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
  VIRA7_BATCH="${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"

  echo "[*] Local server public IP: $LOCAL_PUBLIC_IP"
  echo "[*] Tunnel type: Vira7 UDP-TUN"
  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $VIRA7_IFACE"
  echo "[*] Server role: $SERVER_ROLE"
  echo "[*] Remote server public IP: $REMOTE_PUBLIC_IP"
  echo "[*] Local Vira7 IP: $LOCAL_VIRA7_IP"
  echo "[*] Remote Vira7 IP: $REMOTE_VIRA7_IP"
  echo "[*] UDP Port: $VIRA7_PORT"
  echo "[*] CPU mode: checksum=$VIRA7_CHECKSUM verify_checksum=$VIRA7_VERIFY_CHECKSUM batch=$VIRA7_BATCH"

  enable_ip_forward
  modprobe tun || true
  vira7_compile_engine || return 1
  vira7_save_config
  vira7_apply_firewall_rules "$TUNNEL_ID" || true
  vira7_install_service "$TUNNEL_ID"
}

vira7_menu_config_tunnel() {
  show_header "Configure Vira7 UDP-TUN Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_port existing_mtu
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter Vira7 tunnel number before IP [1-254]: " || return
  existing_local_ip=""
  existing_remote_ip=""
  existing_port=""
  existing_mtu=""
  if vira7_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_port="${VIRA7_PORT:-}"
    existing_mtu="${VIRA7_MTU:-}"
  fi
  ROLE="$selected_role"
  echo
  echo "Vira7 UDP-TUN tunnel $TUNNEL_ID plan:"
  echo "  Interface       : $(vira7_iface_name "$TUNNEL_ID")"
  echo "  Config file     : $(vira7_config_file "$TUNNEL_ID")"
  echo "  Service         : $(vira7_service_name "$TUNNEL_ID")"
  echo "  Iran role IP    : 10.71.$TUNNEL_ID.1"
  echo "  Kharej role IP  : 10.71.$TUNNEL_ID.2"
  echo
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for Vira7 UDP bind" || return
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return
  echo
  VIRA7_PORT="$(auto_select_udp_port "$(vira7_default_port "$TUNNEL_ID")" "$existing_port" "vira7" "$TUNNEL_ID")" || return
  echo "Auto-selected Vira7 UDP port: $VIRA7_PORT"
  read -rp "Enter Vira7 MTU [${existing_mtu:-$VIRA7_DEFAULT_MTU}] (00=menu): " VIRA7_MTU_INPUT
  if is_main_menu_token "$VIRA7_MTU_INPUT"; then return_main_msg; return 99; fi
  VIRA7_MTU="${VIRA7_MTU_INPUT:-${existing_mtu:-$VIRA7_DEFAULT_MTU}}"
  if ! [[ "$VIRA7_MTU" =~ ^[0-9]+$ ]] || [ "$VIRA7_MTU" -lt 576 ] || [ "$VIRA7_MTU" -gt 1600 ]; then
    echo "Invalid MTU."
    return
  fi
  # Safe CPU optimization: keep checksum generation for compatibility, skip expensive receive-side verification, use packet batching.
  VIRA7_CHECKSUM="${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
  VIRA7_VERIFY_CHECKSUM="${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
  VIRA7_BATCH="${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"
  vira7_create_tunnel 1 || echo "Vira7 tunnel creation failed"
}

vira7_collect_ids() {
  {
    if [ -d "$VIRA7_CONFIG_DIR" ]; then
      local f id
      for f in "$VIRA7_CONFIG_DIR"/tunnel-*.conf; do
        [ -e "$f" ] || continue
        id="${f##*/tunnel-}"
        id="${id%.conf}"
        validate_tunnel_id "$id" && echo "$id"
      done
    fi
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${VIRA7_IFACE_PREFIX}[0-9]+$" | sed "s/^${VIRA7_IFACE_PREFIX}//" || true
  } | sort -n -u
}

vira7_list_tunnels() {
  echo "Vira7 UDP-TUN tunnels:"
  local ids id ifc state
  ids="$(vira7_collect_ids || true)"
  if [ -z "$ids" ]; then echo "  none"; return 0; fi
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(vira7_iface_name "$id")"
    state="inactive"
    ip link show "$ifc" >/dev/null 2>&1 && state="active"
    echo "  - tunnel $id | iface $ifc | $state | config: $(vira7_config_file "$id") | service: $(systemctl is-enabled "$(vira7_service_name "$id")" 2>/dev/null || true)"
  done <<< "$ids"
}

vira7_remove_one_tunnel() {
  local id="$1"
  local ifc file port
  ifc="$(vira7_iface_name "$id")"
  file="$(vira7_config_file "$id")"
  port=""
  if vira7_load_config "$id"; then port="${VIRA7_PORT:-}"; fi
  echo "Removing Vira7 tunnel $id ($ifc)..."
  systemctl disable --now "$(vira7_service_name "$id")" 2>/dev/null || true
  ip link delete "$ifc" 2>/dev/null || true
  if [ -n "$port" ] && command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport "$port" -j ACCEPT || break; done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
  fi
  rm -f "$file" "/var/run/$ifc.pid"
  systemctl daemon-reload 2>/dev/null || true
  echo "[OK] Vira7 tunnel $id removed."
}

vira7_remove_menu() {
  show_header "Remove Vira7 UDP-TUN Tunnel"
  vira7_list_tunnels
  echo
  local ids selected_id
  ids="$(vira7_collect_ids || true)"
  if [ -z "$ids" ]; then echo "No Vira7 tunnels found."; return; fi
  read -rp "Enter Vira7 tunnel number to remove, for example 1, or 00=menu: " selected_id
  if is_main_menu_token "$selected_id"; then return_main_msg; return 99; fi
  validate_tunnel_id "$selected_id" || { echo "Invalid tunnel number."; return; }
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "Vira7 tunnel $selected_id was not found in the list."
    return
  fi
  if confirm_yes "Are you sure you want to remove Vira7 tunnel $selected_id completely?"; then
    vira7_remove_one_tunnel "$selected_id"
  else
    echo "Cancelled."
  fi
}

vira7_restart_one_tunnel() {
  local id="$1"
  validate_tunnel_id "$id" || return 1
  if ! vira7_load_config "$id"; then
    echo "No saved Vira7 configuration found for tunnel $id." >&2
    return 1
  fi
  VIRA7_MODE="client"
  if [ "${ROLE:-}" = "1" ]; then VIRA7_MODE="server"; fi
  [ -x "$VIRA7_BINARY" ] || vira7_compile_engine || return 1
  enable_ip_forward
  vira7_apply_firewall_rules "$id" || true
  vira7_install_service "$id"
}


set_config_kv() {
  local file="$1" key="$2" value="$3"
  [ -f "$file" ] || return 1
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

vira7_optimize_cpu_one() {
  local id="$1" mode="${2:-safe}" file svc
  validate_tunnel_id "$id" || { echo "Invalid Vira7 tunnel number." >&2; return 1; }
  file="$(vira7_config_file "$id")"
  svc="$(vira7_service_name "$id")"
  [ -f "$file" ] || { echo "No Vira7 config found: $file" >&2; return 1; }

  # Always safe: skip userspace receive checksum verification and batch packets.
  # Fast mode additionally disables checksum generation; use it only when BOTH sides run this optimized engine.
  set_config_kv "$file" verify_checksum 0
  set_config_kv "$file" VIRA7_VERIFY_CHECKSUM 0
  set_config_kv "$file" batch 128
  set_config_kv "$file" VIRA7_BATCH 128
  if [ "$mode" = "fast" ]; then
    set_config_kv "$file" checksum 0
    set_config_kv "$file" VIRA7_CHECKSUM 0
  else
    set_config_kv "$file" checksum 1
    set_config_kv "$file" VIRA7_CHECKSUM 1
  fi

  echo "Recompiling optimized Vira7 engine..."
  vira7_compile_engine || return 1
  enable_ip_forward
  vira7_apply_firewall_rules "$id" || true
  systemctl daemon-reload 2>/dev/null || true
  systemctl enable "$svc" >/dev/null 2>&1 || true
  if systemctl restart "$svc"; then
    echo "[OK] Vira7 tunnel $id optimized and restarted. mode=$mode"
    echo "Current CPU settings:"
    grep -E '^(checksum|verify_checksum|batch|mtu|port)=' "$file" || true
    return 0
  fi
  echo "[WARN] Restart failed. Last logs:" >&2
  systemctl status "$svc" --no-pager -l 2>/dev/null || true
  journalctl -u "$svc" -n 40 --no-pager 2>/dev/null || true
  return 1
}

vira7_optimize_cpu_menu() {
  show_header "Optimize Vira7 CPU"
  vira7_list_tunnels
  echo
  local id mode_choice mode
  read -rp "Enter Vira7 tunnel number to optimize, 0=all, 00=menu: " id
  if is_main_menu_token "$id"; then return_main_msg; return 99; fi
  echo
  echo "1) Safe low CPU mode (compatible, recommended first)"
  echo "2) Fast low CPU mode (must be applied on BOTH servers for this Vira7 tunnel)"
  echo "00) Back to main menu"
  read -rp "Choose CPU mode [1-2/00]: " mode_choice
  if is_main_menu_token "$mode_choice"; then return_main_msg; return 99; fi
  case "$mode_choice" in
    1) mode="safe" ;;
    2) mode="fast" ;;
    *) echo "Invalid mode."; return 1 ;;
  esac
  if [ "$id" = "0" ]; then
    local ids one
    ids="$(vira7_collect_ids || true)"
    [ -n "$ids" ] || { echo "No Vira7 tunnels found."; return 0; }
    while IFS= read -r one; do
      [ -n "$one" ] && vira7_optimize_cpu_one "$one" "$mode" || true
    done <<< "$ids"
  else
    vira7_optimize_cpu_one "$id" "$mode"
  fi
}

# -----------------------------
# Shared helpers/menus
# -----------------------------
enable_ip_forward() {
  echo 1 > /proc/sys/net/ipv4/ip_forward || true
  if [ -f /etc/sysctl.conf ]; then
    if grep -q '^#\?net.ipv4.ip_forward=' /etc/sysctl.conf; then
      sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
    else
      echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf || true
    fi
    sysctl -p >/dev/null 2>&1 || true
  fi
}


# -----------------------------
# Unified tunnel inventory / professional menus
# -----------------------------
declare -a INV_TYPE INV_ID INV_IFACE INV_LOCAL INV_TARGET INV_LOCAL_PUBLIC INV_REMOTE_PUBLIC INV_STATE INV_DESC

build_tunnel_inventory() {
  INV_TYPE=(); INV_ID=(); INV_IFACE=(); INV_LOCAL=(); INV_TARGET=(); INV_LOCAL_PUBLIC=(); INV_REMOTE_PUBLIC=(); INV_STATE=(); INV_DESC=()
  local ids id ifc local_ip target local_pub remote_pub state desc

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(gre_iface "$id")"
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Normal GRE"
    if gre_load_config "$id"; then
      local_ip="${LOCAL_GRE_IP:-}"
      target="${REMOTE_GRE_IP:-}"
      local_pub="${LOCAL_PUBLIC_IP:-}"
      remote_pub="${REMOTE_PUBLIC_IP:-}"
      if [ -z "$target" ] && [ -n "${ROLE:-}" ]; then
        target="$(gre_remote_inner_ip_for_role "$id" "$ROLE")"
      fi
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("gre"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(wg_iface_name "$id")"
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="WireGuard"
    if wg_load_meta "$id"; then
      local_ip="${LOCAL_WG_IP:-}"
      target="${REMOTE_WG_IP:-}"
      local_pub="${LOCAL_PUBLIC_IP:-}"
      remote_pub="${REMOTE_PUBLIC_IP:-${WG_ENDPOINT_IP:-}}"
      if [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then desc="WireGuard/PENDING"; fi
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("wireguard"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(vira7_iface_name "$id")"
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Vira7 UDP-TUN"
    if vira7_load_config "$id"; then
      local_ip="${LOCAL_VIRA7_IP:-${local_priv:-}}"
      target="${REMOTE_VIRA7_IP:-${remote_priv:-}}"
      local_pub="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
      remote_pub="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("vira7"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"
}


print_tunnel_inventory() {
  local count="${#INV_TYPE[@]}"
  if [ "$count" -eq 0 ]; then
    warn_msg "No saved or active tunnels found."
    return 1
  fi

  echo -e "${C_BOLD}${C_WHITE}Existing tunnels:${C_RESET}"
  printf "${C_DIM}%4s  %-11s %-4s %-10s %-15s %-15s %-15s %-8s${C_RESET}\n" "No" "Type" "ID" "Interface" "Local-Pub" "Remote-Pub" "Remote-Tun" "State"
  printf "${C_DIM}%s${C_RESET}\n" "------------------------------------------------------------------------------------------------------------"
  local i idx type id ifc state color target local_pub remote_pub
  for i in "${!INV_TYPE[@]}"; do
    idx=$((i + 1))
    type="${INV_TYPE[$i]}"; id="${INV_ID[$i]}"; ifc="${INV_IFACE[$i]}"; state="${INV_STATE[$i]}"
    target="${INV_TARGET[$i]:-N/A}"
    local_pub="${INV_LOCAL_PUBLIC[$i]:-N/A}"
    remote_pub="${INV_REMOTE_PUBLIC[$i]:-N/A}"
    if [ "$state" = "active" ]; then color="$C_GREEN"; else color="$C_YELLOW"; fi
    printf "%4s  %-11s %-4s %-10s %-15s %-15s %-15s ${color}%-8s${C_RESET}\n" "$idx" "$type" "$id" "$ifc" "$local_pub" "$remote_pub" "$target" "$state"
  done
  echo
}


remove_inventory_item() {
  local index="$1"
  local i=$((index - 1))
  local type="${INV_TYPE[$i]}"
  local id="${INV_ID[$i]}"
  case "$type" in
    gre) gre_remove_one_tunnel "$id" ;;
    wireguard) wg_remove_one_tunnel "$id" ;;
    vira7) vira7_remove_one_tunnel "$id" ;;
  esac
}

ping_inventory_item() {
  local index="$1"
  local i=$((index - 1))
  local type="${INV_TYPE[$i]}"
  local id="${INV_ID[$i]}"
  case "$type" in
    gre) test_gre_tunnel_ping "$id" ;;
    wireguard) test_wg_tunnel_ping "$id" ;;
    vira7) test_vira7_tunnel_ping "$id" ;;
  esac
}


# Return 0 if the current selected row list contains a tunnel by type/id.
selection_has_type_id() {
  local want_type="$1"
  local want_id="$2"
  shift 2
  local idx i
  for idx in "$@"; do
    i=$((idx - 1))
    [ "${INV_TYPE[$i]:-}" = "$want_type" ] && [ "${INV_ID[$i]:-}" = "$want_id" ] && return 0
  done
  return 1
}

# Return 0 if WireGuard tunnel <wg_id> uses the selected transport tunnel.
wg_uses_transport_tunnel() {
  local wg_id="$1"
  local transport_type="$2"
  local transport_id="$3"
  local expected_ifc=""

  wg_load_meta "$wg_id" || return 1

  case "$transport_type" in
    gre)
      expected_ifc="$(gre_iface "$transport_id")"
      [ "${WG_ENDPOINT_MODE:-}" = "gre" ] || return 1
      ;;
    vira7)
      expected_ifc="$(vira7_iface_name "$transport_id")"
      [ "${WG_ENDPOINT_MODE:-}" = "vira7" ] || return 1
      ;;
    *)
      return 1
      ;;
  esac

  # Normal case: transport interface is saved explicitly.
  if [ -n "${WG_TRANSPORT_IFACE:-}" ] && [ "${WG_TRANSPORT_IFACE}" = "$expected_ifc" ]; then
    return 0
  fi

  # Backward compatibility: older metadata may only use same-number transport.
  [ "$wg_id" = "$transport_id" ]
}

# Prevent accidental removal of a GRE/Vira7 transport that still has a WireGuard tunnel on top.
# This avoids the common "I removed one tunnel and the others stopped" case.
remove_selection_dependency_guard() {
  local -a selected=("$@")
  local idx i type id wg_ids wg_id blocked=0

  for idx in "${selected[@]}"; do
    i=$((idx - 1))
    type="${INV_TYPE[$i]:-}"
    id="${INV_ID[$i]:-}"

    case "$type" in
      gre|vira7)
        wg_ids="$(wg_collect_ids || true)"
        while IFS= read -r wg_id; do
          [ -n "$wg_id" ] || continue
          if wg_uses_transport_tunnel "$wg_id" "$type" "$id"; then
            if ! selection_has_type_id "wireguard" "$wg_id" "${selected[@]}"; then
              warn_msg "Cannot remove $type tunnel $id alone: WireGuard tunnel $wg_id is using it as transport."
              echo "  Select the WireGuard tunnel row too, or remove/change that WireGuard tunnel first."
              blocked=1
            fi
          fi
        done <<< "$wg_ids"
        ;;
    esac
  done

  [ "$blocked" -eq 0 ]
}

gre_apply_firewall_rules() {
  local id="$1"
  local ifc
  validate_tunnel_id "$id" || return 1
  gre_load_config "$id" || return 1
  ifc="$(gre_iface "$id")"
  enable_ip_forward
  firewall_allow_ip_peer "GRE tunnel $id remote public" "${REMOTE_PUBLIC_IP:-}" "$ifc" >/dev/null 2>&1 || true
  firewall_allow_ip_peer "GRE tunnel $id remote inner" "${REMOTE_GRE_IP:-}" "$ifc" >/dev/null 2>&1 || true
}

# After deleting selected tunnels, re-apply firewall rules and revive only remaining tunnels
# that are enabled but inactive. Active tunnels are not restarted.
heal_remaining_tunnels_after_remove() {
  local ids id ifc svc
  echo
  echo -e "${C_CYAN}Re-checking remaining tunnels and re-applying firewall rules...${C_RESET}"

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if gre_load_config "$id"; then
      ifc="$(gre_iface "$id")"
      gre_apply_firewall_rules "$id" || true
      svc="$(gre_service_name "$id")"
      if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$svc" 2>/dev/null && ! ip link show "$ifc" >/dev/null 2>&1; then
        warn_msg "Remaining GRE tunnel $id is enabled but inactive; restarting only this tunnel."
        systemctl restart "$svc" 2>/dev/null || gre_service_start "$id" || true
      fi
    fi
  done <<< "$ids"

  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if vira7_load_config "$id"; then
      ifc="$(vira7_iface_name "$id")"
      vira7_apply_firewall_rules "$id" >/dev/null 2>&1 || true
      svc="$(vira7_service_name "$id")"
      if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$svc" 2>/dev/null && ! ip link show "$ifc" >/dev/null 2>&1; then
        warn_msg "Remaining Vira7 tunnel $id is enabled but inactive; restarting only this tunnel."
        systemctl restart "$svc" 2>/dev/null || true
      fi
    fi
  done <<< "$ids"

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if wg_load_meta "$id"; then
      ifc="$(wg_iface_name "$id")"
      wg_apply_firewall_rules "$id" >/dev/null 2>&1 || true
      svc="$(wg_service_name "$id")"
      if [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ] && command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$svc" 2>/dev/null && ! ip link show "$ifc" >/dev/null 2>&1; then
        warn_msg "Remaining WireGuard tunnel $id is enabled but inactive; restarting only this tunnel."
        systemctl restart "$svc" 2>/dev/null || true
      fi
    fi
  done <<< "$ids"

  ok_msg "Remaining tunnel firewall/health check finished."
}

menu_config_tunnel() {
  show_header "Create / Update Tunnel"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_menu_config_tunnel ;;
    wireguard) wg_menu_config_tunnel ;;
    vira7) vira7_menu_config_tunnel ;;
  esac
}

status_check() {
  show_header "Tunnel Status"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_status_check ;;
    wireguard) wg_status_check ;;
  esac
}

remove_tun() {
  show_header "Remove Tunnel"
  build_tunnel_inventory
  print_tunnel_inventory || return

  echo -e "${C_RED}${C_BOLD}88) remove ALL tunnels${C_RESET}"
  echo "Select one or more tunnel row numbers from the list."
  echo "Examples: 1 2 5  OR  1,2,5"
  echo "Use 88 to remove everything. Use 00 to return to main menu."
  echo
  local selected normalized token count idx i phase
  read -rp "Choose tunnel(s) to remove [number(s)/88/00]: " selected
  if is_main_menu_token "$selected"; then return_main_msg; return 99; fi

  if [ "$selected" = "88" ]; then
    echo
    echo -e "${C_RED}${C_BOLD}WARNING:${C_RESET} this will remove ALL GRE, WireGuard, and Vira7 tunnels."
    if ! confirm_yes "Are you sure?"; then
      echo "Cancelled."
      return
    fi

    local ids id
    # Remove UDP/overlay tunnels first, then GRE transport last.
    ids="$(wg_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && wg_remove_one_tunnel "$id"; done <<< "$ids"
    ids="$(vira7_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && vira7_remove_one_tunnel "$id"; done <<< "$ids"
    ids="$(gre_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && gre_remove_one_tunnel "$id"; done <<< "$ids"
    ok_msg "All tunnels removed."
    return
  fi

  normalized="$(printf '%s' "$selected" | tr ',' ' ')"
  count="${#INV_TYPE[@]}"

  local -a SELECTED_INDEXES=()
  local seen=" "

  for token in $normalized; do
    if ! [[ "$token" =~ ^[0-9]+$ ]]; then
      err_msg "Invalid selection: $token"
      return
    fi
    if [ "$token" -lt 1 ] || [ "$token" -gt "$count" ]; then
      err_msg "Tunnel row number out of range: $token"
      return
    fi
    # de-duplicate while preserving user's order.
    if [[ "$seen" != *" $token "* ]]; then
      SELECTED_INDEXES+=("$token")
      seen+="$token "
    fi
  done

  if [ "${#SELECTED_INDEXES[@]}" -eq 0 ]; then
    err_msg "No tunnel selected."
    return
  fi

  if ! remove_selection_dependency_guard "${SELECTED_INDEXES[@]}"; then
    echo
    err_msg "Removal stopped to avoid breaking dependent tunnels."
    echo "Tip: if you really want to remove the transport tunnel too, select its WireGuard row together with it."
    return 1
  fi

  echo
  echo -e "${C_BOLD}${C_WHITE}Selected tunnel(s) for removal:${C_RESET}"
  for idx in "${SELECTED_INDEXES[@]}"; do
    i=$((idx - 1))
    printf "  - row %s: %s tunnel %s (%s) -> remote %s
"       "$idx" "${INV_TYPE[$i]}" "${INV_ID[$i]}" "${INV_IFACE[$i]}" "${INV_TARGET[$i]:-N/A}"
  done
  echo

  if ! confirm_yes "Remove selected tunnel(s) completely?"; then
    echo "Cancelled."
    return
  fi

  # Remove in dependency-safe order. WireGuard may depend on GRE/Vira transport,
  # so overlay tunnels are removed first, GRE transport last.
  for phase in wireguard vira7 gre; do
    for idx in "${SELECTED_INDEXES[@]}"; do
      i=$((idx - 1))
      if [ "${INV_TYPE[$i]}" = "$phase" ]; then
        echo
        echo -e "${C_CYAN}Removing row $idx: ${INV_TYPE[$i]} ${INV_ID[$i]} (${INV_IFACE[$i]})${C_RESET}"
        if ! remove_inventory_item "$idx"; then
          warn_msg "Could not fully remove row $idx (${INV_TYPE[$i]} ${INV_ID[$i]}). Continue with the next selected tunnel."
        fi
      fi
    done
  done

  heal_remaining_tunnels_after_remove || true
  ok_msg "Selected tunnel removal finished."
}



list_saved_tunnels() {
  show_header "Saved / Active Tunnels"
  gre_list_tunnels
  echo
  wg_list_tunnels
  echo
  vira7_list_tunnels
}

ping4_target() {
  local label="$1"
  local target_ip="$2"
  if [ -z "${target_ip:-}" ]; then
    echo "[SKIP] $label: remote IP is empty"
    return 1
  fi
  target_ip="${target_ip%%/*}"
  echo
  echo "============================================================"
  echo "Testing: $label"
  echo "Target : $target_ip"
  echo "Command: ping -c 4 -W 2 $target_ip"
  echo "------------------------------------------------------------"
  if ping -c 4 -W 2 "$target_ip"; then
    echo "[OK] $label ping success"
    return 0
  fi
  echo "[FAIL] $label ping failed"
  return 1
}

test_gre_tunnel_ping() {
  local id="$1"
  if ! gre_load_config "$id"; then
    echo "[SKIP] GRE tunnel $id: no saved config"
    return 1
  fi
  local target="${REMOTE_GRE_IP:-}"
  if [ -z "$target" ] && [ -n "${ROLE:-}" ]; then
    target="$(gre_remote_inner_ip_for_role "$id" "$ROLE")"
  fi
  ping4_target "GRE tunnel $id ($(gre_iface "$id")) remote inner IP" "$target"
}

test_wg_tunnel_ping() {
  local id="$1"
  if ! wg_load_meta "$id"; then
    echo "[SKIP] WireGuard tunnel $id: no saved metadata"
    return 1
  fi
  if [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
    echo "[SKIP] WireGuard tunnel $id: pending peer public key"
    return 1
  fi
  ping4_target "WireGuard tunnel $id ($(wg_iface_name "$id")) remote inner IP" "${REMOTE_WG_IP:-}"
}

test_vira7_tunnel_ping() {
  local id="$1"
  if ! vira7_load_config "$id"; then
    echo "[SKIP] Vira7 tunnel $id: no saved config"
    return 1
  fi
  ping4_target "Vira7 tunnel $id ($(vira7_iface_name "$id")) remote inner IP" "${REMOTE_VIRA7_IP:-${remote_priv:-}}"
}

test_one_tunnel_ping_menu() {
  show_header "Test One Tunnel"
  ask_tunnel_type || return
  echo
  prompt_tunnel_id "Enter tunnel number to test [1-254]: " || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) test_gre_tunnel_ping "$TUNNEL_ID" ;;
    wireguard) test_wg_tunnel_ping "$TUNNEL_ID" ;;
    vira7) test_vira7_tunnel_ping "$TUNNEL_ID" ;;
  esac
}

test_all_tunnels_ping() {
  show_header "Test All Tunnels"
  local ids id total=0 ok=0 fail=0

  echo "Testing all saved GRE tunnels..."
  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    total=$((total + 1))
    if test_gre_tunnel_ping "$id"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
  done <<< "$ids"

  echo
  echo "Testing all saved WireGuard tunnels..."
  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    total=$((total + 1))
    if test_wg_tunnel_ping "$id"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
  done <<< "$ids"

  echo
  echo "Testing all saved Vira7 tunnels..."
  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    total=$((total + 1))
    if test_vira7_tunnel_ping "$id"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
  done <<< "$ids"

  echo
  echo "============================================================"
  echo "Ping test summary: total=$total ok=$ok failed_or_skipped=$fail"
  echo "============================================================"
}

test_tunnels_menu() {
  show_header "Tunnel Ping Test"
  build_tunnel_inventory
  print_tunnel_inventory || return

  echo -e "${C_GREEN}${C_BOLD}0) ping ALL tunnels${C_RESET}"
  echo "Select a tunnel number from the list, or 0 to ping all."
  echo
  read -rp "Choose tunnel to ping [0/list number] (00=menu): " selected
  if is_main_menu_token "$selected"; then return_main_msg; return 99; fi

  if [ "$selected" = "0" ]; then
    local i total ok fail
    total="${#INV_TYPE[@]}"; ok=0; fail=0
    for i in "${!INV_TYPE[@]}"; do
      if ping_inventory_item "$((i + 1))"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
    done
    echo
    echo -e "${C_BOLD}Ping summary:${C_RESET} total=$total ok=${C_GREEN}$ok${C_RESET} failed_or_skipped=${C_RED}$fail${C_RESET}"
    return
  fi

  if ! [[ "$selected" =~ ^[0-9]+$ ]] || [ "$selected" -lt 1 ] || [ "$selected" -gt "${#INV_TYPE[@]}" ]; then
    err_msg "Invalid selection."
    return
  fi

  ping_inventory_item "$selected"
}


reset_all_tunnels() {
  show_header "Reset All Tunnels"
  echo "This will restart/recreate all saved GRE, WireGuard, and Vira7 tunnels from their saved configs."
  echo "It will also re-enable their systemd services for boot."
  echo
  if ! confirm_yes "Continue with reset all tunnels?"; then
    echo "Cancelled."
    return
  fi

  echo
  echo "Stopping WireGuard and Vira7 first..."
  local ids id

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl stop "$(wg_service_name "$id")" 2>/dev/null || true
    wg-quick down "$(wg_iface_name "$id")" >/dev/null 2>&1 || true
    ip link delete "$(wg_iface_name "$id")" 2>/dev/null || true
  done <<< "$ids"

  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl stop "$(vira7_service_name "$id")" 2>/dev/null || true
    ip link delete "$(vira7_iface_name "$id")" 2>/dev/null || true
  done <<< "$ids"

  echo "Stopping GRE tunnels..."
  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ip link set dev "$(gre_iface "$id")" down 2>/dev/null || true
    ip tunnel del "$(gre_iface "$id")" 2>/dev/null || true
    ip link delete "$(gre_iface "$id")" 2>/dev/null || true
  done <<< "$ids"

  echo
  echo "Starting GRE tunnels..."
  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if gre_load_config "$id"; then
      if gre_create_tunnel 0 && gre_install_service "$id"; then
        echo "[OK] GRE tunnel $id reset"
      else
        echo "[WARN] GRE tunnel $id reset failed"
      fi
    fi
  done <<< "$ids"

  echo
  echo "Starting Vira7 tunnels..."
  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if vira7_restart_one_tunnel "$id"; then
      echo "[OK] Vira7 tunnel $id reset"
    else
      echo "[WARN] Vira7 tunnel $id reset failed"
    fi
  done <<< "$ids"

  echo
  echo "Starting WireGuard tunnels..."
  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if wg_load_meta "$id" && [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
      echo "[SKIP] WireGuard tunnel $id is pending peer key"
      continue
    fi
    if wg_restart_one_tunnel "$id"; then
      echo "[OK] WireGuard tunnel $id reset"
    else
      echo "[WARN] WireGuard tunnel $id reset failed"
    fi
  done <<< "$ids"

  echo
  echo "[OK] Reset all finished."
}

# -----------------------------
# HAProxy port forward manager
# -----------------------------
haproxy_base_header() {
  # Silent WebSocket-safe profile:
  # - no access logging by default, so HAProxy does not spam journald/syslog for every WS request
  # - keep HTTP mode for WebSocket forwarding
  # - longer tunnel timeout + TCP keepalive to avoid random long-lived WS drops
  cat <<EOF_HEADER
global
    maxconn ${HAPROXY_MAXCONN}
    daemon
    stats socket /run/haproxy/admin.sock mode 660 level admin

defaults
    mode http
    option dontlognull
    option clitcpka
    option srvtcpka
    timeout connect 10s
    timeout http-request 15s
    timeout queue 30s
    timeout client 2h
    timeout server 2h
    timeout client-fin 30s
    timeout server-fin 30s
    timeout tunnel 12h
EOF_HEADER
}

haproxy_is_installed() {
  command -v haproxy >/dev/null 2>&1
}

haproxy_install_package() {
  if haproxy_is_installed; then
    ok_msg "HAProxy is already installed."
    return 0
  fi

  info_msg "HAProxy is not installed. Installing now..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y haproxy
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y haproxy
  elif command -v yum >/dev/null 2>&1; then
    yum install -y haproxy
  else
    err_msg "No supported package manager found. Install haproxy manually first."
    return 1
  fi

  if ! haproxy_is_installed; then
    err_msg "HAProxy نصب نشد. این بخش بدون نصب HAProxy کار نمی‌کند؛ حتماً باید نصبش کنی."
    return 1
  fi

  systemctl enable haproxy >/dev/null 2>&1 || true
  ok_msg "HAProxy installed."
}

haproxy_apply_high_limits() {
  # HAProxy cannot truly have an unlimited connection count; it is bound by RAM, CPU,
  # kernel limits, and available file descriptors. Use a high practical limit instead.
  mkdir -p /etc/systemd/system/haproxy.service.d /etc/security/limits.d /etc/sysctl.d 2>/dev/null || true

  cat > /etc/systemd/system/haproxy.service.d/99-gretun-limits.conf <<EOF_LIMIT
[Service]
LimitNOFILE=${HAPROXY_NOFILE_LIMIT}
TasksMax=infinity
EOF_LIMIT

  cat > /etc/security/limits.d/99-gretun-haproxy.conf <<EOF_SECURITY
* soft nofile ${HAPROXY_NOFILE_LIMIT}
* hard nofile ${HAPROXY_NOFILE_LIMIT}
root soft nofile ${HAPROXY_NOFILE_LIMIT}
root hard nofile ${HAPROXY_NOFILE_LIMIT}
EOF_SECURITY

  cat > /etc/sysctl.d/99-gretun-haproxy.conf <<EOF_SYSCTL
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_tw_reuse = 1
net.netfilter.nf_conntrack_max = 1048576
EOF_SYSCTL
  sysctl -p /etc/sysctl.d/99-gretun-haproxy.conf >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
}

haproxy_ensure_maxconn_in_config() {
  [ -f "$HAPROXY_CONFIG" ] || return 0

  if grep -Eq '^[[:space:]]*maxconn[[:space:]]+' "$HAPROXY_CONFIG"; then
    sed -i -E "s/^[[:space:]]*maxconn[[:space:]]+[0-9]+/    maxconn ${HAPROXY_MAXCONN}/" "$HAPROXY_CONFIG" || true
  else
    awk -v mc="$HAPROXY_MAXCONN" '
      BEGIN { in_global=0; inserted=0 }
      /^[[:space:]]*global[[:space:]]*$/ { print; in_global=1; next }
      in_global && !inserted && /^[[:space:]]*defaults[[:space:]]*$/ { print "    maxconn " mc; inserted=1; in_global=0; print; next }
      { print }
      END { if (in_global && !inserted) print "    maxconn " mc }
    ' "$HAPROXY_CONFIG" > "$HAPROXY_CONFIG.tmp.$$" && mv -f "$HAPROXY_CONFIG.tmp.$$" "$HAPROXY_CONFIG"
  fi
}

haproxy_ensure_ready() {
  haproxy_install_package || return 1
  haproxy_apply_high_limits
  mkdir -p /etc/haproxy "$HAPROXY_BACKUP_DIR"
  if [ ! -f "$HAPROXY_CONFIG" ]; then
    haproxy_base_header > "$HAPROXY_CONFIG"
  else
    haproxy_ensure_maxconn_in_config
  fi
  systemctl restart haproxy >/dev/null 2>&1 || true
}

haproxy_normalize_proto() {
  local proto="${1:-http}"
  proto="$(printf '%s' "$proto" | tr '[:upper:]' '[:lower:]')"
  case "$proto" in
    tcp) echo "tcp" ;;
    *) echo "http" ;;
  esac
}

haproxy_toggle_proto() {
  local proto
  proto="$(haproxy_normalize_proto "${1:-http}")"
  if [ "$proto" = "tcp" ]; then
    echo "http"
  else
    echo "tcp"
  fi
}

haproxy_export_entries() {
  # Output: local_port target_ip target_port protocol
  # Older configs without a saved protocol are treated as http.
  [ -f "$HAPROXY_CONFIG" ] || return 0
  awk '
    /^[[:space:]]*backend[[:space:]]+ws_[0-9]+_out[[:space:]]*$/ {
      p=$2; sub(/^ws_/, "", p); sub(/_out$/, "", p); proto="http"; next
    }
    p != "" && /^[[:space:]]*mode[[:space:]]+/ {
      proto=$2; next
    }
    /^[[:space:]]*server[[:space:]]+/ && p != "" {
      split($3, a, ":");
      if (a[1] != "" && a[2] != "") {
        if (proto != "tcp") proto="http";
        print p, a[1], a[2], proto;
      }
      p=""; proto="http";
    }
  ' "$HAPROXY_CONFIG" | sort -n -k1,1 -u
}

haproxy_list_forwards() {
  echo -e "${C_BOLD}${C_WHITE}HAProxy forwarded ports:${C_RESET}"
  local entries proto color
  entries="$(haproxy_export_entries || true)"
  if [ -z "$entries" ]; then
    warn_msg "No forwarded ports found in $HAPROXY_CONFIG"
    return 0
  fi
  printf "${C_DIM}%8s  %-15s %-12s %-8s${C_RESET}\n" "Port" "Target-IP" "Target-Port" "Protocol"
  printf "${C_DIM}%s${C_RESET}\n" "-----------------------------------------------------"
  while read -r port ip tport proto; do
    [ -n "${port:-}" ] || continue
    proto="$(haproxy_normalize_proto "${proto:-http}")"
    if [ "$proto" = "tcp" ]; then color="$C_YELLOW"; else color="$C_CYAN"; fi
    printf "%8s  ${C_MAGENTA}%-15s${C_RESET} %-12s ${color}%-8s${C_RESET}\n" "$port" "$ip" "$tport" "$proto"
  done <<< "$entries"
}

haproxy_open_firewall_tcp() {
  local port="$1"
  validate_port "$port" || return 0
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT || true
    iptables -C OUTPUT -p tcp --sport "$port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p tcp --sport "$port" -j ACCEPT || true
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port/tcp" >/dev/null 2>&1 || true
  fi
}

haproxy_validate_and_restart() {
  local tmp="$1"
  # Validate quietly first so HAProxy NOTICE/WARNING lines do not confuse the menu output.
  # If validation fails, run it again without -q to print the real error.
  if ! haproxy -c -q -f "$tmp" >/dev/null 2>&1; then
    haproxy -c -f "$tmp" || true
    err_msg "HAProxy config validation failed. Nothing changed."
    rm -f "$tmp"
    return 1
  fi
  mkdir -p "$HAPROXY_BACKUP_DIR"
  if [ -f "$HAPROXY_CONFIG" ]; then
    cp -f "$HAPROXY_CONFIG" "$HAPROXY_BACKUP_DIR/haproxy.cfg.$(date +%Y%m%d-%H%M%S).bak" 2>/dev/null || true
  fi
  mv -f "$tmp" "$HAPROXY_CONFIG"
  haproxy_apply_high_limits
  haproxy_ensure_maxconn_in_config
  systemctl enable haproxy >/dev/null 2>&1 || true
  if systemctl restart haproxy; then
    ok_msg "HAProxy restarted successfully."
    return 0
  fi
  err_msg "HAProxy restart failed. Check: journalctl -u haproxy -n 50 --no-pager"
  return 1
}

haproxy_write_entries_file() {
  local entries_file="$1"
  local tmp proto
  tmp="$(mktemp)"
  haproxy_base_header > "$tmp"
  if [ -s "$entries_file" ]; then
    while read -r port ip tport proto; do
      [ -n "${port:-}" ] || continue
      validate_port "$port" || continue
      validate_ipv4 "$ip" || continue
      validate_port "${tport:-$port}" || tport="$port"
      proto="$(haproxy_normalize_proto "${proto:-http}")"

      if [ "$proto" = "tcp" ]; then
        cat >> "$tmp" <<EOF_BLOCK

frontend ws_${port}_in
    bind *:${port}
    mode tcp
    no log
    default_backend ws_${port}_out

backend ws_${port}_out
    mode tcp
    no log
    server foreign_${port} ${ip}:${tport}
EOF_BLOCK
      else
        cat >> "$tmp" <<EOF_BLOCK

frontend ws_${port}_in
    bind *:${port}
    mode http
    no log
    option forwardfor
    default_backend ws_${port}_out

backend ws_${port}_out
    mode http
    no log
    option http-keep-alive
    server foreign_${port} ${ip}:${tport}
EOF_BLOCK
      fi
      haproxy_open_firewall_tcp "$port"
    done < <(sort -n -k1,1 -u "$entries_file")
  fi
  haproxy_validate_and_restart "$tmp"
}

haproxy_entries_tmp() {
  local tmp
  tmp="$(mktemp)"
  haproxy_export_entries > "$tmp" || true
  echo "$tmp"
}

haproxy_add_port() {
  local port ip tmp existing_proto
  echo "00) Back to main menu"
  read -rp "Enter local port to forward (00=menu): " port
  if is_main_menu_token "$port"; then return_main_msg; return 99; fi
  validate_port "$port" || { err_msg "Invalid port."; return 1; }
  read -rp "Enter target IP for port $port (00=menu): " ip
  if is_main_menu_token "$ip"; then return_main_msg; return 99; fi
  validate_ipv4 "$ip" || { err_msg "Invalid IPv4."; return 1; }

  tmp="$(haproxy_entries_tmp)"
  existing_proto="$(awk -v p="$port" '$1==p{print $4; exit}' "$tmp")"
  existing_proto="$(haproxy_normalize_proto "${existing_proto:-http}")"
  if awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$tmp"; then
    warn_msg "Port $port already exists; replacing its target IP and keeping protocol: $existing_proto"
  fi
  awk -v p="$port" '$1!=p' "$tmp" > "$tmp.new" || true
  printf '%s %s %s %s\n' "$port" "$ip" "$port" "$existing_proto" >> "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
}

haproxy_change_all_ips() {
  local ip tmp
  tmp="$(haproxy_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No forwarded ports to update."; rm -f "$tmp"; return 0; fi
  echo "00) Back to main menu"
  read -rp "Enter new target IP for ALL ports (00=menu): " ip
  if is_main_menu_token "$ip"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_ipv4 "$ip" || { err_msg "Invalid IPv4."; rm -f "$tmp"; return 1; }
  awk -v ip="$ip" '{proto=$4; if(proto=="") proto="http"; print $1, ip, $3, proto}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
}

haproxy_delete_port() {
  local port tmp before after
  tmp="$(haproxy_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No forwarded ports to delete."; rm -f "$tmp"; return 0; fi
  haproxy_list_forwards
  echo
  echo "00) Back to main menu"
  read -rp "Enter local port to delete (00=menu): " port
  if is_main_menu_token "$port"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_port "$port" || { err_msg "Invalid port."; rm -f "$tmp"; return 1; }
  before="$(wc -l < "$tmp" | tr -d ' ')"
  awk -v p="$port" '$1!=p' "$tmp" > "$tmp.new" || true
  after="$(wc -l < "$tmp.new" | tr -d ' ')"
  if [ "$before" = "$after" ]; then warn_msg "Port $port was not found."; rm -f "$tmp" "$tmp.new"; return 0; fi
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
}

haproxy_change_one_ip() {
  local port ip tmp
  tmp="$(haproxy_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No forwarded ports to update."; rm -f "$tmp"; return 0; fi
  haproxy_list_forwards
  echo
  echo "00) Back to main menu"
  read -rp "Enter local port to change IP (00=menu): " port
  if is_main_menu_token "$port"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_port "$port" || { err_msg "Invalid port."; rm -f "$tmp"; return 1; }
  if ! awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$tmp"; then
    warn_msg "Port $port was not found."
    rm -f "$tmp"
    return 0
  fi
  read -rp "Enter new target IP for port $port (00=menu): " ip
  if is_main_menu_token "$ip"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_ipv4 "$ip" || { err_msg "Invalid IPv4."; rm -f "$tmp"; return 1; }
  awk -v p="$port" -v ip="$ip" '{proto=$4; if(proto=="") proto="http"; if ($1==p) print $1, ip, $3, proto; else print $1, $2, $3, proto}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
}

haproxy_show_protocol_rows() {
  local entries="$1"
  local n=0 proto color
  printf "${C_DIM}%4s  %8s  %-15s %-12s %-8s${C_RESET}\n" "No" "Port" "Target-IP" "Target-Port" "Protocol"
  printf "${C_DIM}%s${C_RESET}\n" "------------------------------------------------------------"
  while read -r port ip tport proto; do
    [ -n "${port:-}" ] || continue
    n=$((n + 1))
    proto="$(haproxy_normalize_proto "${proto:-http}")"
    if [ "$proto" = "tcp" ]; then color="$C_YELLOW"; else color="$C_CYAN"; fi
    printf "%4s  %8s  ${C_MAGENTA}%-15s${C_RESET} %-12s ${color}%-8s${C_RESET}\n" "$n" "$port" "$ip" "$tport" "$proto"
  done <<< "$entries"
}

haproxy_change_protocol() {
  local tmp entries selected total port old_proto new_proto
  tmp="$(haproxy_entries_tmp)"
  entries="$(cat "$tmp")"
  if [ ! -s "$tmp" ]; then
    warn_msg "No forwarded ports found."
    rm -f "$tmp"
    return 0
  fi

  echo -e "${C_BOLD}${C_WHITE}Change HAProxy protocol:${C_RESET}"
  haproxy_show_protocol_rows "$entries"
  echo
  echo -e "${C_GREEN}0)${C_RESET} toggle protocol for ALL ports"
  echo -e "${C_DIM}00) Back to main menu${C_RESET}"
  echo
  read -rp "Choose row number to toggle protocol [number/0/00]: " selected

  if is_main_menu_token "$selected"; then rm -f "$tmp"; return_main_msg; return 99; fi

  if [ "$selected" = "0" ]; then
    awk '{proto=$4; if(proto=="") proto="http"; if(proto=="tcp") proto="http"; else proto="tcp"; print $1, $2, $3, proto}' "$tmp" > "$tmp.new"
    mv -f "$tmp.new" "$tmp"
    haproxy_write_entries_file "$tmp"
    rm -f "$tmp"
    ok_msg "Protocol toggled for all HAProxy ports."
    return 0
  fi

  [[ "$selected" =~ ^[0-9]+$ ]] || { err_msg "Invalid selection."; rm -f "$tmp"; return 1; }
  total="$(wc -l < "$tmp" | tr -d ' ')"
  if [ "$selected" -lt 1 ] || [ "$selected" -gt "$total" ]; then
    err_msg "Selected row not found."
    rm -f "$tmp"
    return 1
  fi

  port="$(awk -v n="$selected" 'NR==n{print $1}' "$tmp")"
  old_proto="$(awk -v n="$selected" 'NR==n{print $4}' "$tmp")"
  old_proto="$(haproxy_normalize_proto "${old_proto:-http}")"
  new_proto="$(haproxy_toggle_proto "$old_proto")"

  awk -v n="$selected" -v newp="$new_proto" '{proto=$4; if(proto=="") proto="http"; if(NR==n) proto=newp; print $1, $2, $3, proto}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
  ok_msg "Port $port protocol changed: $old_proto -> $new_proto"
}


haproxy_optimize_websocket_nolog() {
  local tmp count
  tmp="$(haproxy_entries_tmp)"
  if [ ! -s "$tmp" ]; then
    warn_msg "No forwarded ports found to optimize."
    rm -f "$tmp"
    return 0
  fi
  count="$(wc -l < "$tmp" | tr -d ' ')"
  info_msg "Rewriting $count HAProxy forward(s) with silent WebSocket-safe mode..."
  echo "This keeps the current protocol/IP/port unchanged; it disables HAProxy access logs and applies longer tunnel timeout + TCP keepalive."
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
  ok_msg "HAProxy silent WebSocket optimization applied. HTTP/WebSocket mode is preserved."
}

haproxy_run_action() {
  local rc
  set +e
  "$@"
  rc=$?
  set -e
  if [ "$rc" -eq 99 ]; then
    return 99
  fi
  pause
  return 0
}

haproxy_menu() {
  haproxy_ensure_ready || return 1
  while true; do
    show_header "HAProxy Port Forward Manager"
    echo -e "${C_BOLD}${C_WHITE}HAProxy Menu${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} list forwarded ports"
    echo -e "  ${C_GREEN}2)${C_RESET} add/update port"
    echo -e "  ${C_YELLOW}3)${C_RESET} change ALL target IPs"
    echo -e "  ${C_RED}4)${C_RESET} delete port"
    echo -e "  ${C_CYAN}5)${C_RESET} change target IP for one port"
    echo -e "  ${C_MAGENTA}6)${C_RESET} change protocol http/tcp"
    echo -e "  ${C_CYAN}7)${C_RESET} optimize WebSocket / silent HAProxy no access-log"
    echo -e "  ${C_DIM}00) Back to main menu${C_RESET}"
    echo
    read -rp "Choose HAProxy option [1-7/00]: " HAP_CHOICE
    case "$HAP_CHOICE" in
      1) haproxy_run_action haproxy_list_forwards || return 0 ;;
      2) haproxy_run_action haproxy_add_port || return 0 ;;
      3) haproxy_run_action haproxy_change_all_ips || return 0 ;;
      4) haproxy_run_action haproxy_delete_port || return 0 ;;
      5) haproxy_run_action haproxy_change_one_ip || return 0 ;;
      6) haproxy_run_action haproxy_change_protocol || return 0 ;;
      7) haproxy_run_action haproxy_optimize_websocket_nolog || return 0 ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

show_menu() {
  show_header "GRE + WireGuard + Vira7 Tunnel Management"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel"
  echo -e "  ${C_RED}2)${C_RESET} remove tunnel"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} haproxy port manager"
  echo -e "  ${C_BLUE}6)${C_RESET} optimize Vira7 CPU"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  read -rp "Choose an option [0-6]: " CHOICE
  case "$CHOICE" in
    1) if menu_config_tunnel; then pause; fi ;;
    2) if remove_tun; then pause; fi ;;
    3) if reset_all_tunnels; then pause; fi ;;
    4) if test_tunnels_menu; then pause; fi ;;
    5) haproxy_menu || true ;;
    6) if vira7_optimize_cpu_menu; then pause; fi ;;
    00) return_main_msg ;;
    0) echo "Bye"; exit 0 ;;
    *) err_msg "Invalid option"; sleep 1 ;;
  esac
}

# ============================================================================
# Tunnel Manager v9 additions
# These functions are intentionally defined after the legacy implementation.
# Bash uses the last function definition, allowing v9 to extend the manager
# without changing the Normal GRE implementation or old configuration files.
# ============================================================================

TM9_VERSION="9.0.0"
TM9_DIR="/etc/tunnel-manager-v9"
TM9_HEALTH_DIR="$TM9_DIR/health"
TM9_HEALTH_CONFIG="$TM9_DIR/health.conf"
TM9_HEALTH_SERVICE="/etc/systemd/system/tm9-health.service"
TM9_HEALTH_TIMER="/etc/systemd/system/tm9-health.timer"
TM9_HYBRID_SERVICE_TEMPLATE="/etc/systemd/system/tm9-hybrid@.service"
TM9_WSS_SERVICE_TEMPLATE="/etc/systemd/system/tm9-wss@.service"
TM9_WSTUNNEL_BIN="/usr/local/bin/wstunnel"
TM9_WSTUNNEL_VERSION="${TM9_WSTUNNEL_VERSION:-10.5.5}"
TM9_WGGRE_PORT_BASE=54000
TM9_WGVIRA_PORT_BASE=54400
TM9_WSS_WG_PORT_BASE=54800
TM9_WSS_CLIENT_LISTEN_BASE=55200
TM9_WSS_TCP_PORT_BASE=24000
TM9_HEALTH_DEFAULT_INTERVAL=30
TM9_HEALTH_DEFAULT_FAIL_LIMIT=3
TM9_HEALTH_DEFAULT_COOLDOWN=120

# Preserve access to the legacy reset implementation before overriding it.
if declare -F reset_all_tunnels >/dev/null 2>&1 && ! declare -F tm9_legacy_reset_all_tunnels >/dev/null 2>&1; then
  eval "$(declare -f reset_all_tunnels | sed '1s/reset_all_tunnels/tm9_legacy_reset_all_tunnels/')"
fi

# -----------------------------
# v9 shared helpers
# -----------------------------
tm9_prepare_dirs() {
  mkdir -p "$TM9_DIR" "$TM9_HEALTH_DIR" "$TM9_DIR/wggre/keys" "$TM9_DIR/wgvira/keys" "$TM9_DIR/hybrid" "$TM9_DIR/wss/keys"
  chmod 700 "$TM9_DIR" "$TM9_DIR/wggre/keys" "$TM9_DIR/wgvira/keys" "$TM9_DIR/wss/keys" 2>/dev/null || true
}

tm9_fixed_port() {
  local kind="$1" id="$2"
  case "$kind" in
    wggre) echo $((TM9_WGGRE_PORT_BASE + id)) ;;
    wgvira) echo $((TM9_WGVIRA_PORT_BASE + id)) ;;
    wss-wg) echo $((TM9_WSS_WG_PORT_BASE + id)) ;;
    wss-client) echo $((TM9_WSS_CLIENT_LISTEN_BASE + id)) ;;
    wss-tcp) echo $((TM9_WSS_TCP_PORT_BASE + id)) ;;
    *) return 1 ;;
  esac
}

tm9_port_range_text() {
  cat <<EOF
Reserved v9 port ranges (no automatic increment):
  WireGuard over GRE : $((TM9_WGGRE_PORT_BASE + 1))-$((TM9_WGGRE_PORT_BASE + 254))/udp
  WireGuard over Vira: $((TM9_WGVIRA_PORT_BASE + 1))-$((TM9_WGVIRA_PORT_BASE + 254))/udp
  WSS remote WG      : $((TM9_WSS_WG_PORT_BASE + 1))-$((TM9_WSS_WG_PORT_BASE + 254))/udp (loopback/server)
  WSS client WG      : $((TM9_WSS_CLIENT_LISTEN_BASE + 1))-$((TM9_WSS_CLIENT_LISTEN_BASE + 254))/udp
  WSS public TCP     : $((TM9_WSS_TCP_PORT_BASE + 1))-$((TM9_WSS_TCP_PORT_BASE + 254))/tcp
EOF
}

tm9_port_busy() {
  local proto="$1" port="$2"
  case "$proto" in
    udp)
      ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "(^|[:.])${port}$"
      ;;
    tcp)
      ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|[:.])${port}$"
      ;;
    *) return 1 ;;
  esac
}

tm9_validate_free_port() {
  local proto="$1" port="$2" label="$3"
  validate_port "$port" || { err_msg "Invalid $label port: $port"; return 1; }
  if tm9_port_busy "$proto" "$port"; then
    err_msg "$label port $port/$proto is already in use."
    echo "v9 will not silently select another port because both servers must use the same deterministic port."
    echo "Free the port or select another tunnel number."
    return 1
  fi
}

tm9_ping_quiet() {
  local target="$1" ifc="${2:-}"
  [ -n "$target" ] || return 1
  if [ -n "$ifc" ]; then
    ping -I "$ifc" -c 1 -W 1 "$target" >/dev/null 2>&1
  else
    ping -c 1 -W 1 "$target" >/dev/null 2>&1
  fi
}

tm9_generate_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 18
  else
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36
  fi
}

tm9_install_self() {
  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"
}

tm9_disable_rp_filter() {
  local ifc
  for ifc in "$@"; do
    [ -n "$ifc" ] || continue
    [ -e "/proc/sys/net/ipv4/conf/$ifc/rp_filter" ] && echo 0 > "/proc/sys/net/ipv4/conf/$ifc/rp_filter" 2>/dev/null || true
  done
  [ -e /proc/sys/net/ipv4/conf/all/rp_filter ] && echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true
}

tm9_write_health_defaults() {
  tm9_prepare_dirs
  if [ ! -f "$TM9_HEALTH_CONFIG" ]; then
    cat > "$TM9_HEALTH_CONFIG" <<EOF
ENABLED=0
INTERVAL=$TM9_HEALTH_DEFAULT_INTERVAL
FAIL_LIMIT=$TM9_HEALTH_DEFAULT_FAIL_LIMIT
COOLDOWN=$TM9_HEALTH_DEFAULT_COOLDOWN
EOF
    chmod 600 "$TM9_HEALTH_CONFIG"
  fi
}

tm9_health_is_enabled() {
  tm9_write_health_defaults
  local ENABLED=0
  # shellcheck disable=SC1090
  source "$TM9_HEALTH_CONFIG"
  [ "${ENABLED:-0}" = "1" ]
}

tm9_set_health_flag_in_file() {
  local file="$1" value="$2"
  [ -f "$file" ] || return 0
  set_config_kv "$file" HEALTH_ENABLED "$value"
}

# -----------------------------
# Isolated WireGuard overlays over GRE/Vira7
# -----------------------------
tm9_overlay_dir() { echo "$TM9_DIR/$1"; }
tm9_overlay_meta() { echo "$(tm9_overlay_dir "$1")/tunnel-$2.conf"; }
tm9_overlay_iface() {
  case "$1" in
    wggre) echo "wggre$2" ;;
    wgvira) echo "wgvira$2" ;;
    *) return 1 ;;
  esac
}
tm9_overlay_key_private() { echo "$(tm9_overlay_dir "$1")/keys/tunnel-$2.private"; }
tm9_overlay_key_public() { echo "$(tm9_overlay_dir "$1")/keys/tunnel-$2.public"; }
tm9_overlay_wg_config() { echo "$WG_CONFIG_DIR/$(tm9_overlay_iface "$1" "$2").conf"; }
tm9_overlay_service() { echo "wg-quick@$(tm9_overlay_iface "$1" "$2").service"; }

tm9_overlay_base_octet() {
  case "$1" in
    wggre) echo 81 ;;
    wgvira) echo 82 ;;
    *) return 1 ;;
  esac
}

tm9_overlay_local_ip() {
  local octet role id
  octet="$(tm9_overlay_base_octet "$1")"; id="$2"; role="$3"
  if [ "$role" = "1" ]; then echo "10.${octet}.${id}.1"; else echo "10.${octet}.${id}.2"; fi
}

tm9_overlay_remote_ip() {
  local octet role id
  octet="$(tm9_overlay_base_octet "$1")"; id="$2"; role="$3"
  if [ "$role" = "1" ]; then echo "10.${octet}.${id}.2"; else echo "10.${octet}.${id}.1"; fi
}

tm9_hybrid_local_ip_for_role() {
  local id="$1" role="$2"
  if [ "$role" = "1" ]; then echo "10.83.${id}.1"; else echo "10.83.${id}.2"; fi
}

tm9_hybrid_remote_ip_for_role() {
  local id="$1" role="$2"
  if [ "$role" = "1" ]; then echo "10.83.${id}.2"; else echo "10.83.${id}.1"; fi
}

tm9_overlay_transport_iface() {
  case "$1" in
    wggre) gre_iface "$2" ;;
    wgvira) vira7_iface_name "$2" ;;
    *) return 1 ;;
  esac
}

tm9_overlay_transport_remote_ip() {
  local kind="$1" id="$2" role="$3"
  case "$kind" in
    wggre) gre_remote_inner_ip_for_role "$id" "$role" ;;
    wgvira) vira7_remote_inner_ip_for_role "$id" "$role" ;;
    *) return 1 ;;
  esac
}

tm9_overlay_default_port() {
  case "$1" in
    wggre) tm9_fixed_port wggre "$2" ;;
    wgvira) tm9_fixed_port wgvira "$2" ;;
    *) return 1 ;;
  esac
}

tm9_overlay_reset_vars() {
  unset TM9_KIND TM9_ID TM9_ROLE TM9_IFACE TM9_LOCAL_IP TM9_REMOTE_IP TM9_TRANSPORT_IFACE TM9_TRANSPORT_REMOTE_IP TM9_LISTEN_PORT TM9_REMOTE_PUBLIC_KEY TM9_MTU HEALTH_ENABLED 2>/dev/null || true
}

tm9_overlay_load() {
  local kind="$1" id="$2" file
  validate_tunnel_id "$id" || return 1
  file="$(tm9_overlay_meta "$kind" "$id")"
  [ -f "$file" ] || return 1
  tm9_overlay_reset_vars
  # shellcheck disable=SC1090
  source "$file"
  TM9_KIND="$kind"; TM9_ID="$id"
  TM9_IFACE="${TM9_IFACE:-$(tm9_overlay_iface "$kind" "$id")}" 
  TM9_LISTEN_PORT="${TM9_LISTEN_PORT:-$(tm9_overlay_default_port "$kind" "$id")}" 
  HEALTH_ENABLED="${HEALTH_ENABLED:-0}"
}

tm9_overlay_generate_keys() {
  local kind="$1" id="$2" private public
  wg_ensure_tools || return 1
  tm9_prepare_dirs
  private="$(tm9_overlay_key_private "$kind" "$id")"
  public="$(tm9_overlay_key_public "$kind" "$id")"
  if [ ! -s "$private" ]; then
    umask 077
    wg genkey > "$private"
    wg pubkey < "$private" > "$public"
    chmod 600 "$private"; chmod 644 "$public"
  elif [ ! -s "$public" ]; then
    wg pubkey < "$private" > "$public"
    chmod 644 "$public"
  fi
}

tm9_overlay_save() {
  local kind="$1" id="$2" file
  tm9_prepare_dirs
  file="$(tm9_overlay_meta "$kind" "$id")"
  {
    write_var TM9_KIND "$kind"
    write_var TM9_ID "$id"
    write_var TM9_ROLE "$TM9_ROLE"
    write_var TM9_IFACE "$TM9_IFACE"
    write_var TM9_LOCAL_IP "$TM9_LOCAL_IP"
    write_var TM9_REMOTE_IP "$TM9_REMOTE_IP"
    write_var TM9_TRANSPORT_IFACE "$TM9_TRANSPORT_IFACE"
    write_var TM9_TRANSPORT_REMOTE_IP "$TM9_TRANSPORT_REMOTE_IP"
    write_var TM9_LISTEN_PORT "$TM9_LISTEN_PORT"
    write_var TM9_REMOTE_PUBLIC_KEY "${TM9_REMOTE_PUBLIC_KEY:-}"
    write_var TM9_MTU "${TM9_MTU:-1280}"
    write_var HEALTH_ENABLED "${HEALTH_ENABLED:-0}"
  } > "$file"
  chmod 600 "$file"
}

tm9_overlay_write_wg_config() {
  local kind="$1" id="$2" private_key conf hybrid_remote
  private_key="$(cat "$(tm9_overlay_key_private "$kind" "$id")")"
  conf="$(tm9_overlay_wg_config "$kind" "$id")"
  hybrid_remote="$(tm9_hybrid_remote_ip_for_role "$id" "$TM9_ROLE")"
  mkdir -p "$WG_CONFIG_DIR"
  chmod 700 "$WG_CONFIG_DIR" 2>/dev/null || true
  cat > "$conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = $TM9_LOCAL_IP/30
ListenPort = $TM9_LISTEN_PORT
MTU = ${TM9_MTU:-1280}
Table = off

[Peer]
PublicKey = $TM9_REMOTE_PUBLIC_KEY
Endpoint = $TM9_TRANSPORT_REMOTE_IP:$TM9_LISTEN_PORT
AllowedIPs = $TM9_REMOTE_IP/32, $hybrid_remote/32
PersistentKeepalive = 15
EOF
  chmod 600 "$conf"
}

tm9_overlay_apply_firewall() {
  local kind="$1" id="$2"
  tm9_overlay_load "$kind" "$id" || return 1
  enable_ip_forward
  tm9_disable_rp_filter "$TM9_IFACE" "$TM9_TRANSPORT_IFACE"
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -i "$TM9_TRANSPORT_IFACE" -p udp --dport "$TM9_LISTEN_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$TM9_TRANSPORT_IFACE" -p udp --dport "$TM9_LISTEN_PORT" -j ACCEPT || true
    iptables -C OUTPUT -o "$TM9_TRANSPORT_IFACE" -p udp -d "$TM9_TRANSPORT_REMOTE_IP" --dport "$TM9_LISTEN_PORT" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$TM9_TRANSPORT_IFACE" -p udp -d "$TM9_TRANSPORT_REMOTE_IP" --dport "$TM9_LISTEN_PORT" -j ACCEPT || true
    iptables -C INPUT -i "$TM9_IFACE" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$TM9_IFACE" -j ACCEPT || true
    iptables -C OUTPUT -o "$TM9_IFACE" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$TM9_IFACE" -j ACCEPT || true
    iptables -C FORWARD -i "$TM9_IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$TM9_IFACE" -j ACCEPT || true
    iptables -C FORWARD -o "$TM9_IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$TM9_IFACE" -j ACCEPT || true
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow in on "$TM9_TRANSPORT_IFACE" to any port "$TM9_LISTEN_PORT" proto udp >/dev/null 2>&1 || true
    ufw allow in on "$TM9_IFACE" >/dev/null 2>&1 || true
  fi
}

tm9_overlay_start() {
  local kind="$1" id="$2" svc conf
  tm9_overlay_load "$kind" "$id" || return 1
  [ -n "${TM9_REMOTE_PUBLIC_KEY:-}" ] || { warn_msg "$kind tunnel $id is pending the peer key."; return 0; }
  conf="$(tm9_overlay_wg_config "$kind" "$id")"
  [ -f "$conf" ] || tm9_overlay_write_wg_config "$kind" "$id"
  tm9_overlay_apply_firewall "$kind" "$id" || true
  svc="$(tm9_overlay_service "$kind" "$id")"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$svc" >/dev/null 2>&1 || true
  wg-quick down "$TM9_IFACE" >/dev/null 2>&1 || true
  ip link delete "$TM9_IFACE" 2>/dev/null || true
  if systemctl restart "$svc"; then
    ok_msg "$kind tunnel $id started as $TM9_IFACE"
  else
    systemctl status "$svc" --no-pager -l 2>/dev/null || true
    return 1
  fi
}

tm9_overlay_configure() {
  local kind="$1" existing_key="" existing_health=0 peer_input local_pub transport_label was_active=0 meta_bak="" conf_bak=""
  show_header "$( [ "$kind" = wggre ] && echo 'WireGuard over GRE' || echo 'WireGuard over Vira7' )"
  prompt_role || return
  TM9_ROLE="$ROLE"
  echo
  prompt_tunnel_id "Enter secure overlay tunnel number [1-254]: " || return
  TM9_ID="$TUNNEL_ID"
  TM9_IFACE="$(tm9_overlay_iface "$kind" "$TM9_ID")"
  TM9_TRANSPORT_IFACE="$(tm9_overlay_transport_iface "$kind" "$TM9_ID")"
  TM9_TRANSPORT_REMOTE_IP="$(tm9_overlay_transport_remote_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
  TM9_LOCAL_IP="$(tm9_overlay_local_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
  TM9_REMOTE_IP="$(tm9_overlay_remote_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
  TM9_LISTEN_PORT="$(tm9_overlay_default_port "$kind" "$TM9_ID")"
  TM9_MTU=1280
  HEALTH_ENABLED=0

  if tm9_overlay_load "$kind" "$TM9_ID"; then
    existing_key="${TM9_REMOTE_PUBLIC_KEY:-}"
    existing_health="${HEALTH_ENABLED:-0}"
    TM9_ROLE="$ROLE"
    TM9_IFACE="$(tm9_overlay_iface "$kind" "$TM9_ID")"
    TM9_TRANSPORT_IFACE="$(tm9_overlay_transport_iface "$kind" "$TM9_ID")"
    TM9_TRANSPORT_REMOTE_IP="$(tm9_overlay_transport_remote_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
    TM9_LOCAL_IP="$(tm9_overlay_local_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
    TM9_REMOTE_IP="$(tm9_overlay_remote_ip "$kind" "$TM9_ID" "$TM9_ROLE")"
    TM9_LISTEN_PORT="$(tm9_overlay_default_port "$kind" "$TM9_ID")"
    TM9_MTU="${TM9_MTU:-1280}"
  fi
  TM9_REMOTE_PUBLIC_KEY="$existing_key"
  HEALTH_ENABLED="$existing_health"

  if [ ! -f "/sys/class/net/$TM9_TRANSPORT_IFACE/ifindex" ]; then
    err_msg "Required transport interface $TM9_TRANSPORT_IFACE does not exist."
    if [ "$kind" = "wggre" ]; then
      echo "Create Normal GRE tunnel $TM9_ID on both servers first."
    else
      echo "Create Improved Vira7 tunnel $TM9_ID on both servers first."
    fi
    return 1
  fi

  transport_label="GRE"
  [ "$kind" = "wgvira" ] && transport_label="Vira7"
  echo "$transport_label transport : $TM9_TRANSPORT_IFACE -> $TM9_TRANSPORT_REMOTE_IP"
  echo "Secure interface   : $TM9_IFACE"
  echo "Iran secure IP     : $(tm9_overlay_local_ip "$kind" "$TM9_ID" 1)"
  echo "Kharej secure IP   : $(tm9_overlay_remote_ip "$kind" "$TM9_ID" 1)"
  echo "Fixed UDP port     : $TM9_LISTEN_PORT (inside $transport_label only)"
  echo "Hybrid stable range: 10.83.$TM9_ID.x (reserved; no route unless Hybrid is configured)"
  echo

  tm9_overlay_generate_keys "$kind" "$TM9_ID" || return 1
  local_pub="$(cat "$(tm9_overlay_key_public "$kind" "$TM9_ID")")"
  echo "LOCAL WireGuard public key:"
  echo "$local_pub"
  echo
  if [ -n "$TM9_REMOTE_PUBLIC_KEY" ]; then
    read -rp "REMOTE peer key [Enter=keep, CLEAR=remove, or paste new] (00=menu): " peer_input
    if is_main_menu_token "$peer_input"; then return_main_msg; return 99; fi
    case "$peer_input" in
      "") ;;
      CLEAR|clear) TM9_REMOTE_PUBLIC_KEY="" ;;
      *) TM9_REMOTE_PUBLIC_KEY="$(normalize_wg_public_key "$peer_input")" ;;
    esac
  else
    read -rp "Paste OTHER server WireGuard public key, or Enter to save pending (00=menu): " peer_input
    if is_main_menu_token "$peer_input"; then return_main_msg; return 99; fi
    TM9_REMOTE_PUBLIC_KEY="$(normalize_wg_public_key "$peer_input")"
  fi

  if [ -n "$TM9_REMOTE_PUBLIC_KEY" ] && ! validate_wg_public_key "$TM9_REMOTE_PUBLIC_KEY"; then
    if [ -n "$existing_key" ]; then warn_msg "Invalid replacement key; keeping the previous working peer key."; TM9_REMOTE_PUBLIC_KEY="$existing_key"; else err_msg "Invalid remote WireGuard public key. Saving as pending."; TM9_REMOTE_PUBLIC_KEY=""; fi
  fi
  if [ "$TM9_REMOTE_PUBLIC_KEY" = "$local_pub" ]; then
    if [ -n "$existing_key" ]; then warn_msg "Own key entered; keeping the previous working peer key."; TM9_REMOTE_PUBLIC_KEY="$existing_key"; else err_msg "You entered this server's own public key. Saving as pending."; TM9_REMOTE_PUBLIC_KEY=""; fi
  fi

  if confirm_yes "Enable optional low-CPU external health check for this secure overlay?"; then HEALTH_ENABLED=1; else HEALTH_ENABLED=0; fi

  systemctl is-active --quiet "$(tm9_overlay_service "$kind" "$TM9_ID")" 2>/dev/null && was_active=1 || true
  if [ -f "$(tm9_overlay_meta "$kind" "$TM9_ID")" ]; then meta_bak="$(mktemp)"; cp -f "$(tm9_overlay_meta "$kind" "$TM9_ID")" "$meta_bak"; fi
  if [ -f "$(tm9_overlay_wg_config "$kind" "$TM9_ID")" ]; then conf_bak="$(mktemp)"; cp -f "$(tm9_overlay_wg_config "$kind" "$TM9_ID")" "$conf_bak"; fi
  systemctl stop "$(tm9_overlay_service "$kind" "$TM9_ID")" >/dev/null 2>&1 || true
  wg-quick down "$TM9_IFACE" >/dev/null 2>&1 || true
  if ! tm9_validate_free_port udp "$TM9_LISTEN_PORT" "$kind"; then
    [ "$was_active" = 1 ] && systemctl restart "$(tm9_overlay_service "$kind" "$TM9_ID")" >/dev/null 2>&1 || true
    rm -f "$meta_bak" "$conf_bak"
    return 1
  fi

  tm9_overlay_save "$kind" "$TM9_ID"
  if [ -z "$TM9_REMOTE_PUBLIC_KEY" ]; then
    rm -f "$(tm9_overlay_wg_config "$kind" "$TM9_ID")"
    warn_msg "Saved as PENDING. Configure the same type/number on the other server and exchange public keys."
    echo "Metadata: $(tm9_overlay_meta "$kind" "$TM9_ID")"
    rm -f "$meta_bak" "$conf_bak"
    return 0
  fi

  tm9_overlay_write_wg_config "$kind" "$TM9_ID"
  if ! tm9_overlay_start "$kind" "$TM9_ID"; then
    err_msg "New $kind configuration failed; restoring the previous saved configuration."
    if [ -n "$meta_bak" ] && [ -s "$meta_bak" ]; then cp -f "$meta_bak" "$(tm9_overlay_meta "$kind" "$TM9_ID")"; fi
    if [ -n "$conf_bak" ] && [ -s "$conf_bak" ]; then cp -f "$conf_bak" "$(tm9_overlay_wg_config "$kind" "$TM9_ID")"; fi
    [ "$was_active" = 1 ] && systemctl restart "$(tm9_overlay_service "$kind" "$TM9_ID")" >/dev/null 2>&1 || true
    rm -f "$meta_bak" "$conf_bak"
    return 1
  fi
  rm -f "$meta_bak" "$conf_bak"
  echo "Test after both sides are configured: ping $TM9_REMOTE_IP"
}

tm9_overlay_collect_ids() {
  local kind="$1" f id dir
  dir="$(tm9_overlay_dir "$kind")"
  [ -d "$dir" ] || return 0
  for f in "$dir"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}

tm9_overlay_remove() {
  local kind="$1" id="$2" ifc svc
  ifc="$(tm9_overlay_iface "$kind" "$id")"; svc="$(tm9_overlay_service "$kind" "$id")"
  systemctl disable --now "$svc" >/dev/null 2>&1 || true
  wg-quick down "$ifc" >/dev/null 2>&1 || true
  ip link delete "$ifc" 2>/dev/null || true
  rm -f "$(tm9_overlay_wg_config "$kind" "$id")" "$(tm9_overlay_meta "$kind" "$id")" "$(tm9_overlay_key_private "$kind" "$id")" "$(tm9_overlay_key_public "$kind" "$id")"
  rm -rf "$TM9_HEALTH_DIR/$kind-$id"
  ok_msg "$kind tunnel $id removed. Transport GRE/Vira7 was not touched."
}

tm9_overlay_status_line() {
  local kind="$1" id="$2" ifc state target health pending=""
  ifc="$(tm9_overlay_iface "$kind" "$id")"; state="inactive"
  ip link show "$ifc" >/dev/null 2>&1 && state="active"
  if tm9_overlay_load "$kind" "$id"; then
    target="${TM9_REMOTE_IP:-unknown}"; health="${HEALTH_ENABLED:-0}"
    [ -z "${TM9_REMOTE_PUBLIC_KEY:-}" ] && pending="/pending"
    echo "  - $kind $id | $ifc | ${state}${pending} | remote $target | UDP $TM9_LISTEN_PORT | health=$health"
  fi
}

tm9_vira_port_reserved_elsewhere() {
  local want="$1" current_id="$2" f id saved
  [ -d "$VIRA7_CONFIG_DIR" ] || return 1
  for f in "$VIRA7_CONFIG_DIR"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    [ "$id" = "$current_id" ] && continue
    saved="$(bash -c '. "$1" 2>/dev/null; printf "%s" "${VIRA7_PORT:-${port:-}}"' _ "$f" 2>/dev/null || true)"
    [ "$saved" = "$want" ] && return 0
  done
  return 1
}

# -----------------------------
# Improved Vira7 protocol (wire-compatible with existing Vira7)
# -----------------------------
# New configs opt into peer locking, dead-path recovery and lightweight status.
# Old configs do not contain these keys and retain old behavior (all defaults 0).
vira7_compile_engine() {
  vira7_ensure_deps || return 1
  mkdir -p "$VIRA7_CONFIG_DIR"
  cat > "$VIRA7_SOURCE" <<'ENGINEEOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TUN_DEVICE "/dev/net/tun"
#define MAX_PKT_SIZE 2000
#define VIRA7_MAGIC 0x5637
#define PKT_DATA 1
#define PKT_KEEPALIVE 2
#define PKT_ACK 3

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint16_t type;
    uint32_t seq;
    uint16_t length;
    uint16_t checksum;
} v7_hdr_t;

typedef struct {
    char iface[IFNAMSIZ];
    char mode[16];
    char bind_ip[64];
    char remote_ip[64];
    char local_priv[64];
    char remote_priv[64];
    int port, mtu, keepalive, buffer_size, queue_len, checksum, verify_checksum, batch;
    int dead_timeout, peer_lock, status_interval;
} v7_config_t;

static volatile sig_atomic_t running = 1;
static uint32_t seqno = 1;
static int g_send_checksum = 1;
static int g_verify_checksum = 0;
static void on_signal(int sig) { (void)sig; running = 0; }
static void trim(char *s) {
    char *p=s; while (*p==' '||*p=='\t'||*p=='\r'||*p=='\n') p++;
    if (p!=s) memmove(s,p,strlen(p)+1);
    size_t n=strlen(s); while(n&&(s[n-1]==' '||s[n-1]=='\t'||s[n-1]=='\r'||s[n-1]=='\n')) s[--n]=0;
}
static uint16_t csum16(const uint8_t *buf,size_t len){uint32_t sum=0;for(size_t i=0;i<len;i++){sum+=buf[i];sum=(sum&0xffffU)+(sum>>16);}return(uint16_t)(~sum&0xffffU);}
static int load_config(const char *path,v7_config_t *c){
    memset(c,0,sizeof(*c)); snprintf(c->iface,sizeof(c->iface),"vira7"); snprintf(c->mode,sizeof(c->mode),"client");
    c->port=5571;c->mtu=1400;c->keepalive=5;c->buffer_size=2097152;c->queue_len=1000;c->checksum=1;c->verify_checksum=0;c->batch=128;
    c->dead_timeout=0;c->peer_lock=0;c->status_interval=0;
    FILE*f=fopen(path,"r");if(!f)return-1;char line[512];
    while(fgets(line,sizeof(line),f)){trim(line);if(!line[0]||line[0]=='#')continue;char*eq=strchr(line,'=');if(!eq)continue;*eq=0;char*key=line;char*val=eq+1;trim(key);trim(val);
        if(!strcmp(key,"iface"))snprintf(c->iface,sizeof(c->iface),"%s",val);else if(!strcmp(key,"mode"))snprintf(c->mode,sizeof(c->mode),"%s",val);
        else if(!strcmp(key,"bind_ip"))snprintf(c->bind_ip,sizeof(c->bind_ip),"%s",val);else if(!strcmp(key,"remote_ip"))snprintf(c->remote_ip,sizeof(c->remote_ip),"%s",val);
        else if(!strcmp(key,"local_priv"))snprintf(c->local_priv,sizeof(c->local_priv),"%s",val);else if(!strcmp(key,"remote_priv"))snprintf(c->remote_priv,sizeof(c->remote_priv),"%s",val);
        else if(!strcmp(key,"port"))c->port=atoi(val);else if(!strcmp(key,"mtu"))c->mtu=atoi(val);else if(!strcmp(key,"keepalive"))c->keepalive=atoi(val);
        else if(!strcmp(key,"buffer_size"))c->buffer_size=atoi(val);else if(!strcmp(key,"queue_len"))c->queue_len=atoi(val);else if(!strcmp(key,"checksum"))c->checksum=atoi(val);
        else if(!strcmp(key,"verify_checksum"))c->verify_checksum=atoi(val);else if(!strcmp(key,"batch"))c->batch=atoi(val);else if(!strcmp(key,"dead_timeout"))c->dead_timeout=atoi(val);
        else if(!strcmp(key,"peer_lock"))c->peer_lock=atoi(val);else if(!strcmp(key,"status_interval"))c->status_interval=atoi(val);
    }
    fclose(f);if(!c->local_priv[0]||!c->remote_priv[0]||c->port<=0||c->port>65535)return-1;if(!strcmp(c->mode,"client")&&!c->remote_ip[0])return-1;
    if (c->mtu < 576 || c->mtu > 1600) c->mtu = 1400;
    if (c->keepalive < 1 || c->keepalive > 60) c->keepalive = 5;
    if (c->queue_len < 100) c->queue_len = 1000;
    if (c->buffer_size < 65536) c->buffer_size = 2097152;
    c->checksum = c->checksum ? 1 : 0;
    c->verify_checksum = c->verify_checksum ? 1 : 0;
    if (c->batch < 1) c->batch = 1;
    if (c->batch > 512) c->batch = 512;
    if (c->dead_timeout < 0 || c->dead_timeout > 600) c->dead_timeout = 0;
    c->peer_lock = c->peer_lock ? 1 : 0;
    if (c->status_interval < 0 || c->status_interval > 60) c->status_interval = 0;
    return 0;
}
static int tun_alloc_named(const char*dev){struct ifreq ifr;int fd=open(TUN_DEVICE,O_RDWR);if(fd<0)return-1;memset(&ifr,0,sizeof(ifr));ifr.ifr_flags=IFF_TUN|IFF_NO_PI;snprintf(ifr.ifr_name,IFNAMSIZ,"%s",dev);if(ioctl(fd,TUNSETIFF,&ifr)<0){close(fd);return-1;}int flags=fcntl(fd,F_GETFL,0);if(flags>=0)fcntl(fd,F_SETFL,flags|O_NONBLOCK);return fd;}
static void cleanup_iface(const char*iface){char cmd[256];snprintf(cmd,sizeof(cmd),"ip link del %s 2>/dev/null",iface);system(cmd);}
static int configure_tun(const v7_config_t*c){char cmd[512];snprintf(cmd,sizeof(cmd),"ip link set dev %s up mtu %d txqueuelen %d",c->iface,c->mtu,c->queue_len);if(system(cmd)!=0)return-1;snprintf(cmd,sizeof(cmd),"ip addr add %s/32 peer %s dev %s 2>/dev/null || true",c->local_priv,c->remote_priv,c->iface);return system(cmd)==0?0:-1;}
static int udp_socket_create(const v7_config_t*c){int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return-1;int yes=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));setsockopt(fd,SOL_SOCKET,SO_RCVBUF,&c->buffer_size,sizeof(c->buffer_size));setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&c->buffer_size,sizeof(c->buffer_size));struct sockaddr_in addr;memset(&addr,0,sizeof(addr));addr.sin_family=AF_INET;addr.sin_port=htons((uint16_t)c->port);if(c->bind_ip[0]){if(inet_pton(AF_INET,c->bind_ip,&addr.sin_addr)!=1){close(fd);return-1;}}else addr.sin_addr.s_addr=htonl(INADDR_ANY);if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))<0){close(fd);return-1;}int flags=fcntl(fd,F_GETFL,0);if(flags>=0)fcntl(fd,F_SETFL,flags|O_NONBLOCK);return fd;}
static int send_v7(int fd,const struct sockaddr_in*dst,uint16_t type,const uint8_t*payload,uint16_t len){uint8_t buf[sizeof(v7_hdr_t)+MAX_PKT_SIZE];if(len>MAX_PKT_SIZE)return-1;v7_hdr_t*h=(v7_hdr_t*)buf;h->magic=htons(VIRA7_MAGIC);h->type=htons(type);h->seq=htonl(seqno++);h->length=htons(len);h->checksum=0;if(payload&&len)memcpy(buf+sizeof(v7_hdr_t),payload,len);if(g_send_checksum)h->checksum=htons(csum16(buf,sizeof(v7_hdr_t)+len));ssize_t n=sendto(fd,buf,sizeof(v7_hdr_t)+len,0,(const struct sockaddr*)dst,sizeof(*dst));return n==(ssize_t)(sizeof(v7_hdr_t)+len)?0:-1;}
static int verify_packet(uint8_t*buf,ssize_t n,uint16_t*type,uint8_t**payload,uint16_t*len){if(n<(ssize_t)sizeof(v7_hdr_t))return-1;v7_hdr_t*h=(v7_hdr_t*)buf;if(ntohs(h->magic)!=VIRA7_MAGIC)return-1;*len=ntohs(h->length);if((ssize_t)(sizeof(v7_hdr_t)+*len)!=n||*len>MAX_PKT_SIZE)return-1;uint16_t got=ntohs(h->checksum);if(got!=0&&g_verify_checksum){h->checksum=0;if(got!=csum16(buf,(size_t)n))return-1;}*type=ntohs(h->type);*payload=buf+sizeof(v7_hdr_t);return 0;}
static int peer_allowed(const v7_config_t*c,const struct sockaddr_in*sender){if(!c->peer_lock||!c->remote_ip[0])return 1;struct in_addr allowed;if(inet_pton(AF_INET,c->remote_ip,&allowed)!=1)return 0;return sender->sin_addr.s_addr==allowed.s_addr;}
static void write_status(const v7_config_t*c,time_t now,time_t last_rx,unsigned long long tx,unsigned long long rx,unsigned long long drop,int remote_known){char path[160],tmp[180];snprintf(path,sizeof(path),"/run/%s.status",c->iface);snprintf(tmp,sizeof(tmp),"%s.tmp",path);FILE*f=fopen(tmp,"w");if(!f)return;fprintf(f,"pid=%d\nnow=%ld\nlast_rx=%ld\nrx_age=%ld\ntx_packets=%llu\nrx_packets=%llu\ndrops=%llu\nremote_known=%d\n",getpid(),(long)now,(long)last_rx,last_rx? (long)(now-last_rx):-1L,tx,rx,drop,remote_known);fclose(f);rename(tmp,path);}
int main(int argc,char**argv){if(argc<2||getuid()!=0)return 1;v7_config_t cfg;if(load_config(argv[1],&cfg)!=0)return 1;g_send_checksum=cfg.checksum?1:0;g_verify_checksum=cfg.verify_checksum?1:0;signal(SIGINT,on_signal);signal(SIGTERM,on_signal);signal(SIGPIPE,SIG_IGN);mkdir("/dev/net",0755);if(access(TUN_DEVICE,F_OK)!=0)system("mknod /dev/net/tun c 10 200 2>/dev/null || true");system("modprobe tun 2>/dev/null || true");cleanup_iface(cfg.iface);int tun_fd=tun_alloc_named(cfg.iface);if(tun_fd<0)return 1;if(configure_tun(&cfg)!=0){cleanup_iface(cfg.iface);close(tun_fd);return 1;}int udp_fd=udp_socket_create(&cfg);if(udp_fd<0){cleanup_iface(cfg.iface);close(tun_fd);return 1;}
    struct sockaddr_in remote;memset(&remote,0,sizeof(remote));remote.sin_family=AF_INET;remote.sin_port=htons((uint16_t)cfg.port);int remote_known=0;if(!strcmp(cfg.mode,"client")){if(inet_pton(AF_INET,cfg.remote_ip,&remote.sin_addr)!=1){close(udp_fd);close(tun_fd);cleanup_iface(cfg.iface);return 1;}remote_known=1;}
    char pidfile[128];snprintf(pidfile,sizeof(pidfile),"/run/%s.pid",cfg.iface);FILE*pf=fopen(pidfile,"w");if(pf){fprintf(pf,"%d\n",getpid());fclose(pf);}uint8_t tun_buf[MAX_PKT_SIZE],udp_buf[sizeof(v7_hdr_t)+MAX_PKT_SIZE];time_t now=time(NULL),last_keepalive=0,last_rx=now,last_status=0;unsigned long long tx=0,rx=0,drop=0;int send_errors=0;
    while(running){fd_set rfds;FD_ZERO(&rfds);FD_SET(tun_fd,&rfds);FD_SET(udp_fd,&rfds);int maxfd=tun_fd>udp_fd?tun_fd:udp_fd;struct timeval tv={1,0};int rc=select(maxfd+1,&rfds,NULL,NULL,&tv);if(rc<0){if(errno==EINTR)continue;break;}now=time(NULL);
        if(remote_known&&now-last_keepalive>=cfg.keepalive){if(send_v7(udp_fd,&remote,PKT_KEEPALIVE,NULL,0)==0){tx++;send_errors=0;}else if(++send_errors>=5&&!strcmp(cfg.mode,"client"))break;last_keepalive=now;}
        if(FD_ISSET(tun_fd,&rfds)){for(int i=0;i<cfg.batch;i++){ssize_t n=read(tun_fd,tun_buf,sizeof(tun_buf));if(n>0){if(remote_known){if(send_v7(udp_fd,&remote,PKT_DATA,tun_buf,(uint16_t)n)==0){tx++;send_errors=0;}else send_errors++;}continue;}if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))break;break;}}
        if(FD_ISSET(udp_fd,&rfds)){for(int i=0;i<cfg.batch;i++){struct sockaddr_in sender;socklen_t slen=sizeof(sender);ssize_t n=recvfrom(udp_fd,udp_buf,sizeof(udp_buf),0,(struct sockaddr*)&sender,&slen);if(n<0){if(errno==EAGAIN||errno==EWOULDBLOCK)break;break;}if(n==0)break;if(!peer_allowed(&cfg,&sender)){drop++;continue;}uint16_t type,len;uint8_t*payload;if(verify_packet(udp_buf,n,&type,&payload,&len)!=0){drop++;continue;}last_rx=now;rx++;if(!strcmp(cfg.mode,"server")){memcpy(&remote,&sender,sizeof(remote));remote_known=1;}if(type==PKT_DATA&&len>0){ssize_t w=write(tun_fd,payload,len);if(w!=(ssize_t)len)drop++;}else if(type==PKT_KEEPALIVE&&remote_known){if(send_v7(udp_fd,&remote,PKT_ACK,NULL,0)==0)tx++;}}}
        if(cfg.dead_timeout>0&&remote_known&&now-last_rx>=cfg.dead_timeout){if(!strcmp(cfg.mode,"client"))break;remote_known=0;last_rx=now;}
        if(cfg.status_interval>0&&now-last_status>=cfg.status_interval){write_status(&cfg,now,last_rx,tx,rx,drop,remote_known);last_status=now;}
    }
    close(udp_fd);close(tun_fd);unlink(pidfile);char statusfile[160];snprintf(statusfile,sizeof(statusfile),"/run/%s.status",cfg.iface);unlink(statusfile);cleanup_iface(cfg.iface);return 0;
}
ENGINEEOF
  gcc -O3 -flto -Wall -Wextra -o "$VIRA7_BINARY" "$VIRA7_SOURCE" 2>/dev/null || gcc -O3 -Wall -Wextra -o "$VIRA7_BINARY" "$VIRA7_SOURCE"
  chmod 755 "$VIRA7_BINARY"
}

# Override loader to clear values first and read v9 optional fields safely.
vira7_load_config() {
  local id="${1:-${TUNNEL_ID:-}}" file
  validate_tunnel_id "$id" || return 1
  file="$(vira7_config_file "$id")"; [ -f "$file" ] || return 1
  unset TUNNEL_TYPE TUNNEL_ID VIRA7_IFACE ROLE SERVER_ROLE LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP LOCAL_VIRA7_IP REMOTE_VIRA7_IP VIRA7_PORT VIRA7_MTU VIRA7_CHECKSUM VIRA7_VERIFY_CHECKSUM VIRA7_BATCH VIRA7_DEAD_TIMEOUT VIRA7_PEER_LOCK VIRA7_STATUS_INTERVAL HEALTH_ENABLED iface mode bind_ip remote_ip local_priv remote_priv port mtu keepalive buffer_size queue_len checksum verify_checksum batch dead_timeout peer_lock status_interval 2>/dev/null || true
  # shellcheck disable=SC1090
  source "$file"
  TUNNEL_ID="$id"
  VIRA7_IFACE="${VIRA7_IFACE:-${iface:-$(vira7_iface_name "$id")}}"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"; REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
  LOCAL_VIRA7_IP="${LOCAL_VIRA7_IP:-${local_priv:-}}"; REMOTE_VIRA7_IP="${REMOTE_VIRA7_IP:-${remote_priv:-}}"
  VIRA7_PORT="${VIRA7_PORT:-${port:-$(vira7_default_port "$id")}}"; VIRA7_MTU="${VIRA7_MTU:-${mtu:-$VIRA7_DEFAULT_MTU}}"
  VIRA7_CHECKSUM="${VIRA7_CHECKSUM:-${checksum:-$VIRA7_DEFAULT_CHECKSUM}}"; VIRA7_VERIFY_CHECKSUM="${VIRA7_VERIFY_CHECKSUM:-${verify_checksum:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}}"; VIRA7_BATCH="${VIRA7_BATCH:-${batch:-$VIRA7_DEFAULT_BATCH}}"
  VIRA7_DEAD_TIMEOUT="${VIRA7_DEAD_TIMEOUT:-${dead_timeout:-0}}"; VIRA7_PEER_LOCK="${VIRA7_PEER_LOCK:-${peer_lock:-0}}"; VIRA7_STATUS_INTERVAL="${VIRA7_STATUS_INTERVAL:-${status_interval:-0}}"; HEALTH_ENABLED="${HEALTH_ENABLED:-0}"
  if [ -z "${ROLE:-}" ]; then if [ "$LOCAL_VIRA7_IP" = "10.71.$id.1" ]; then ROLE=1; else ROLE=2; fi; fi
}

vira7_save_config() {
  mkdir -p "$VIRA7_CONFIG_DIR"
  local file; file="$(vira7_config_file "$TUNNEL_ID")"
  {
    write_var TUNNEL_TYPE "vira7"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var VIRA7_IFACE "$VIRA7_IFACE"
    write_var ROLE "$ROLE"
    write_var SERVER_ROLE "$SERVER_ROLE"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_VIRA7_IP "$LOCAL_VIRA7_IP"
    write_var REMOTE_VIRA7_IP "$REMOTE_VIRA7_IP"
    write_var VIRA7_PORT "$VIRA7_PORT"
    write_var VIRA7_MTU "$VIRA7_MTU"
    write_var VIRA7_CHECKSUM "${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
    write_var VIRA7_VERIFY_CHECKSUM "${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
    write_var VIRA7_BATCH "${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"
    write_var VIRA7_DEAD_TIMEOUT "${VIRA7_DEAD_TIMEOUT:-0}"
    write_var VIRA7_PEER_LOCK "${VIRA7_PEER_LOCK:-0}"
    write_var VIRA7_STATUS_INTERVAL "${VIRA7_STATUS_INTERVAL:-0}"
    write_var HEALTH_ENABLED "${HEALTH_ENABLED:-0}"
    echo
    printf 'iface=%s\n' "$VIRA7_IFACE"
    printf 'mode=%s\n' "$VIRA7_MODE"
    printf 'bind_ip=%s\n' "$LOCAL_PUBLIC_IP"
    printf 'remote_ip=%s\n' "$REMOTE_PUBLIC_IP"
    printf 'local_priv=%s\n' "$LOCAL_VIRA7_IP"
    printf 'remote_priv=%s\n' "$REMOTE_VIRA7_IP"
    printf 'port=%s\n' "$VIRA7_PORT"
    printf 'mtu=%s\n' "$VIRA7_MTU"
    printf 'keepalive=%s\n' "$VIRA7_DEFAULT_KEEPALIVE"
    printf 'buffer_size=%s\n' "$VIRA7_DEFAULT_BUFFER_SIZE"
    printf 'queue_len=%s\n' "$VIRA7_DEFAULT_QUEUE_LEN"
    printf 'checksum=%s\n' "${VIRA7_CHECKSUM:-$VIRA7_DEFAULT_CHECKSUM}"
    printf 'verify_checksum=%s\n' "${VIRA7_VERIFY_CHECKSUM:-$VIRA7_DEFAULT_VERIFY_CHECKSUM}"
    printf 'batch=%s\n' "${VIRA7_BATCH:-$VIRA7_DEFAULT_BATCH}"
    printf 'dead_timeout=%s\n' "${VIRA7_DEAD_TIMEOUT:-0}"
    printf 'peer_lock=%s\n' "${VIRA7_PEER_LOCK:-0}"
    printf 'status_interval=%s\n' "${VIRA7_STATUS_INTERVAL:-0}"
  } > "$file"
  chmod 600 "$file"
  echo "Saved Improved Vira7 tunnel $TUNNEL_ID configuration to $file"
}

vira7_menu_config_tunnel() {
  show_header "Improved Vira7 UDP-TUN"
  prompt_role || return
  local selected_role existing_local_ip="" existing_remote_ip="" existing_port="" existing_mtu="" existing_health=0 existing_dead=30 existing_lock=1 existing_status=5
  local port_input mtu_input new_local new_remote new_port new_mtu new_dead new_lock new_status new_health old_file old_backup="" was_active=0
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter Improved Vira7 tunnel number [1-254]: " || return
  old_file="$(vira7_config_file "$TUNNEL_ID")"
  if vira7_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"; existing_remote_ip="${REMOTE_PUBLIC_IP:-}"; existing_port="${VIRA7_PORT:-}"; existing_mtu="${VIRA7_MTU:-}"
    existing_health="${HEALTH_ENABLED:-0}"; existing_dead="${VIRA7_DEAD_TIMEOUT:-0}"; existing_lock="${VIRA7_PEER_LOCK:-0}"; existing_status="${VIRA7_STATUS_INTERVAL:-0}"
  fi
  ROLE="$selected_role"
  echo
  echo "Interface       : $(vira7_iface_name "$TUNNEL_ID")"
  echo "Iran IP        : 10.71.$TUNNEL_ID.1"
  echo "Kharej IP      : 10.71.$TUNNEL_ID.2"
  echo "Default port   : $(vira7_default_port "$TUNNEL_ID")/udp"
  echo "Protocol v9    : original wire format + fixed peer + ACK timeout recovery + counters"
  echo "Compatibility  : existing Vira7 config is not changed until this update succeeds"
  echo
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL public IPv4 for Vira7 bind" || return
  new_local="$LOCAL_PUBLIC_IP"
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return
  new_remote="$REMOTE_PUBLIC_IP"

  new_port="${existing_port:-$(vira7_default_port "$TUNNEL_ID")}" 
  read -rp "Enter SAME Vira7 UDP port on both servers [$new_port] (00=menu): " port_input
  if is_main_menu_token "$port_input"; then return_main_msg; return 99; fi
  new_port="${port_input:-$new_port}"
  validate_port "$new_port" || { err_msg "Invalid Vira7 port."; return 1; }
  if tm9_vira_port_reserved_elsewhere "$new_port" "$TUNNEL_ID"; then err_msg "Vira7 port $new_port is already reserved by another saved Vira tunnel."; return 1; fi

  read -rp "Enter Vira7 MTU [${existing_mtu:-1320}] (00=menu): " mtu_input
  if is_main_menu_token "$mtu_input"; then return_main_msg; return 99; fi
  new_mtu="${mtu_input:-${existing_mtu:-1320}}"
  [[ "$new_mtu" =~ ^[0-9]+$ ]] && [ "$new_mtu" -ge 576 ] && [ "$new_mtu" -le 1500 ] || { err_msg "Invalid MTU."; return 1; }

  new_dead="$existing_dead"; new_lock="$existing_lock"; new_status="$existing_status"; new_health="$existing_health"
  if confirm_default_yes "Enable built-in dead-path recovery (recommended, near-zero CPU)?"; then new_dead=30; else new_dead=0; fi
  if confirm_default_yes "Lock Vira7 packets to the configured remote public IP?"; then new_lock=1; else new_lock=0; fi
  if confirm_default_yes "Write lightweight runtime counters every 5 seconds?"; then new_status=5; else new_status=0; fi
  if confirm_yes "Enable optional external health ping for this Vira7 tunnel?"; then new_health=1; else new_health=0; fi

  systemctl is-active --quiet "$(vira7_service_name "$TUNNEL_ID")" 2>/dev/null && was_active=1 || true
  if [ -f "$old_file" ]; then old_backup="$(mktemp)"; cp -f "$old_file" "$old_backup"; fi
  systemctl stop "$(vira7_service_name "$TUNNEL_ID")" >/dev/null 2>&1 || true
  ip link delete "$(vira7_iface_name "$TUNNEL_ID")" 2>/dev/null || true
  if ! tm9_validate_free_port udp "$new_port" "Vira7"; then
    [ "$was_active" = 1 ] && systemctl restart "$(vira7_service_name "$TUNNEL_ID")" >/dev/null 2>&1 || true
    rm -f "$old_backup"
    return 1
  fi

  if ! vira7_compile_engine; then
    err_msg "Improved Vira engine compilation failed. Previous tunnel config was not changed."
    [ "$was_active" = 1 ] && systemctl restart "$(vira7_service_name "$TUNNEL_ID")" >/dev/null 2>&1 || true
    rm -f "$old_backup"
    return 1
  fi

  LOCAL_PUBLIC_IP="$new_local"; REMOTE_PUBLIC_IP="$new_remote"; VIRA7_PORT="$new_port"; VIRA7_MTU="$new_mtu"
  VIRA7_IFACE="$(vira7_iface_name "$TUNNEL_ID")"
  if [ "$ROLE" = "1" ]; then SERVER_ROLE="IRAN"; VIRA7_MODE="server"; LOCAL_VIRA7_IP="10.71.$TUNNEL_ID.1"; REMOTE_VIRA7_IP="10.71.$TUNNEL_ID.2"; else SERVER_ROLE="KHAREJ"; VIRA7_MODE="client"; LOCAL_VIRA7_IP="10.71.$TUNNEL_ID.2"; REMOTE_VIRA7_IP="10.71.$TUNNEL_ID.1"; fi
  VIRA7_CHECKSUM=1; VIRA7_VERIFY_CHECKSUM=0; VIRA7_BATCH=128; VIRA7_DEAD_TIMEOUT="$new_dead"; VIRA7_PEER_LOCK="$new_lock"; VIRA7_STATUS_INTERVAL="$new_status"; HEALTH_ENABLED="$new_health"
  enable_ip_forward; modprobe tun || true; vira7_save_config; vira7_apply_firewall_rules "$TUNNEL_ID" || true
  if ! vira7_install_service "$TUNNEL_ID"; then
    err_msg "Improved Vira start failed; restoring previous configuration."
    if [ -n "$old_backup" ] && [ -s "$old_backup" ]; then cp -f "$old_backup" "$old_file"; systemctl restart "$(vira7_service_name "$TUNNEL_ID")" >/dev/null 2>&1 || true; else rm -f "$old_file"; fi
    rm -f "$old_backup"
    return 1
  fi
  rm -f "$old_backup"
  echo "Improved Vira7 status file: /run/$VIRA7_IFACE.status"
}

vira7_list_tunnels() {
  echo "Improved/legacy Vira7 UDP-TUN tunnels:"
  local ids id ifc state age="-" mode_text
  ids="$(vira7_collect_ids || true)"; [ -n "$ids" ] || { echo "  none"; return 0; }
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(vira7_iface_name "$id")"; state="inactive"; ip link show "$ifc" >/dev/null 2>&1 && state="active"
    mode_text="legacy-compatible"
    if vira7_load_config "$id"; then
      [ "${VIRA7_DEAD_TIMEOUT:-0}" -gt 0 ] && mode_text="improved"
      if [ -f "/run/$ifc.status" ]; then age="$(awk -F= '$1=="rx_age"{print $2}' "/run/$ifc.status" 2>/dev/null || echo -)"; else age="-"; fi
      echo "  - Vira7 $id | $ifc | $state | remote ${REMOTE_VIRA7_IP:-?} | UDP ${VIRA7_PORT:-?} | mode=$mode_text | rx_age=${age}s | health=${HEALTH_ENABLED:-0}"
    fi
  done <<< "$ids"
}

# -----------------------------
# WSS/TCP emergency WireGuard tunnel
# -----------------------------
tm9_wss_meta() { echo "$TM9_DIR/wss/tunnel-$1.conf"; }
tm9_wss_iface() { echo "wsswg$1"; }
tm9_wss_wg_config() { echo "$WG_CONFIG_DIR/$(tm9_wss_iface "$1").conf"; }
tm9_wss_key_private() { echo "$TM9_DIR/wss/keys/tunnel-$1.private"; }
tm9_wss_key_public() { echo "$TM9_DIR/wss/keys/tunnel-$1.public"; }
tm9_wss_service() { echo "tm9-wss@$1.service"; }
tm9_wss_wg_service() { echo "wg-quick@$(tm9_wss_iface "$1").service"; }
tm9_wss_local_ip() { if [ "$2" = 1 ]; then echo "10.84.$1.1"; else echo "10.84.$1.2"; fi; }
tm9_wss_remote_ip() { if [ "$2" = 1 ]; then echo "10.84.$1.2"; else echo "10.84.$1.1"; fi; }

tm9_wss_reset_vars() { unset WSS_ID WSS_ROLE WSS_IFACE WSS_LOCAL_IP WSS_REMOTE_IP WSS_LOCAL_PUBLIC_IP WSS_REMOTE_PUBLIC_IP WSS_TCP_PORT WSS_WG_PORT WSS_CLIENT_LISTEN_PORT WSS_SECRET WSS_REMOTE_PUBLIC_KEY WSS_MTU HEALTH_ENABLED 2>/dev/null || true; }
tm9_wss_load() {
  local id="$1" file; validate_tunnel_id "$id" || return 1; file="$(tm9_wss_meta "$id")"; [ -f "$file" ] || return 1
  tm9_wss_reset_vars
  # shellcheck disable=SC1090
  source "$file"
  WSS_ID="$id"; WSS_IFACE="${WSS_IFACE:-$(tm9_wss_iface "$id")}"; HEALTH_ENABLED="${HEALTH_ENABLED:-0}"
}

tm9_install_wstunnel() {
  if [ -x "$TM9_WSTUNNEL_BIN" ]; then return 0; fi
  local arch asset tmp version candidate latest=""
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) err_msg "Unsupported wstunnel architecture: $(uname -m)"; return 1 ;; esac
  if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates tar
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y curl ca-certificates tar
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl ca-certificates tar
    else
      err_msg "curl and tar are required to install wstunnel."
      return 1
    fi
  fi
  tmp="$(mktemp -d)"
  latest="$(curl -fsSL --connect-timeout 10 https://api.github.com/repos/erebe/wstunnel/releases/latest 2>/dev/null | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\([^"]*\)".*/\1/p' | head -n1 || true)"
  for version in "$latest" "$TM9_WSTUNNEL_VERSION" 10.5.5; do
    [ -n "$version" ] || continue
    asset="wstunnel_${version}_linux_${arch}.tar.gz"
    candidate="https://github.com/erebe/wstunnel/releases/download/v${version}/${asset}"
    info_msg "Downloading wstunnel v$version for linux/$arch..."
    if curl -fL --connect-timeout 15 --retry 2 -o "$tmp/wstunnel.tgz" "$candidate"; then
      tar -xzf "$tmp/wstunnel.tgz" -C "$tmp"
      if [ -f "$tmp/wstunnel" ]; then install -m 755 "$tmp/wstunnel" "$TM9_WSTUNNEL_BIN"; rm -rf "$tmp"; return 0; fi
    fi
  done
  rm -rf "$tmp"; err_msg "Could not download wstunnel binary."; return 1
}

tm9_wss_generate_keys() {
  local id="$1" private public
  wg_ensure_tools || return 1; tm9_prepare_dirs
  private="$(tm9_wss_key_private "$id")"; public="$(tm9_wss_key_public "$id")"
  if [ ! -s "$private" ]; then umask 077; wg genkey > "$private"; wg pubkey < "$private" > "$public"; chmod 600 "$private"; chmod 644 "$public"; elif [ ! -s "$public" ]; then wg pubkey < "$private" > "$public"; chmod 644 "$public"; fi
}

tm9_wss_save() {
  local file; tm9_prepare_dirs; file="$(tm9_wss_meta "$WSS_ID")"
  {
    write_var WSS_ID "$WSS_ID"; write_var WSS_ROLE "$WSS_ROLE"; write_var WSS_IFACE "$WSS_IFACE"
    write_var WSS_LOCAL_IP "$WSS_LOCAL_IP"; write_var WSS_REMOTE_IP "$WSS_REMOTE_IP"
    write_var WSS_LOCAL_PUBLIC_IP "$WSS_LOCAL_PUBLIC_IP"; write_var WSS_REMOTE_PUBLIC_IP "$WSS_REMOTE_PUBLIC_IP"
    write_var WSS_TCP_PORT "$WSS_TCP_PORT"; write_var WSS_WG_PORT "$WSS_WG_PORT"; write_var WSS_CLIENT_LISTEN_PORT "$WSS_CLIENT_LISTEN_PORT"
    write_var WSS_SECRET "$WSS_SECRET"; write_var WSS_REMOTE_PUBLIC_KEY "${WSS_REMOTE_PUBLIC_KEY:-}"; write_var WSS_MTU "${WSS_MTU:-1280}"; write_var HEALTH_ENABLED "${HEALTH_ENABLED:-0}"
  } > "$file"; chmod 600 "$file"
}

tm9_wss_write_wg_config() {
  local id="$1" private conf
  tm9_wss_load "$id" || return 1
  private="$(cat "$(tm9_wss_key_private "$id")")"; conf="$(tm9_wss_wg_config "$id")"; mkdir -p "$WG_CONFIG_DIR"
  if [ "$WSS_ROLE" = "1" ]; then
    cat > "$conf" <<EOF
[Interface]
PrivateKey = $private
Address = $WSS_LOCAL_IP/30
ListenPort = $WSS_CLIENT_LISTEN_PORT
MTU = ${WSS_MTU:-1280}

[Peer]
PublicKey = $WSS_REMOTE_PUBLIC_KEY
Endpoint = 127.0.0.1:$WSS_WG_PORT
AllowedIPs = $WSS_REMOTE_IP/32
PersistentKeepalive = 20
EOF
  else
    cat > "$conf" <<EOF
[Interface]
PrivateKey = $private
Address = $WSS_LOCAL_IP/30
ListenPort = $WSS_WG_PORT
MTU = ${WSS_MTU:-1280}

[Peer]
PublicKey = $WSS_REMOTE_PUBLIC_KEY
AllowedIPs = $WSS_REMOTE_IP/32
EOF
  fi
  chmod 600 "$conf"
}

tm9_wss_write_service_template() {
  tm9_install_self
  cat > "$TM9_WSS_SERVICE_TEMPLATE" <<EOF
[Unit]
Description=Tunnel Manager v9 WSS transport %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=TOKIO_WORKER_THREADS=1
ExecStart=/bin/bash $INSTALL_BIN --service run-wss %i
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

tm9_wss_run() {
  local id="$1"
  tm9_wss_load "$id" || return 1
  [ -x "$TM9_WSTUNNEL_BIN" ] || return 1
  if [ "$WSS_ROLE" = "1" ]; then
    exec "$TM9_WSTUNNEL_BIN" client --log-lvl=WARN --websocket-ping-frequency-sec 30 --http-upgrade-path-prefix "$WSS_SECRET" -L "udp://127.0.0.1:${WSS_WG_PORT}:127.0.0.1:${WSS_WG_PORT}?timeout_sec=0" "wss://${WSS_REMOTE_PUBLIC_IP}:${WSS_TCP_PORT}"
  else
    exec "$TM9_WSTUNNEL_BIN" server --log-lvl=WARN --websocket-ping-frequency-sec 30 --restrict-to "127.0.0.1:${WSS_WG_PORT}" --restrict-http-upgrade-path-prefix "$WSS_SECRET" "wss://0.0.0.0:${WSS_TCP_PORT}"
  fi
}

tm9_wss_apply_firewall() {
  local id="$1"; tm9_wss_load "$id" || return 1; enable_ip_forward; tm9_disable_rp_filter "$WSS_IFACE"
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -i "$WSS_IFACE" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$WSS_IFACE" -j ACCEPT || true
    iptables -C OUTPUT -o "$WSS_IFACE" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$WSS_IFACE" -j ACCEPT || true
    if [ "$WSS_ROLE" = 2 ]; then iptables -C INPUT -p tcp --dport "$WSS_TCP_PORT" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$WSS_TCP_PORT" -j ACCEPT || true; fi
  fi
  if command -v ufw >/dev/null 2>&1 && [ "$WSS_ROLE" = 2 ]; then ufw allow "$WSS_TCP_PORT/tcp" >/dev/null 2>&1 || true; fi
}

tm9_wss_start() {
  local id="$1"; tm9_wss_load "$id" || return 1
  [ -n "${WSS_REMOTE_PUBLIC_KEY:-}" ] || { warn_msg "WSS tunnel $id is pending peer key."; return 0; }
  tm9_install_wstunnel || return 1; tm9_wss_write_service_template; tm9_wss_write_wg_config "$id"; tm9_wss_apply_firewall "$id"
  systemctl enable "$(tm9_wss_service "$id")" >/dev/null 2>&1 || true
  systemctl restart "$(tm9_wss_service "$id")" || return 1
  sleep 1
  systemctl enable "$(tm9_wss_wg_service "$id")" >/dev/null 2>&1 || true
  wg-quick down "$WSS_IFACE" >/dev/null 2>&1 || true
  systemctl restart "$(tm9_wss_wg_service "$id")" || return 1
  ok_msg "WSS/TCP emergency tunnel $id started. Remote secure IP: $WSS_REMOTE_IP"
}

tm9_wss_configure() {
  show_header "WSS/TCP Emergency Tunnel"
  prompt_role || return
  local selected_role="$ROLE" existing_key="" existing_secret="" existing_health=0 peer_input secret_input local_pub was_active=0 meta_bak="" conf_bak=""
  echo "Role mapping: Iran=client, Kharej=TLS WebSocket server."
  echo
  prompt_tunnel_id "Enter WSS tunnel number [1-254]: " || return
  WSS_ID="$TUNNEL_ID"; WSS_ROLE="$selected_role"; WSS_IFACE="$(tm9_wss_iface "$WSS_ID")"
  WSS_LOCAL_IP="$(tm9_wss_local_ip "$WSS_ID" "$WSS_ROLE")"; WSS_REMOTE_IP="$(tm9_wss_remote_ip "$WSS_ID" "$WSS_ROLE")"
  WSS_TCP_PORT="$(tm9_fixed_port wss-tcp "$WSS_ID")"; WSS_WG_PORT="$(tm9_fixed_port wss-wg "$WSS_ID")"; WSS_CLIENT_LISTEN_PORT="$(tm9_fixed_port wss-client "$WSS_ID")"; WSS_MTU=1280; HEALTH_ENABLED=0
  WSS_LOCAL_PUBLIC_IP="$(detect_local_public_ip || true)"; WSS_REMOTE_PUBLIC_IP=""; WSS_SECRET=""; WSS_REMOTE_PUBLIC_KEY=""
  if tm9_wss_load "$WSS_ID"; then existing_key="${WSS_REMOTE_PUBLIC_KEY:-}"; existing_secret="${WSS_SECRET:-}"; existing_health="${HEALTH_ENABLED:-0}"; fi
  WSS_ROLE="$selected_role"; WSS_IFACE="$(tm9_wss_iface "$WSS_ID")"; WSS_LOCAL_IP="$(tm9_wss_local_ip "$WSS_ID" "$WSS_ROLE")"; WSS_REMOTE_IP="$(tm9_wss_remote_ip "$WSS_ID" "$WSS_ROLE")"
  WSS_TCP_PORT="$(tm9_fixed_port wss-tcp "$WSS_ID")"; WSS_WG_PORT="$(tm9_fixed_port wss-wg "$WSS_ID")"; WSS_CLIENT_LISTEN_PORT="$(tm9_fixed_port wss-client "$WSS_ID")"; WSS_MTU=1280; HEALTH_ENABLED="$existing_health"; WSS_REMOTE_PUBLIC_KEY="$existing_key"; WSS_SECRET="$existing_secret"

  prompt_local_tunnel_ip "${WSS_LOCAL_PUBLIC_IP:-$(detect_local_public_ip || true)}" "Enter LOCAL public IPv4" || return
  WSS_LOCAL_PUBLIC_IP="$LOCAL_PUBLIC_IP"
  echo
  prompt_remote_public_ip "$WSS_REMOTE_PUBLIC_IP" || return
  WSS_REMOTE_PUBLIC_IP="$REMOTE_PUBLIC_IP"

  echo "Public WSS TCP port : $WSS_TCP_PORT"
  echo "Forwarded WG UDP    : $WSS_WG_PORT"
  echo "Secure IP range     : 10.84.$WSS_ID.x"
  echo
  if [ -n "$WSS_SECRET" ]; then read -rp "Shared WSS path secret [Enter=keep or paste replacement]: " secret_input; [ -n "$secret_input" ] && WSS_SECRET="$secret_input"; else read -rp "Paste shared WSS path secret, or Enter to generate on this server: " secret_input; WSS_SECRET="${secret_input:-$(tm9_generate_secret)}"; fi
  echo "WSS shared secret (must be identical on both servers): $WSS_SECRET"

  tm9_wss_generate_keys "$WSS_ID" || return 1; local_pub="$(cat "$(tm9_wss_key_public "$WSS_ID")")"; echo "LOCAL WireGuard public key:"; echo "$local_pub"
  if [ -n "$WSS_REMOTE_PUBLIC_KEY" ]; then read -rp "REMOTE peer key [Enter=keep, CLEAR=remove, or paste new]: " peer_input; case "$peer_input" in "") ;; CLEAR|clear) WSS_REMOTE_PUBLIC_KEY="" ;; *) WSS_REMOTE_PUBLIC_KEY="$(normalize_wg_public_key "$peer_input")" ;; esac; else read -rp "Paste OTHER server WireGuard public key, or Enter for pending: " peer_input; WSS_REMOTE_PUBLIC_KEY="$(normalize_wg_public_key "$peer_input")"; fi
  if [ -n "$WSS_REMOTE_PUBLIC_KEY" ] && ! validate_wg_public_key "$WSS_REMOTE_PUBLIC_KEY"; then
    if [ -n "$existing_key" ]; then warn_msg "Invalid replacement key; keeping previous peer key."; WSS_REMOTE_PUBLIC_KEY="$existing_key"; else err_msg "Invalid peer key; saved pending."; WSS_REMOTE_PUBLIC_KEY=""; fi
  fi
  if [ "$WSS_REMOTE_PUBLIC_KEY" = "$local_pub" ]; then
    if [ -n "$existing_key" ]; then warn_msg "Own key entered; keeping previous peer key."; WSS_REMOTE_PUBLIC_KEY="$existing_key"; else err_msg "Own key entered; saved pending."; WSS_REMOTE_PUBLIC_KEY=""; fi
  fi
  if confirm_yes "Enable optional low-CPU health check for WSS tunnel?"; then HEALTH_ENABLED=1; else HEALTH_ENABLED=0; fi

  systemctl is-active --quiet "$(tm9_wss_service "$WSS_ID")" 2>/dev/null && was_active=1 || true
  if [ -f "$(tm9_wss_meta "$WSS_ID")" ]; then meta_bak="$(mktemp)"; cp -f "$(tm9_wss_meta "$WSS_ID")" "$meta_bak"; fi
  if [ -f "$(tm9_wss_wg_config "$WSS_ID")" ]; then conf_bak="$(mktemp)"; cp -f "$(tm9_wss_wg_config "$WSS_ID")" "$conf_bak"; fi
  systemctl stop "$(tm9_wss_service "$WSS_ID")" "$(tm9_wss_wg_service "$WSS_ID")" >/dev/null 2>&1 || true
  wg-quick down "$WSS_IFACE" >/dev/null 2>&1 || true
  if [ "$WSS_ROLE" = 2 ]; then
    if ! tm9_validate_free_port tcp "$WSS_TCP_PORT" "WSS public" || ! tm9_validate_free_port udp "$WSS_WG_PORT" "WSS server WireGuard"; then [ "$was_active" = 1 ] && systemctl restart "$(tm9_wss_service "$WSS_ID")" "$(tm9_wss_wg_service "$WSS_ID")" >/dev/null 2>&1 || true; rm -f "$meta_bak" "$conf_bak"; return 1; fi
  else
    if ! tm9_validate_free_port udp "$WSS_WG_PORT" "WSS local forward" || ! tm9_validate_free_port udp "$WSS_CLIENT_LISTEN_PORT" "WSS client WireGuard"; then [ "$was_active" = 1 ] && systemctl restart "$(tm9_wss_service "$WSS_ID")" "$(tm9_wss_wg_service "$WSS_ID")" >/dev/null 2>&1 || true; rm -f "$meta_bak" "$conf_bak"; return 1; fi
  fi

  tm9_wss_save
  if [ -z "$WSS_REMOTE_PUBLIC_KEY" ]; then rm -f "$(tm9_wss_wg_config "$WSS_ID")"; warn_msg "Saved pending. Configure the same WSS number and secret on the other server."; rm -f "$meta_bak" "$conf_bak"; return 0; fi
  if ! tm9_wss_start "$WSS_ID"; then
    err_msg "New WSS configuration failed; restoring previous saved configuration."
    if [ -n "$meta_bak" ] && [ -s "$meta_bak" ]; then cp -f "$meta_bak" "$(tm9_wss_meta "$WSS_ID")"; fi
    if [ -n "$conf_bak" ] && [ -s "$conf_bak" ]; then cp -f "$conf_bak" "$(tm9_wss_wg_config "$WSS_ID")"; fi
    [ "$was_active" = 1 ] && { systemctl restart "$(tm9_wss_service "$WSS_ID")" >/dev/null 2>&1 || true; systemctl restart "$(tm9_wss_wg_service "$WSS_ID")" >/dev/null 2>&1 || true; }
    rm -f "$meta_bak" "$conf_bak"
    return 1
  fi
  rm -f "$meta_bak" "$conf_bak"
}

tm9_wss_collect_ids() { local f id; [ -d "$TM9_DIR/wss" ] || return 0; for f in "$TM9_DIR/wss"/tunnel-*.conf; do [ -e "$f" ] || continue; id="${f##*/tunnel-}"; id="${id%.conf}"; validate_tunnel_id "$id" && echo "$id"; done | sort -n -u; }
tm9_wss_remove() { local id="$1" ifc; ifc="$(tm9_wss_iface "$id")"; systemctl disable --now "$(tm9_wss_service "$id")" "$(tm9_wss_wg_service "$id")" >/dev/null 2>&1 || true; wg-quick down "$ifc" >/dev/null 2>&1 || true; ip link delete "$ifc" 2>/dev/null || true; rm -f "$(tm9_wss_meta "$id")" "$(tm9_wss_wg_config "$id")" "$(tm9_wss_key_private "$id")" "$(tm9_wss_key_public "$id")"; rm -rf "$TM9_HEALTH_DIR/wss-$id"; ok_msg "WSS tunnel $id removed."; }

# -----------------------------
# Hybrid GRE + Vira failover using stable 10.83.N.x addresses
# -----------------------------
tm9_hybrid_meta() { echo "$TM9_DIR/hybrid/tunnel-$1.conf"; }
tm9_hybrid_iface() { echo "hyb$1"; }
tm9_hybrid_load() { local id="$1" file; validate_tunnel_id "$id" || return 1; file="$(tm9_hybrid_meta "$id")"; [ -f "$file" ] || return 1; unset HYB_ID HYB_ROLE HYB_IFACE HYB_LOCAL_IP HYB_REMOTE_IP HYB_PRIMARY HYB_ACTIVE_PATH HEALTH_ENABLED 2>/dev/null || true; source "$file"; HYB_ID="$id"; HYB_IFACE="${HYB_IFACE:-$(tm9_hybrid_iface "$id")}"; HEALTH_ENABLED="${HEALTH_ENABLED:-1}"; }
tm9_hybrid_save() { tm9_prepare_dirs; local file; file="$(tm9_hybrid_meta "$HYB_ID")"; { write_var HYB_ID "$HYB_ID"; write_var HYB_ROLE "$HYB_ROLE"; write_var HYB_IFACE "$HYB_IFACE"; write_var HYB_LOCAL_IP "$HYB_LOCAL_IP"; write_var HYB_REMOTE_IP "$HYB_REMOTE_IP"; write_var HYB_PRIMARY "${HYB_PRIMARY:-wggre}"; write_var HYB_ACTIVE_PATH "${HYB_ACTIVE_PATH:-wggre}"; write_var HEALTH_ENABLED "${HEALTH_ENABLED:-1}"; } > "$file"; chmod 600 "$file"; }

tm9_hybrid_switch() {
  local id="$1" path="$2" ifc
  tm9_hybrid_load "$id" || return 1
  case "$path" in wggre|wgvira) ifc="$(tm9_overlay_iface "$path" "$id")" ;; *) return 1 ;; esac
  ip link show "$ifc" >/dev/null 2>&1 || return 1
  ip route replace "$HYB_REMOTE_IP/32" dev "$ifc" src "$HYB_LOCAL_IP" metric 10
  HYB_ACTIVE_PATH="$path"; tm9_hybrid_save
  echo "$path" > "$TM9_HEALTH_DIR/hybrid-$id.active"
  ok_msg "Hybrid $id route switched to $path ($ifc) -> $HYB_REMOTE_IP"
}

tm9_hybrid_start() {
  local id="$1" primary backup primary_target backup_target
  tm9_hybrid_load "$id" || return 1
  modprobe dummy 2>/dev/null || true
  ip link show "$HYB_IFACE" >/dev/null 2>&1 || ip link add "$HYB_IFACE" type dummy
  ip addr replace "$HYB_LOCAL_IP/32" dev "$HYB_IFACE"
  ip link set "$HYB_IFACE" up
  primary="${HYB_PRIMARY:-wggre}"; [ "$primary" = wggre ] && backup=wgvira || backup=wggre
  primary_target="$(tm9_overlay_remote_ip "$primary" "$id" "$HYB_ROLE")"; backup_target="$(tm9_overlay_remote_ip "$backup" "$id" "$HYB_ROLE")"
  if tm9_ping_quiet "$primary_target" "$(tm9_overlay_iface "$primary" "$id")"; then tm9_hybrid_switch "$id" "$primary"; elif tm9_ping_quiet "$backup_target" "$(tm9_overlay_iface "$backup" "$id")"; then tm9_hybrid_switch "$id" "$backup"; else warn_msg "Neither Hybrid path responds yet. Installing primary route for later recovery."; tm9_hybrid_switch "$id" "$primary" || true; fi
}

tm9_hybrid_write_service() {
  tm9_install_self
  cat > "$TM9_HYBRID_SERVICE_TEMPLATE" <<EOF
[Unit]
Description=Tunnel Manager v9 Hybrid stable route %i
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start-hybrid %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

tm9_hybrid_configure() {
  show_header "Hybrid GRE + Vira Failover"
  prompt_role || return
  local selected_role="$ROLE" primary_choice
  echo
  prompt_tunnel_id "Enter Hybrid tunnel number [1-254]: " || return
  HYB_ID="$TUNNEL_ID"; HYB_ROLE="$selected_role"; HYB_IFACE="$(tm9_hybrid_iface "$HYB_ID")"; HYB_LOCAL_IP="$(tm9_hybrid_local_ip_for_role "$HYB_ID" "$HYB_ROLE")"; HYB_REMOTE_IP="$(tm9_hybrid_remote_ip_for_role "$HYB_ID" "$HYB_ROLE")"; HYB_PRIMARY=wggre; HYB_ACTIVE_PATH=wggre; HEALTH_ENABLED=1
  if ! tm9_overlay_load wggre "$HYB_ID" || [ -z "${TM9_REMOTE_PUBLIC_KEY:-}" ]; then err_msg "WireGuard over GRE $HYB_ID must be configured with peer keys first."; return 1; fi
  [ "${TM9_ROLE:-}" = "$HYB_ROLE" ] || { err_msg "wggre$HYB_ID role does not match the selected Hybrid role."; return 1; }
  if ! tm9_overlay_load wgvira "$HYB_ID" || [ -z "${TM9_REMOTE_PUBLIC_KEY:-}" ]; then err_msg "WireGuard over Vira7 $HYB_ID must be configured with peer keys first."; return 1; fi
  [ "${TM9_ROLE:-}" = "$HYB_ROLE" ] || { err_msg "wgvira$HYB_ID role does not match the selected Hybrid role."; return 1; }
  echo "Stable Iran IP  : 10.83.$HYB_ID.1"
  echo "Stable Kharej IP: 10.83.$HYB_ID.2"
  echo "Applications/HAProxy can always target the stable remote IP: $HYB_REMOTE_IP"
  echo "1) GRE secure path as primary (recommended)"
  echo "2) Vira secure path as primary"
  read -rp "Select primary [1-2]: " primary_choice
  [ "$primary_choice" = 2 ] && HYB_PRIMARY=wgvira || HYB_PRIMARY=wggre
  tm9_hybrid_save; tm9_hybrid_write_service
  systemctl enable "tm9-hybrid@$HYB_ID.service" >/dev/null 2>&1 || true
  systemctl restart "tm9-hybrid@$HYB_ID.service" || return 1
  echo
  warn_msg "Hybrid automatic switching requires the optional health timer."
  if confirm_default_yes "Enable lightweight global health timer now?"; then tm9_health_enable; fi
}

tm9_hybrid_collect_ids() { local f id; [ -d "$TM9_DIR/hybrid" ] || return 0; for f in "$TM9_DIR/hybrid"/tunnel-*.conf; do [ -e "$f" ] || continue; id="${f##*/tunnel-}"; id="${id%.conf}"; validate_tunnel_id "$id" && echo "$id"; done | sort -n -u; }
tm9_hybrid_remove() { local id="$1" ifc; ifc="$(tm9_hybrid_iface "$id")"; systemctl disable --now "tm9-hybrid@$id.service" >/dev/null 2>&1 || true; if tm9_hybrid_load "$id"; then ip route del "$HYB_REMOTE_IP/32" 2>/dev/null || true; fi; ip link delete "$ifc" 2>/dev/null || true; rm -f "$(tm9_hybrid_meta "$id")" "$TM9_HEALTH_DIR/hybrid-$id.active"; rm -rf "$TM9_HEALTH_DIR/hybrid-$id"; ok_msg "Hybrid profile $id removed; GRE/Vira/WireGuard paths were kept."; }

# -----------------------------
# Optional low-CPU health manager
# -----------------------------
tm9_health_write_units() {
  local interval="$1"
  tm9_install_self
  cat > "$TM9_HEALTH_SERVICE" <<EOF
[Unit]
Description=Tunnel Manager v9 lightweight health check
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service health-run
Nice=10
IOSchedulingClass=idle
EOF
  cat > "$TM9_HEALTH_TIMER" <<EOF
[Unit]
Description=Tunnel Manager v9 health timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=${interval}s
AccuracySec=5s
RandomizedDelaySec=3s
Persistent=false

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
}

tm9_health_enable() {
  tm9_write_health_defaults
  local ENABLED=0 INTERVAL=$TM9_HEALTH_DEFAULT_INTERVAL FAIL_LIMIT=$TM9_HEALTH_DEFAULT_FAIL_LIMIT COOLDOWN=$TM9_HEALTH_DEFAULT_COOLDOWN
  source "$TM9_HEALTH_CONFIG"; ENABLED=1
  cat > "$TM9_HEALTH_CONFIG" <<EOF
ENABLED=1
INTERVAL=${INTERVAL:-$TM9_HEALTH_DEFAULT_INTERVAL}
FAIL_LIMIT=${FAIL_LIMIT:-$TM9_HEALTH_DEFAULT_FAIL_LIMIT}
COOLDOWN=${COOLDOWN:-$TM9_HEALTH_DEFAULT_COOLDOWN}
EOF
  tm9_health_write_units "${INTERVAL:-$TM9_HEALTH_DEFAULT_INTERVAL}"
  systemctl enable --now tm9-health.timer >/dev/null 2>&1 || true
  ok_msg "Low-CPU health timer enabled (one ping per enabled tunnel every ${INTERVAL}s)."
}

tm9_health_disable() {
  tm9_write_health_defaults
  local INTERVAL=$TM9_HEALTH_DEFAULT_INTERVAL FAIL_LIMIT=$TM9_HEALTH_DEFAULT_FAIL_LIMIT COOLDOWN=$TM9_HEALTH_DEFAULT_COOLDOWN
  source "$TM9_HEALTH_CONFIG"
  cat > "$TM9_HEALTH_CONFIG" <<EOF
ENABLED=0
INTERVAL=${INTERVAL:-$TM9_HEALTH_DEFAULT_INTERVAL}
FAIL_LIMIT=${FAIL_LIMIT:-$TM9_HEALTH_DEFAULT_FAIL_LIMIT}
COOLDOWN=${COOLDOWN:-$TM9_HEALTH_DEFAULT_COOLDOWN}
EOF
  systemctl disable --now tm9-health.timer >/dev/null 2>&1 || true
  ok_msg "Health timer disabled. Built-in Vira dead-path recovery remains controlled per Vira config."
}

tm9_health_record() {
  local key="$1" success="$2" fail_limit="$3" cooldown="$4" dir now fails last_action
  dir="$TM9_HEALTH_DIR/$key"; mkdir -p "$dir"; now="$(date +%s)"; fails="$(cat "$dir/fails" 2>/dev/null || echo 0)"; last_action="$(cat "$dir/last_action" 2>/dev/null || echo 0)"
  if [ "$success" = 1 ]; then echo 0 > "$dir/fails"; return 1; fi
  fails=$((fails + 1)); echo "$fails" > "$dir/fails"
  if [ "$fails" -ge "$fail_limit" ] && [ $((now - last_action)) -ge "$cooldown" ]; then echo "$now" > "$dir/last_action"; echo 0 > "$dir/fails"; return 0; fi
  return 1
}

tm9_health_check_vira() {
  local id="$1" target ok=0
  vira7_load_config "$id" || return 0; [ "${HEALTH_ENABLED:-0}" = 1 ] || return 0; target="${REMOTE_VIRA7_IP:-}"
  tm9_ping_quiet "$target" "$VIRA7_IFACE" && ok=1
  if tm9_health_record "vira-$id" "$ok" "$HEALTH_FAIL_LIMIT" "$HEALTH_COOLDOWN"; then systemctl restart "$(vira7_service_name "$id")" >/dev/null 2>&1 || true; fi
}

tm9_health_check_overlay() {
  local kind="$1" id="$2" ok=0 target ifc
  tm9_overlay_load "$kind" "$id" || return 0; [ "${HEALTH_ENABLED:-0}" = 1 ] || return 0; target="$TM9_REMOTE_IP"; ifc="$TM9_IFACE"
  tm9_ping_quiet "$target" "$ifc" && ok=1
  if tm9_health_record "$kind-$id" "$ok" "$HEALTH_FAIL_LIMIT" "$HEALTH_COOLDOWN"; then
    if [ "$kind" = wgvira ]; then systemctl restart "$(vira7_service_name "$id")" >/dev/null 2>&1 || true; sleep 1; fi
    tm9_overlay_start "$kind" "$id" >/dev/null 2>&1 || true
  fi
}

tm9_health_check_wss() {
  local id="$1" ok=0
  tm9_wss_load "$id" || return 0; [ "${HEALTH_ENABLED:-0}" = 1 ] || return 0
  tm9_ping_quiet "$WSS_REMOTE_IP" "$WSS_IFACE" && ok=1
  if tm9_health_record "wss-$id" "$ok" "$HEALTH_FAIL_LIMIT" "$HEALTH_COOLDOWN"; then systemctl restart "$(tm9_wss_service "$id")" >/dev/null 2>&1 || true; sleep 1; systemctl restart "$(tm9_wss_wg_service "$id")" >/dev/null 2>&1 || true; fi
}

tm9_health_check_hybrid() {
  local id="$1" primary backup ptarget btarget pif bif current state_dir rise=0 ok=0
  tm9_hybrid_load "$id" || return 0
  [ "${HEALTH_ENABLED:-1}" = "1" ] || return 0
  primary="${HYB_PRIMARY:-wggre}"; [ "$primary" = "wggre" ] && backup="wgvira" || backup="wggre"
  pif="$(tm9_overlay_iface "$primary" "$id")"; bif="$(tm9_overlay_iface "$backup" "$id")"
  ptarget="$(tm9_overlay_remote_ip "$primary" "$id" "$HYB_ROLE")"; btarget="$(tm9_overlay_remote_ip "$backup" "$id" "$HYB_ROLE")"
  current="${HYB_ACTIVE_PATH:-$primary}"; state_dir="$TM9_HEALTH_DIR/hybrid-$id"; mkdir -p "$state_dir"

  if [ "$current" = "$primary" ]; then
    tm9_ping_quiet "$ptarget" "$pif" && ok=1 || ok=0
    if tm9_health_record "hybrid-$id-primary" "$ok" "$HEALTH_FAIL_LIMIT" "$HEALTH_COOLDOWN"; then
      if tm9_ping_quiet "$btarget" "$bif"; then tm9_hybrid_switch "$id" "$backup" >/dev/null 2>&1 || true; fi
    fi
    echo 0 > "$state_dir/primary_rise"
    return 0
  fi

  # While on backup, require two consecutive successful primary checks before failback.
  if tm9_ping_quiet "$ptarget" "$pif"; then
    rise="$(cat "$state_dir/primary_rise" 2>/dev/null || echo 0)"; rise=$((rise + 1)); echo "$rise" > "$state_dir/primary_rise"
    if [ "$rise" -ge 2 ]; then tm9_hybrid_switch "$id" "$primary" >/dev/null 2>&1 || true; echo 0 > "$state_dir/primary_rise"; fi
    return 0
  fi
  echo 0 > "$state_dir/primary_rise"

  # Backup is also checked, but no route flapping occurs on a single failed ping.
  tm9_ping_quiet "$btarget" "$bif" && ok=1 || ok=0
  if tm9_health_record "hybrid-$id-backup" "$ok" "$HEALTH_FAIL_LIMIT" "$HEALTH_COOLDOWN"; then
    if tm9_ping_quiet "$ptarget" "$pif"; then tm9_hybrid_switch "$id" "$primary" >/dev/null 2>&1 || true; fi
  fi
}

tm9_health_run() {
  tm9_write_health_defaults
  local ENABLED=0 INTERVAL=$TM9_HEALTH_DEFAULT_INTERVAL FAIL_LIMIT=$TM9_HEALTH_DEFAULT_FAIL_LIMIT COOLDOWN=$TM9_HEALTH_DEFAULT_COOLDOWN ids id
  source "$TM9_HEALTH_CONFIG"; [ "${ENABLED:-0}" = 1 ] || [ "${TM9_HEALTH_FORCE:-0}" = 1 ] || return 0
  HEALTH_FAIL_LIMIT="${FAIL_LIMIT:-$TM9_HEALTH_DEFAULT_FAIL_LIMIT}"; HEALTH_COOLDOWN="${COOLDOWN:-$TM9_HEALTH_DEFAULT_COOLDOWN}"
  exec 9>"$TM9_HEALTH_DIR/health.lock"; flock -n 9 || return 0
  ids="$(vira7_collect_ids || true)"; while IFS= read -r id; do [ -n "$id" ] && tm9_health_check_vira "$id"; done <<< "$ids"
  for kind in wggre wgvira; do ids="$(tm9_overlay_collect_ids "$kind" || true)"; while IFS= read -r id; do [ -n "$id" ] && tm9_health_check_overlay "$kind" "$id"; done <<< "$ids"; done
  ids="$(tm9_wss_collect_ids || true)"; while IFS= read -r id; do [ -n "$id" ] && tm9_health_check_wss "$id"; done <<< "$ids"
  ids="$(tm9_hybrid_collect_ids || true)"; while IFS= read -r id; do [ -n "$id" ] && tm9_health_check_hybrid "$id"; done <<< "$ids"
}

tm9_health_set_interval() {
  local interval="$1" ENABLED=0 INTERVAL=30 FAIL_LIMIT=3 COOLDOWN=120
  [[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 15 ] && [ "$interval" -le 600 ] || { err_msg "Interval must be 15-600 seconds."; return 1; }
  tm9_write_health_defaults; source "$TM9_HEALTH_CONFIG"; INTERVAL="$interval"
  cat > "$TM9_HEALTH_CONFIG" <<EOF
ENABLED=${ENABLED:-0}
INTERVAL=$INTERVAL
FAIL_LIMIT=${FAIL_LIMIT:-3}
COOLDOWN=${COOLDOWN:-120}
EOF
  tm9_health_write_units "$INTERVAL"; [ "${ENABLED:-0}" = 1 ] && systemctl restart tm9-health.timer >/dev/null 2>&1 || true
  ok_msg "Health interval changed to ${INTERVAL}s."
}

tm9_health_toggle_all() {
  local value="$1" f kind id
  for f in "$VIRA7_CONFIG_DIR"/tunnel-*.conf "$TM9_DIR/wggre"/tunnel-*.conf "$TM9_DIR/wgvira"/tunnel-*.conf "$TM9_DIR/wss"/tunnel-*.conf; do [ -e "$f" ] || continue; tm9_set_health_flag_in_file "$f" "$value"; done
  ok_msg "Per-tunnel external health flag set to $value for all saved Vira/v9 secure tunnels."
}

tm9_health_menu() {
  local choice interval ENABLED=0 INTERVAL=30 FAIL_LIMIT=3 COOLDOWN=120
  while true; do
    tm9_write_health_defaults; source "$TM9_HEALTH_CONFIG"
    show_header "Optional Low-CPU Health Manager"
    echo "Global timer : $([ "${ENABLED:-0}" = 1 ] && echo ENABLED || echo DISABLED)"
    echo "Interval     : ${INTERVAL}s"
    echo "Fail limit   : ${FAIL_LIMIT} consecutive failures"
    echo "Cooldown     : ${COOLDOWN}s"
    echo
    echo "1) Enable global health timer"
    echo "2) Disable global health timer"
    echo "3) Run one health pass now"
    echo "4) Change interval (15-600 seconds)"
    echo "5) Enable health flag for all v9/Vira tunnels"
    echo "6) Disable health flag for all v9/Vira tunnels"
    echo "00) Back"
    read -rp "Choose [1-6/00]: " choice
    case "$choice" in
      1) tm9_health_enable; pause ;;
      2) tm9_health_disable; pause ;;
      3) TM9_HEALTH_FORCE=1 tm9_health_run; ok_msg "Health pass completed."; pause ;;
      4) read -rp "New interval seconds [15-600]: " interval; tm9_health_set_interval "$interval" || true; pause ;;
      5) tm9_health_toggle_all 1; pause ;;
      6) tm9_health_toggle_all 0; pause ;;
      00) return ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# v9 unified create/status/inventory/remove/reset menus
# -----------------------------
ask_tunnel_type() {
  echo "Tunnel Manager v9 types:"
  echo "1) Normal GRE"
  echo "2) Improved Vira7"
  echo "3) WireGuard over GRE"
  echo "4) WireGuard over Vira7"
  echo "5) Hybrid GRE + Vira Failover"
  echo "6) WSS/TCP Emergency Tunnel"
  echo
  read -rp "Choose [1-6] (00=menu): " TUNNEL_TYPE_CHOICE
  if is_main_menu_token "$TUNNEL_TYPE_CHOICE"; then return_main_msg; return 99; fi
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE=gre ;;
    2) SELECTED_TUNNEL_TYPE=vira7 ;;
    3) SELECTED_TUNNEL_TYPE=wggre ;;
    4) SELECTED_TUNNEL_TYPE=wgvira ;;
    5) SELECTED_TUNNEL_TYPE=hybrid ;;
    6) SELECTED_TUNNEL_TYPE=wss ;;
    *) err_msg "Invalid tunnel type"; return 1 ;;
  esac
}

menu_config_tunnel() {
  show_header "Tunnel Manager v9 - Create / Update"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_menu_config_tunnel ;;
    vira7) vira7_menu_config_tunnel ;;
    wggre) tm9_overlay_configure wggre ;;
    wgvira) tm9_overlay_configure wgvira ;;
    hybrid) tm9_hybrid_configure ;;
    wss) tm9_wss_configure ;;
  esac
}

build_tunnel_inventory() {
  INV_TYPE=(); INV_ID=(); INV_IFACE=(); INV_LOCAL=(); INV_TARGET=(); INV_LOCAL_PUBLIC=(); INV_REMOTE_PUBLIC=(); INV_STATE=(); INV_DESC=()
  local ids id ifc local_ip target local_pub remote_pub state desc kind

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(gre_iface "$id")"; local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Normal GRE"
    if gre_load_config "$id"; then
      local_ip="${LOCAL_GRE_IP:-}"; target="${REMOTE_GRE_IP:-}"; local_pub="${LOCAL_PUBLIC_IP:-}"; remote_pub="${REMOTE_PUBLIC_IP:-}"
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("gre"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(wg_iface_name "$id")"; local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Legacy WireGuard"
    if wg_load_meta "$id"; then
      local_ip="${LOCAL_WG_IP:-}"; target="${REMOTE_WG_IP:-}"; local_pub="${LOCAL_PUBLIC_IP:-}"; remote_pub="${REMOTE_PUBLIC_IP:-${WG_ENDPOINT_IP:-}}"
      [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ] && desc="Legacy WG/PENDING"
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("wireguard"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(vira7_iface_name "$id")"; local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Improved Vira7"
    if vira7_load_config "$id"; then
      local_ip="${LOCAL_VIRA7_IP:-}"; target="${REMOTE_VIRA7_IP:-}"; local_pub="${LOCAL_PUBLIC_IP:-}"; remote_pub="${REMOTE_PUBLIC_IP:-}"
      [ "${VIRA7_DEAD_TIMEOUT:-0}" = "0" ] && desc="Legacy Vira7"
    fi
    if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
    INV_TYPE+=("vira7"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  for kind in wggre wgvira; do
    ids="$(tm9_overlay_collect_ids "$kind" || true)"
    while IFS= read -r id; do
      [ -n "$id" ] || continue
      if tm9_overlay_load "$kind" "$id"; then
        ifc="$TM9_IFACE"; local_ip="$TM9_LOCAL_IP"; target="$TM9_REMOTE_IP"; local_pub="$TM9_TRANSPORT_IFACE"; remote_pub="$TM9_TRANSPORT_REMOTE_IP"; desc="$kind"
        [ -z "${TM9_REMOTE_PUBLIC_KEY:-}" ] && desc="$kind/PENDING"
        if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
        INV_TYPE+=("$kind"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
      fi
    done <<< "$ids"
  done

  ids="$(tm9_hybrid_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if tm9_hybrid_load "$id"; then
      ifc="$HYB_IFACE"; local_ip="$HYB_LOCAL_IP"; target="$HYB_REMOTE_IP"; local_pub="${HYB_PRIMARY:-wggre}"; remote_pub="${HYB_ACTIVE_PATH:-?}"; desc="Hybrid stable"
      if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
      INV_TYPE+=("hybrid"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
    fi
  done <<< "$ids"

  ids="$(tm9_wss_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if tm9_wss_load "$id"; then
      ifc="$WSS_IFACE"; local_ip="$WSS_LOCAL_IP"; target="$WSS_REMOTE_IP"; local_pub="$WSS_LOCAL_PUBLIC_IP"; remote_pub="$WSS_REMOTE_PUBLIC_IP"; desc="WSS/TCP"
      [ -z "${WSS_REMOTE_PUBLIC_KEY:-}" ] && desc="WSS/PENDING"
      if ip link show "$ifc" >/dev/null 2>&1; then state="active"; else state="inactive"; fi
      INV_TYPE+=("wss"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
    fi
  done <<< "$ids"
}

remove_inventory_item() {
  local index="$1" i type id
  i=$((index - 1)); type="${INV_TYPE[$i]}"; id="${INV_ID[$i]}"
  case "$type" in
    gre) gre_remove_one_tunnel "$id" ;;
    wireguard) wg_remove_one_tunnel "$id" ;;
    vira7) vira7_remove_one_tunnel "$id" ;;
    wggre|wgvira) tm9_overlay_remove "$type" "$id" ;;
    hybrid) tm9_hybrid_remove "$id" ;;
    wss) tm9_wss_remove "$id" ;;
  esac
}

ping_inventory_item() {
  local index="$1" i type id
  i=$((index - 1)); type="${INV_TYPE[$i]}"; id="${INV_ID[$i]}"
  case "$type" in
    gre) test_gre_tunnel_ping "$id" ;;
    wireguard) test_wg_tunnel_ping "$id" ;;
    vira7) test_vira7_tunnel_ping "$id" ;;
    wggre|wgvira)
      if tm9_overlay_load "$type" "$id"; then ping4_target "$type $id remote secure IP" "$TM9_REMOTE_IP"; fi
      ;;
    hybrid)
      if tm9_hybrid_load "$id"; then ping4_target "Hybrid $id stable remote IP" "$HYB_REMOTE_IP"; fi
      ;;
    wss)
      if tm9_wss_load "$id"; then ping4_target "WSS $id remote secure IP" "$WSS_REMOTE_IP"; fi
      ;;
  esac
}

remove_tun() {
  show_header "Remove Tunnel Safely"
  build_tunnel_inventory
  print_tunnel_inventory || return
  local selected i type id
  read -rp "Enter one row number to remove (00=menu): " selected
  if is_main_menu_token "$selected"; then return_main_msg; return 99; fi
  if ! [[ "$selected" =~ ^[0-9]+$ ]] || [ "$selected" -lt 1 ] || [ "$selected" -gt "${#INV_TYPE[@]}" ]; then
    err_msg "Invalid row."
    return 1
  fi
  i=$((selected - 1)); type="${INV_TYPE[$i]}"; id="${INV_ID[$i]}"
  if [ "$type" = "gre" ] && [ -f "$(tm9_overlay_meta wggre "$id")" ]; then err_msg "Cannot remove gre$id while wggre$id exists. Remove WireGuard over GRE first."; return 1; fi
  if [ "$type" = "vira7" ] && [ -f "$(tm9_overlay_meta wgvira "$id")" ]; then err_msg "Cannot remove vira7$id while wgvira$id exists. Remove WireGuard over Vira first."; return 1; fi
  if { [ "$type" = "wggre" ] || [ "$type" = "wgvira" ]; } && [ -f "$(tm9_hybrid_meta "$id")" ]; then err_msg "Cannot remove $type$id while Hybrid $id uses it. Remove Hybrid profile first."; return 1; fi
  if confirm_yes "Remove $type tunnel/profile $id?"; then remove_inventory_item "$selected"; else echo "Cancelled."; fi
}

status_check() { show_header "Tunnel Manager v9 Status"; build_tunnel_inventory; print_tunnel_inventory || true; tm9_port_range_text; echo; if tm9_health_is_enabled;then echo "Health timer: ENABLED";else echo "Health timer: DISABLED";fi; }

reset_all_tunnels() {
  show_header "Reset All Tunnels (safe service restart)"
  echo "This restarts saved services without deleting or rewriting Normal GRE configs."
  if ! confirm_yes "Restart all saved legacy and v9 tunnels?"; then echo "Cancelled."; return 0; fi
  local ids id kind svc

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(gre_service_name "$id")"
    systemctl enable "$svc" >/dev/null 2>&1 || true
    systemctl restart "$svc" >/dev/null 2>&1 || gre_service_start "$id" >/dev/null 2>&1 || true
  done <<< "$ids"

  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && systemctl restart "$(vira7_service_name "$id")" >/dev/null 2>&1 || true; done <<< "$ids"

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && systemctl restart "$(wg_service_name "$id")" >/dev/null 2>&1 || true; done <<< "$ids"

  for kind in wggre wgvira; do
    ids="$(tm9_overlay_collect_ids "$kind" || true)"
    while IFS= read -r id; do [ -n "$id" ] && tm9_overlay_start "$kind" "$id" >/dev/null 2>&1 || true; done <<< "$ids"
  done

  ids="$(tm9_wss_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && tm9_wss_start "$id" >/dev/null 2>&1 || true; done <<< "$ids"

  ids="$(tm9_hybrid_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && tm9_hybrid_start "$id" >/dev/null 2>&1 || true; done <<< "$ids"
  ok_msg "Safe restart pass finished."
}

show_menu() {
  show_header "Tunnel Manager v9"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel (6 v9 types)"
  echo -e "  ${C_RED}2)${C_RESET} remove one tunnel safely"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all saved tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} HAProxy port manager"
  echo -e "  ${C_BLUE}6)${C_RESET} optimize Vira7 CPU"
  echo -e "  ${C_CYAN}7)${C_RESET} optional low-CPU health manager"
  echo -e "  ${C_WHITE}8)${C_RESET} show status / IP and port ranges"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  read -rp "Choose [0-8]: " CHOICE
  case "$CHOICE" in
    1) if menu_config_tunnel;then pause;fi;;
    2) if remove_tun;then pause;fi;;
    3) if reset_all_tunnels;then pause;fi;;
    4) if test_tunnels_menu;then pause;fi;;
    5) haproxy_menu||true;;
    6) if vira7_optimize_cpu_menu;then pause;fi;;
    7) tm9_health_menu;;
    8) status_check;pause;;
    0) echo "Bye";exit 0;;
    *) err_msg "Invalid option";sleep 1;;
  esac
}


### Script entry
if [[ "${1:-}" == "--self-test" ]]; then
  echo "Tunnel Manager v9 self-test"
  echo "Version: $TM9_VERSION"
  echo "GRE function preserved: $(declare -F gre_create_tunnel >/dev/null && echo yes || echo no)"
  echo "Improved Vira compiler: $(declare -F vira7_compile_engine >/dev/null && echo yes || echo no)"
  echo "WGGRE IP example : $(tm9_overlay_local_ip wggre 3 1) <-> $(tm9_overlay_remote_ip wggre 3 1)"
  echo "WGVIRA IP example: $(tm9_overlay_local_ip wgvira 3 1) <-> $(tm9_overlay_remote_ip wgvira 3 1)"
  echo "Hybrid IP example: $(tm9_hybrid_local_ip_for_role 3 1) <-> $(tm9_hybrid_remote_ip_for_role 3 1)"
  echo "WSS IP example   : $(tm9_wss_local_ip 3 1) <-> $(tm9_wss_remote_ip 3 1)"
  tm9_port_range_text
  exit 0
fi
if [[ "${1:-}" == "--service" ]]; then
  case "${2:-}" in
    start-gre)
      ensure_root
      gre_service_start "${3:-}"
      exit $?
      ;;
    start)
      # Backward compatibility with older gre-tunnel@ service template.
      ensure_root
      gre_service_start "${3:-}"
      exit $?
      ;;
    firewall-wg)
      ensure_root
      wg_apply_firewall_rules "${3:-}"
      exit $?
      ;;
    firewall-vira7)
      ensure_root
      vira7_apply_firewall_rules "${3:-}"
      exit $?
      ;;
    start-vira7)
      ensure_root
      vira7_restart_one_tunnel "${3:-}"
      exit $?
      ;;
    run-wss)
      ensure_root
      tm9_wss_run "${3:-}"
      exit $?
      ;;
    start-hybrid)
      ensure_root
      tm9_hybrid_start "${3:-}"
      exit $?
      ;;
    health-run)
      ensure_root
      tm9_health_run
      exit $?
      ;;
    *)
      echo "Unknown service command." >&2
      exit 1
      ;;
  esac
fi

ensure_root
while true; do
  show_menu
done
