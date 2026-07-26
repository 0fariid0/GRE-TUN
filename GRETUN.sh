#!/bin/bash
set -euo pipefail

# GRE + WireGuard + Vira Hybrid + HAProxy multi-tunnel manager v10.0.0
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - WireGuard can use public UDP or automatically ride over an existing GRE tunnel as transport
# - Local tunnel/bind IPv4 can be selected manually for servers with multiple IPs
# - v10 rewrites Vira from scratch with authenticated framing, ephemeral UDP client ports, and automatic TCP fallback

SCRIPT_VERSION="10.0.0-vira-hybrid"

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
VIRA7_DEFAULT_MTU=1280
VIRA7_DEFAULT_PORT_BASE=5571
VIRA7_DEFAULT_KEEPALIVE=3
VIRA7_DEFAULT_BUFFER_SIZE=8388608
VIRA7_DEFAULT_QUEUE_LEN=4000
VIRA7_DEFAULT_TRANSPORT="auto"
VIRA7_DEFAULT_LOCAL_PORT=0
VIRA7_DEFAULT_HANDSHAKE_TIMEOUT=4
VIRA7_DEFAULT_PEER_TIMEOUT=20
VIRA7_DEFAULT_RECONNECT_INTERVAL=5
# Backward-compatible variables retained for old configs/menu code.
# checksum=1 keeps packet format compatible with older engines.
# verify_checksum=0 trusts UDP checksum and skips expensive userspace checksum validation on receive.
# batch=128 drains packet bursts per select() wakeup and reduces syscall/loop overhead.
VIRA7_DEFAULT_CHECKSUM=1
VIRA7_DEFAULT_VERIFY_CHECKSUM=0
VIRA7_DEFAULT_BATCH=128
VIRA7_DEFAULT_PEER_LOCK=1
VIRA7_DEFAULT_RECONNECT_TIMEOUT=$VIRA7_DEFAULT_RECONNECT_INTERVAL

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
  echo "3) Vira Hybrid auto UDP/TCP tunnel"
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
# Vira Hybrid Auto UDP/TCP helpers
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

vira7_stats_file() {
  echo "/run/vira7-$(vira7_iface_name "$1").stats"
}

vira7_default_port() {
  local id="$1"
  echo $((VIRA7_DEFAULT_PORT_BASE + id))
}


vira7_default_auth_key() {
  local id="$1" port="$2"
  # Matching identifier, not encryption. It is deterministic so both servers derive the same value.
  printf 'gretun-vira-hybrid-v2-%s-%s' "$id" "$port"
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

vira7_mode_for_role() {
  local role="$1"
  local direction="${2:-recommended}"
  if [ "$direction" = "legacy" ]; then
    if [ "$role" = "1" ]; then echo "server"; else echo "client"; fi
  else
    # Recommended for filtered networks: Iran initiates outbound UDP to Kharej.
    if [ "$role" = "1" ]; then echo "client"; else echo "server"; fi
  fi
}

vira7_infer_direction() {
  local role="${1:-}"
  local mode="${2:-}"
  if { [ "$role" = "1" ] && [ "$mode" = "server" ]; } || { [ "$role" = "2" ] && [ "$mode" = "client" ]; }; then
    echo "legacy"
  else
    echo "recommended"
  fi
}

vira7_ensure_deps() {
  if command -v gcc >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    return 0
  fi
  echo "Installing Vira7 build/runtime dependencies..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential gcc iproute2 iptables kmod procps
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make iproute iptables kmod procps-ng
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make iproute iptables kmod procps-ng
  else
    echo "No supported package manager found. Install gcc, iproute2, iptables, kmod and procps manually." >&2
    return 1
  fi
}

vira7_tune_kernel() {
  local id="${1:-}"
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-vira7-stable.conf <<EOF_SYSCTL
net.ipv4.ip_forward = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 4194304
net.core.wmem_default = 4194304
net.core.netdev_max_backlog = 16384
net.ipv4.udp_rmem_min = 131072
net.ipv4.udp_wmem_min = 131072
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF_SYSCTL
  sysctl -p /etc/sysctl.d/99-vira7-stable.conf >/dev/null 2>&1 || true
  if validate_tunnel_id "$id"; then
    sysctl -w "net.ipv4.conf.$(vira7_iface_name "$id").rp_filter=0" >/dev/null 2>&1 || true
  fi
}

vira7_compile_engine() {
  vira7_ensure_deps || return 1
  mkdir -p "$VIRA7_CONFIG_DIR"
  cat > "$VIRA7_SOURCE" <<'ENGINEEOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define ENGINE_NAME "Vira Hybrid"
#define ENGINE_VERSION "10.0.0"
#define TUN_DEVICE "/dev/net/tun"
#define PROTO_MAGIC 0x56485232U /* VHR2 */
#define PROTO_VERSION 2U
#define HEADER_SIZE 40U
#define MAX_PAYLOAD 9000U
#define MAX_PACKET (HEADER_SIZE + MAX_PAYLOAD)
#define TCP_RX_CAP (MAX_PACKET * 4U + 16U)

#define TYPE_HELLO 1U
#define TYPE_HELLO_ACK 2U
#define TYPE_DATA 3U
#define TYPE_PING 4U
#define TYPE_PONG 5U

typedef enum {
    ACTIVE_NONE = 0,
    ACTIVE_UDP = 1,
    ACTIVE_TCP = 2
} active_transport_t;

typedef struct {
    char iface[IFNAMSIZ];
    char mode[16];
    char transport[16];
    char bind_ip[64];
    char remote_ip[64];
    char local_priv[64];
    char remote_priv[64];
    char auth_key[160];
    int tunnel_id;
    int port;
    int local_port;
    int mtu;
    int keepalive;
    int handshake_timeout;
    int peer_timeout;
    int reconnect_interval;
    int buffer_size;
    int queue_len;
    int peer_lock;
    int stats_interval;
} config_t;

typedef struct {
    uint8_t data[TCP_RX_CAP];
    size_t used;
} tcp_rx_buffer_t;

typedef struct {
    config_t cfg;
    int tun_fd;
    int udp_fd;
    int tcp_listen_fd;
    int tcp_fd;
    tcp_rx_buffer_t tcp_rx;
    struct sockaddr_in configured_remote;
    struct sockaddr_in udp_peer;
    struct sockaddr_in tcp_peer;
    int udp_peer_known;
    int tcp_peer_known;
    int tcp_authenticated;
    active_transport_t active;
    uint64_t cookie;
    uint64_t session_nonce;
    uint32_t seq;
    int64_t started_ms;
    int64_t last_rx_ms;
    int64_t last_tx_ms;
    int64_t last_hello_udp_ms;
    int64_t last_tcp_attempt_ms;
    int64_t tcp_connected_ms;
    int64_t last_stats_ms;
    unsigned long long tx_packets;
    unsigned long long rx_packets;
    unsigned long long tx_bytes;
    unsigned long long rx_bytes;
    unsigned long long drops;
    unsigned long long reconnects;
    unsigned long long fallback_count;
    unsigned long long udp_handshakes;
    unsigned long long tcp_handshakes;
} app_t;

static volatile sig_atomic_t g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

static int64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (int64_t)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static uint64_t random_u64(void) {
    uint64_t v = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n = read(fd, &v, sizeof(v));
        close(fd);
        if (n == (ssize_t)sizeof(v) && v != 0) return v;
    }
    v = ((uint64_t)time(NULL) << 32) ^ (uint64_t)getpid() ^ (uint64_t)monotonic_ms();
    return v ? v : 1ULL;
}

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1U);
    size_t n = strlen(s);
    while (n > 0U && (s[n - 1U] == ' ' || s[n - 1U] == '\t' || s[n - 1U] == '\r' || s[n - 1U] == '\n')) {
        s[--n] = '\0';
    }
}

static uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static uint32_t crc32_bytes(const uint8_t *data, size_t len) {
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

static void put_u16(uint8_t *p, uint16_t v) {
    v = htons(v);
    memcpy(p, &v, sizeof(v));
}

static void put_u32(uint8_t *p, uint32_t v) {
    v = htonl(v);
    memcpy(p, &v, sizeof(v));
}

static void put_u64(uint8_t *p, uint64_t v) {
    uint32_t hi = htonl((uint32_t)(v >> 32));
    uint32_t lo = htonl((uint32_t)(v & 0xffffffffULL));
    memcpy(p, &hi, sizeof(hi));
    memcpy(p + 4, &lo, sizeof(lo));
}

static uint16_t get_u16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return ntohs(v);
}

static uint32_t get_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return ntohl(v);
}

static uint64_t get_u64(const uint8_t *p) {
    uint32_t hi, lo;
    memcpy(&hi, p, sizeof(hi));
    memcpy(&lo, p + 4, sizeof(lo));
    return ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
}

static int build_packet(uint8_t *out, size_t out_cap, uint8_t type, uint32_t tunnel_id,
                        uint64_t cookie, uint64_t nonce, uint32_t seq,
                        const uint8_t *payload, uint16_t payload_len) {
    size_t total = HEADER_SIZE + payload_len;
    if (!out || total > out_cap || payload_len > MAX_PAYLOAD) return -1;
    memset(out, 0, HEADER_SIZE);
    put_u32(out + 0, PROTO_MAGIC);
    out[4] = PROTO_VERSION;
    out[5] = type;
    put_u16(out + 6, 0U);
    put_u32(out + 8, tunnel_id);
    put_u64(out + 12, cookie);
    put_u64(out + 20, nonce);
    put_u32(out + 28, seq);
    put_u16(out + 32, payload_len);
    put_u16(out + 34, 0U);
    put_u32(out + 36, 0U);
    if (payload_len > 0U && payload) memcpy(out + HEADER_SIZE, payload, payload_len);
    put_u32(out + 36, crc32_bytes(out, total));
    return (int)total;
}

static int parse_packet(const uint8_t *buf, size_t len, uint32_t expected_tunnel,
                        uint64_t expected_cookie, uint8_t *type, uint64_t *nonce,
                        uint32_t *seq, const uint8_t **payload, uint16_t *payload_len) {
    if (!buf || len < HEADER_SIZE || len > MAX_PACKET) return -1;
    if (get_u32(buf + 0) != PROTO_MAGIC || buf[4] != PROTO_VERSION) return -1;
    if (get_u32(buf + 8) != expected_tunnel || get_u64(buf + 12) != expected_cookie) return -1;
    uint16_t plen = get_u16(buf + 32);
    if (HEADER_SIZE + (size_t)plen != len || plen > MAX_PAYLOAD) return -1;
    uint8_t temp[MAX_PACKET];
    memcpy(temp, buf, len);
    uint32_t got_crc = get_u32(temp + 36);
    put_u32(temp + 36, 0U);
    if (got_crc != crc32_bytes(temp, len)) return -1;
    uint8_t t = buf[5];
    if (t < TYPE_HELLO || t > TYPE_PONG) return -1;
    *type = t;
    *nonce = get_u64(buf + 20);
    *seq = get_u32(buf + 28);
    *payload_len = plen;
    *payload = buf + HEADER_SIZE;
    return 0;
}

static int load_config(const char *path, config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->iface, sizeof(c->iface), "vira7");
    snprintf(c->mode, sizeof(c->mode), "client");
    snprintf(c->transport, sizeof(c->transport), "auto");
    snprintf(c->bind_ip, sizeof(c->bind_ip), "0.0.0.0");
    c->tunnel_id = 1;
    c->port = 5572;
    c->local_port = 0;
    c->mtu = 1280;
    c->keepalive = 3;
    c->handshake_timeout = 4;
    c->peer_timeout = 20;
    c->reconnect_interval = 5;
    c->buffer_size = 8388608;
    c->queue_len = 4000;
    c->peer_lock = 1;
    c->stats_interval = 3;

    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);
        if (!strcmp(key, "iface")) snprintf(c->iface, sizeof(c->iface), "%s", val);
        else if (!strcmp(key, "mode")) snprintf(c->mode, sizeof(c->mode), "%s", val);
        else if (!strcmp(key, "transport")) snprintf(c->transport, sizeof(c->transport), "%s", val);
        else if (!strcmp(key, "bind_ip")) snprintf(c->bind_ip, sizeof(c->bind_ip), "%s", val);
        else if (!strcmp(key, "remote_ip")) snprintf(c->remote_ip, sizeof(c->remote_ip), "%s", val);
        else if (!strcmp(key, "local_priv")) snprintf(c->local_priv, sizeof(c->local_priv), "%s", val);
        else if (!strcmp(key, "remote_priv")) snprintf(c->remote_priv, sizeof(c->remote_priv), "%s", val);
        else if (!strcmp(key, "auth_key")) snprintf(c->auth_key, sizeof(c->auth_key), "%s", val);
        else if (!strcmp(key, "tunnel_id")) c->tunnel_id = atoi(val);
        else if (!strcmp(key, "port")) c->port = atoi(val);
        else if (!strcmp(key, "local_port")) c->local_port = atoi(val);
        else if (!strcmp(key, "mtu")) c->mtu = atoi(val);
        else if (!strcmp(key, "keepalive")) c->keepalive = atoi(val);
        else if (!strcmp(key, "handshake_timeout")) c->handshake_timeout = atoi(val);
        else if (!strcmp(key, "peer_timeout")) c->peer_timeout = atoi(val);
        else if (!strcmp(key, "reconnect_interval")) c->reconnect_interval = atoi(val);
        else if (!strcmp(key, "buffer_size")) c->buffer_size = atoi(val);
        else if (!strcmp(key, "queue_len")) c->queue_len = atoi(val);
        else if (!strcmp(key, "peer_lock")) c->peer_lock = atoi(val);
        else if (!strcmp(key, "stats_interval")) c->stats_interval = atoi(val);
    }
    fclose(f);

    if (strcmp(c->mode, "client") && strcmp(c->mode, "server")) return -1;
    if (strcmp(c->transport, "auto") && strcmp(c->transport, "udp") && strcmp(c->transport, "tcp")) return -1;
    if (!c->remote_ip[0] || !c->local_priv[0] || !c->remote_priv[0] || !c->auth_key[0]) return -1;
    if (c->tunnel_id < 1 || c->tunnel_id > 65535) return -1;
    if (c->port < 1 || c->port > 65535) return -1;
    if (c->local_port < 0 || c->local_port > 65535) return -1;
    if (c->mtu < 576 || c->mtu > (int)MAX_PAYLOAD) c->mtu = 1280;
    if (c->keepalive < 1 || c->keepalive > 60) c->keepalive = 3;
    if (c->handshake_timeout < 2 || c->handshake_timeout > 60) c->handshake_timeout = 4;
    if (c->peer_timeout < 8 || c->peer_timeout > 300) c->peer_timeout = 20;
    if (c->reconnect_interval < 2 || c->reconnect_interval > 60) c->reconnect_interval = 5;
    if (c->buffer_size < 262144) c->buffer_size = 8388608;
    if (c->queue_len < 100) c->queue_len = 4000;
    c->peer_lock = c->peer_lock ? 1 : 0;
    if (c->stats_interval < 1 || c->stats_interval > 60) c->stats_interval = 3;
    return 0;
}

static int ipv4_matches(const config_t *c, const struct sockaddr_in *peer) {
    if (!c->peer_lock) return 1;
    struct in_addr expected;
    if (inet_pton(AF_INET, c->remote_ip, &expected) != 1) return 0;
    return expected.s_addr == peer->sin_addr.s_addr;
}

static void endpoint_to_string(const struct sockaddr_in *addr, int known, char *out, size_t out_len) {
    if (!known || !addr) {
        snprintf(out, out_len, "unknown");
        return;
    }
    char ip[INET_ADDRSTRLEN] = "unknown";
    (void)inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    snprintf(out, out_len, "%s:%u", ip, (unsigned)ntohs(addr->sin_port));
}

static int set_nonblocking(int fd, int enabled) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (enabled) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static void set_socket_buffers(int fd, int size) {
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
}

static void set_tcp_options(int fd, int buffer_size) {
    int yes = 1;
    int idle = 10, intvl = 3, count = 3;
    (void)setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(yes));
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
#ifdef TCP_KEEPIDLE
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    (void)setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
    set_socket_buffers(fd, buffer_size);
    struct timeval tv = {2, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int bind_ipv4_socket(int fd, const char *bind_ip, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (bind_ip[0] && strcmp(bind_ip, "0.0.0.0")) {
        if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) return -1;
    } else {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    return bind(fd, (struct sockaddr *)&addr, sizeof(addr));
}

static int create_udp_socket(const config_t *c) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    set_socket_buffers(fd, c->buffer_size);
#ifdef IP_MTU_DISCOVER
    int pmtu = IP_PMTUDISC_DONT;
    (void)setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu));
#endif
    int bind_port = !strcmp(c->mode, "server") ? c->port : c->local_port;
    if (bind_ipv4_socket(fd, c->bind_ip, bind_port) != 0) {
        close(fd);
        return -1;
    }
    if (set_nonblocking(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int create_tcp_listener(const config_t *c) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    set_socket_buffers(fd, c->buffer_size);
    if (bind_ipv4_socket(fd, c->bind_ip, c->port) != 0 || listen(fd, 16) != 0 || set_nonblocking(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connect_tcp_client(const config_t *c, const struct sockaddr_in *remote, struct sockaddr_in *peer_out) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    set_tcp_options(fd, c->buffer_size);
    if (bind_ipv4_socket(fd, c->bind_ip, 0) != 0) {
        close(fd);
        return -1;
    }
    if (set_nonblocking(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    int rc = connect(fd, (const struct sockaddr *)remote, sizeof(*remote));
    if (rc != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc != 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT};
        rc = poll(&pfd, 1, 3000);
        if (rc <= 0) {
            close(fd);
            return -1;
        }
        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0 || so_error != 0) {
            close(fd);
            return -1;
        }
    }
    if (set_nonblocking(fd, 0) != 0) {
        close(fd);
        return -1;
    }
    if (peer_out) *peer_out = *remote;
    return fd;
}

static int tun_alloc_named(const char *dev) {
    int fd = open(TUN_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        close(fd);
        return -1;
    }
    if (set_nonblocking(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void cleanup_iface(const char *iface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link del dev %s >/dev/null 2>&1 || true", iface);
    (void)system(cmd);
}

static int configure_tun(const config_t *c) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up mtu %d txqueuelen %d", c->iface, c->mtu, c->queue_len);
    if (system(cmd) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "ip addr replace %s/32 peer %s dev %s", c->local_priv, c->remote_priv, c->iface);
    if (system(cmd) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "sysctl -w net.ipv4.conf.%s.rp_filter=0 >/dev/null 2>&1 || true", c->iface);
    (void)system(cmd);
    return 0;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n > 0) {
            off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int tcp_send_frame(int fd, const uint8_t *packet, size_t packet_len) {
    if (fd < 0 || packet_len < HEADER_SIZE || packet_len > MAX_PACKET) return -1;
    uint8_t prefix[4];
    put_u32(prefix, (uint32_t)packet_len);
    if (send_all(fd, prefix, sizeof(prefix)) != 0) return -1;
    return send_all(fd, packet, packet_len);
}

static int udp_send_packet(int fd, const struct sockaddr_in *dst, const uint8_t *packet, size_t packet_len) {
    if (fd < 0 || !dst) return -1;
    ssize_t n = sendto(fd, packet, packet_len, MSG_NOSIGNAL,
                       (const struct sockaddr *)dst, sizeof(*dst));
    return n == (ssize_t)packet_len ? 0 : -1;
}

static const char *active_name(active_transport_t active) {
    if (active == ACTIVE_UDP) return "udp";
    if (active == ACTIVE_TCP) return "tcp";
    return "none";
}

static int transport_enabled(const config_t *c, const char *name) {
    return !strcmp(c->transport, "auto") || !strcmp(c->transport, name);
}

static void close_tcp(app_t *a) {
    if (a->tcp_fd >= 0) close(a->tcp_fd);
    a->tcp_fd = -1;
    a->tcp_rx.used = 0;
    a->tcp_peer_known = 0;
    a->tcp_authenticated = 0;
    if (a->active == ACTIVE_TCP) a->active = ACTIVE_NONE;
}

static int send_control_or_data(app_t *a, active_transport_t via, uint8_t type,
                                const uint8_t *payload, uint16_t payload_len) {
    uint8_t packet[MAX_PACKET];
    int packet_len = build_packet(packet, sizeof(packet), type, (uint32_t)a->cfg.tunnel_id,
                                  a->cookie, a->session_nonce, a->seq++, payload, payload_len);
    if (packet_len < 0) return -1;
    int rc = -1;
    if (via == ACTIVE_UDP && a->udp_peer_known) {
        rc = udp_send_packet(a->udp_fd, &a->udp_peer, packet, (size_t)packet_len);
    } else if (via == ACTIVE_TCP && a->tcp_fd >= 0) {
        rc = tcp_send_frame(a->tcp_fd, packet, (size_t)packet_len);
    }
    if (rc == 0) {
        a->tx_packets++;
        a->tx_bytes += (unsigned long long)payload_len;
        a->last_tx_ms = monotonic_ms();
    } else {
        a->drops++;
        if (via == ACTIVE_TCP) close_tcp(a);
    }
    return rc;
}

static int write_tun_packet(app_t *a, const uint8_t *payload, uint16_t payload_len) {
    if (payload_len == 0U) return 0;
    uint8_t version = payload[0] >> 4U;
    if (version != 4U && version != 6U) return -1;
    ssize_t n;
    do {
        n = write(a->tun_fd, payload, payload_len);
    } while (n < 0 && errno == EINTR);
    return n == (ssize_t)payload_len ? 0 : -1;
}

static int send_hello(app_t *a, active_transport_t via) {
    return send_control_or_data(a, via, TYPE_HELLO, NULL, 0U);
}

static int send_ack(app_t *a, active_transport_t via) {
    return send_control_or_data(a, via, TYPE_HELLO_ACK, NULL, 0U);
}

static void activate_transport(app_t *a, active_transport_t via, int64_t now) {
    if (a->active == via) {
        a->last_rx_ms = now;
        return;
    }
    if (a->active == ACTIVE_TCP && via == ACTIVE_UDP) return;
    a->active = via;
    a->last_rx_ms = now;
    if (via == ACTIVE_UDP) a->udp_handshakes++;
    if (via == ACTIVE_TCP) a->tcp_handshakes++;
    fprintf(stderr, "%s: tunnel connected using %s\n", ENGINE_NAME, active_name(via));
}

static int process_packet(app_t *a, active_transport_t via,
                          const struct sockaddr_in *sender, const uint8_t *buf, size_t len) {
    uint8_t type;
    uint64_t nonce;
    uint32_t seq;
    const uint8_t *payload;
    uint16_t payload_len;
    if (parse_packet(buf, len, (uint32_t)a->cfg.tunnel_id, a->cookie,
                     &type, &nonce, &seq, &payload, &payload_len) != 0) {
        a->drops++;
        return -1;
    }
    (void)seq;
    if (sender && !ipv4_matches(&a->cfg, sender)) {
        a->drops++;
        return -1;
    }
    int64_t now = monotonic_ms();

    if (!strcmp(a->cfg.mode, "server")) {
        if (type == TYPE_HELLO) {
            if (via == ACTIVE_UDP) {
                if (a->active == ACTIVE_TCP) return 0;
                if (sender) {
                    a->udp_peer = *sender;
                    a->udp_peer_known = 1;
                }
            } else if (via == ACTIVE_TCP) {
                /* TCP fallback is allowed to replace a half-open UDP session. */
                a->tcp_authenticated = 1;
            }
            a->session_nonce = nonce;
            activate_transport(a, via, now);
            return send_ack(a, via);
        }
        if (nonce != a->session_nonce || a->active != via) {
            a->drops++;
            return -1;
        }
    } else {
        if (nonce != a->session_nonce) {
            a->drops++;
            return -1;
        }
        if (type == TYPE_HELLO_ACK) {
            if (via == ACTIVE_TCP) a->tcp_authenticated = 1;
            activate_transport(a, via, now);
            return 0;
        }
        if (a->active != via) {
            a->drops++;
            return -1;
        }
    }

    a->last_rx_ms = now;
    a->rx_packets++;
    a->rx_bytes += payload_len;

    if (type == TYPE_DATA) {
        if (write_tun_packet(a, payload, payload_len) != 0) {
            a->drops++;
            return -1;
        }
    } else if (type == TYPE_PING) {
        return send_control_or_data(a, via, TYPE_PONG, NULL, 0U);
    }
    return 0;
}

static int tcp_read_and_process(app_t *a) {
    uint8_t chunk[16384];
    for (;;) {
        ssize_t n = recv(a->tcp_fd, chunk, sizeof(chunk), MSG_DONTWAIT);
        if (n > 0) {
            if (a->tcp_rx.used + (size_t)n > sizeof(a->tcp_rx.data)) return -1;
            memcpy(a->tcp_rx.data + a->tcp_rx.used, chunk, (size_t)n);
            a->tcp_rx.used += (size_t)n;
            continue;
        }
        if (n == 0) return -1;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }

    size_t offset = 0;
    while (a->tcp_rx.used - offset >= 4U) {
        uint32_t frame_len = get_u32(a->tcp_rx.data + offset);
        if (frame_len < HEADER_SIZE || frame_len > MAX_PACKET) return -1;
        if (a->tcp_rx.used - offset < 4U + frame_len) break;
        if (process_packet(a, ACTIVE_TCP, a->tcp_peer_known ? &a->tcp_peer : NULL,
                           a->tcp_rx.data + offset + 4U, frame_len) != 0) {
            /* malformed frames are dropped; valid control errors do not tear down the stream */
        }
        offset += 4U + frame_len;
    }
    if (offset > 0U) {
        memmove(a->tcp_rx.data, a->tcp_rx.data + offset, a->tcp_rx.used - offset);
        a->tcp_rx.used -= offset;
    }
    return 0;
}

static void accept_tcp_client(app_t *a) {
    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept4(a->tcp_listen_fd, (struct sockaddr *)&peer, &plen, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            return;
        }
        if (!ipv4_matches(&a->cfg, &peer)) {
            close(fd);
            continue;
        }
        close_tcp(a);
        set_tcp_options(fd, a->cfg.buffer_size);
        a->tcp_fd = fd;
        a->tcp_peer = peer;
        a->tcp_peer_known = 1;
        a->tcp_connected_ms = monotonic_ms();
        a->tcp_rx.used = 0;
        fprintf(stderr, "%s: accepted TCP fallback connection\n", ENGINE_NAME);
        return;
    }
}

static void receive_udp(app_t *a) {
    uint8_t packet[MAX_PACKET];
    for (;;) {
        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);
        ssize_t n = recvfrom(a->udp_fd, packet, sizeof(packet), 0,
                             (struct sockaddr *)&sender, &slen);
        if (n > 0) {
            if (!strcmp(a->cfg.mode, "client")) {
                if (!ipv4_matches(&a->cfg, &sender)) {
                    a->drops++;
                    continue;
                }
                a->udp_peer = sender;
                a->udp_peer_known = 1;
            }
            (void)process_packet(a, ACTIVE_UDP, &sender, packet, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0) a->drops++;
        break;
    }
}

static int connect_tcp_fallback(app_t *a) {
    struct sockaddr_in peer;
    int fd = connect_tcp_client(&a->cfg, &a->configured_remote, &peer);
    a->last_tcp_attempt_ms = monotonic_ms();
    if (fd < 0) return -1;
    close_tcp(a);
    a->tcp_fd = fd;
    a->tcp_peer = peer;
    a->tcp_peer_known = 1;
    a->tcp_connected_ms = monotonic_ms();
    a->tcp_rx.used = 0;
    a->fallback_count++;
    fprintf(stderr, "%s: UDP handshake unavailable; trying TCP fallback\n", ENGINE_NAME);
    if (send_hello(a, ACTIVE_TCP) != 0) {
        close_tcp(a);
        return -1;
    }
    return 0;
}

static void reset_client_session(app_t *a) {
    close_tcp(a);
    a->active = ACTIVE_NONE;
    a->session_nonce = random_u64();
    a->last_rx_ms = monotonic_ms();
    a->last_hello_udp_ms = 0;
    a->started_ms = monotonic_ms();
    a->reconnects++;
    a->udp_peer = a->configured_remote;
    a->udp_peer_known = 1;
}

static void write_stats(const app_t *a) {
    char path[192], tmp[208], peer[96];
    snprintf(path, sizeof(path), "/run/vira7-%s.stats", a->cfg.iface);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (a->active == ACTIVE_UDP) endpoint_to_string(&a->udp_peer, a->udp_peer_known, peer, sizeof(peer));
    else if (a->active == ACTIVE_TCP) endpoint_to_string(&a->tcp_peer, a->tcp_peer_known, peer, sizeof(peer));
    else snprintf(peer, sizeof(peer), "unknown");
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "engine=%s\n", ENGINE_VERSION);
    fprintf(f, "mode=%s\n", a->cfg.mode);
    fprintf(f, "transport_mode=%s\n", a->cfg.transport);
    fprintf(f, "active_transport=%s\n", active_name(a->active));
    fprintf(f, "connected=%d\n", a->active != ACTIVE_NONE ? 1 : 0);
    fprintf(f, "peer=%s\n", peer);
    fprintf(f, "last_rx_epoch=%lld\n", (long long)time(NULL) - (long long)((monotonic_ms() - a->last_rx_ms) / 1000LL));
    fprintf(f, "tx_packets=%llu\n", a->tx_packets);
    fprintf(f, "rx_packets=%llu\n", a->rx_packets);
    fprintf(f, "tx_bytes=%llu\n", a->tx_bytes);
    fprintf(f, "rx_bytes=%llu\n", a->rx_bytes);
    fprintf(f, "drops=%llu\n", a->drops);
    fprintf(f, "reconnects=%llu\n", a->reconnects);
    fprintf(f, "fallback_count=%llu\n", a->fallback_count);
    fprintf(f, "udp_handshakes=%llu\n", a->udp_handshakes);
    fprintf(f, "tcp_handshakes=%llu\n", a->tcp_handshakes);
    fclose(f);
    (void)rename(tmp, path);
}

static int initialize_app(app_t *a, const config_t *cfg) {
    memset(a, 0, sizeof(*a));
    a->cfg = *cfg;
    a->tun_fd = -1;
    a->udp_fd = -1;
    a->tcp_listen_fd = -1;
    a->tcp_fd = -1;
    a->cookie = fnv1a64(cfg->auth_key) ^ ((uint64_t)(uint32_t)cfg->tunnel_id << 32);
    a->session_nonce = random_u64();
    a->seq = (uint32_t)random_u64();
    a->started_ms = monotonic_ms();
    a->last_rx_ms = a->started_ms;
    a->last_tx_ms = a->started_ms;
    a->last_hello_udp_ms = 0;
    a->last_tcp_attempt_ms = 0;
    a->last_stats_ms = 0;

    memset(&a->configured_remote, 0, sizeof(a->configured_remote));
    a->configured_remote.sin_family = AF_INET;
    a->configured_remote.sin_port = htons((uint16_t)cfg->port);
    if (inet_pton(AF_INET, cfg->remote_ip, &a->configured_remote.sin_addr) != 1) return -1;
    a->udp_peer = a->configured_remote;
    a->udp_peer_known = !strcmp(cfg->mode, "client") ? 1 : 0;
    return 0;
}

static int recv_exact_test(int fd, uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int self_test(void) {
    const char *key = "self-test-key";
    uint64_t cookie = fnv1a64(key) ^ (42ULL << 32);
    uint8_t packet[MAX_PACKET];
    uint8_t payload_in[5] = {0x45, 1, 2, 3, 4};
    int n = build_packet(packet, sizeof(packet), TYPE_DATA, 42U, cookie, 123456789ULL,
                         77U, payload_in, sizeof(payload_in));
    if (n <= 0) return 1;
    uint8_t type;
    uint64_t nonce;
    uint32_t seq;
    const uint8_t *payload;
    uint16_t payload_len;
    if (parse_packet(packet, (size_t)n, 42U, cookie, &type, &nonce, &seq,
                     &payload, &payload_len) != 0) return 1;
    if (type != TYPE_DATA || nonce != 123456789ULL || seq != 77U ||
        payload_len != sizeof(payload_in) || memcmp(payload, payload_in, sizeof(payload_in)) != 0) return 1;
    packet[n - 1] ^= 0x01U;
    if (parse_packet(packet, (size_t)n, 42U, cookie, &type, &nonce, &seq,
                     &payload, &payload_len) == 0) return 1;
    packet[n - 1] ^= 0x01U;

    /* UDP loopback handshake test. */
    int ua = socket(AF_INET, SOCK_DGRAM, 0);
    int ub = socket(AF_INET, SOCK_DGRAM, 0);
    if (ua < 0 || ub < 0) return 1;
    struct sockaddr_in aa, ab, sender;
    socklen_t alen = sizeof(ab), slen = sizeof(sender);
    memset(&aa, 0, sizeof(aa));
    aa.sin_family = AF_INET; aa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    memset(&ab, 0, sizeof(ab));
    ab.sin_family = AF_INET; ab.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ua, (struct sockaddr *)&aa, sizeof(aa)) != 0 ||
        bind(ub, (struct sockaddr *)&ab, sizeof(ab)) != 0 ||
        getsockname(ub, (struct sockaddr *)&ab, &alen) != 0) return 1;
    int hello_len = build_packet(packet, sizeof(packet), TYPE_HELLO, 42U, cookie, 999ULL, 1U, NULL, 0U);
    if (hello_len < 0 || udp_send_packet(ua, &ab, packet, (size_t)hello_len) != 0) return 1;
    uint8_t recvbuf[MAX_PACKET];
    ssize_t rn = recvfrom(ub, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&sender, &slen);
    if (rn <= 0 || parse_packet(recvbuf, (size_t)rn, 42U, cookie, &type, &nonce, &seq,
                                &payload, &payload_len) != 0 || type != TYPE_HELLO || nonce != 999ULL) return 1;
    int ack_len = build_packet(packet, sizeof(packet), TYPE_HELLO_ACK, 42U, cookie, 999ULL, 2U, NULL, 0U);
    if (ack_len < 0 || udp_send_packet(ub, &sender, packet, (size_t)ack_len) != 0) return 1;
    rn = recv(ua, recvbuf, sizeof(recvbuf), 0);
    if (rn <= 0 || parse_packet(recvbuf, (size_t)rn, 42U, cookie, &type, &nonce, &seq,
                                &payload, &payload_len) != 0 || type != TYPE_HELLO_ACK) return 1;
    close(ua); close(ub);

    /* TCP framing test. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 1;
    if (tcp_send_frame(sv[0], packet, (size_t)ack_len) != 0) return 1;
    uint8_t prefix[4];
    if (recv_exact_test(sv[1], prefix, sizeof(prefix)) != 0) return 1;
    uint32_t framed_len = get_u32(prefix);
    if (framed_len != (uint32_t)ack_len || recv_exact_test(sv[1], recvbuf, framed_len) != 0) return 1;
    if (parse_packet(recvbuf, framed_len, 42U, cookie, &type, &nonce, &seq,
                     &payload, &payload_len) != 0 || type != TYPE_HELLO_ACK) return 1;
    close(sv[0]); close(sv[1]);

    /* A valid TCP fallback must replace a half-open server UDP session. */
    app_t a;
    memset(&a, 0, sizeof(a));
    snprintf(a.cfg.mode, sizeof(a.cfg.mode), "server");
    a.active = ACTIVE_UDP;
    activate_transport(&a, ACTIVE_TCP, monotonic_ms());
    if (a.active != ACTIVE_TCP) return 1;

    fprintf(stdout, "%s %s self-test: OK\n", ENGINE_NAME, ENGINE_VERSION);
    return 0;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <config> | --check-config <config> | --self-test | --version\n", argv0);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--self-test")) return self_test();
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        printf("%s %s\n", ENGINE_NAME, ENGINE_VERSION);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--check-config")) {
        config_t cfg;
        if (load_config(argv[2], &cfg) != 0) {
            fprintf(stderr, "invalid config: %s\n", argv[2]);
            return 1;
        }
        printf("config OK: mode=%s transport=%s port=%d iface=%s\n",
               cfg.mode, cfg.transport, cfg.port, cfg.iface);
        return 0;
    }
    if (argc != 2 || getuid() != 0) {
        usage(argv[0]);
        return 1;
    }

    config_t cfg;
    if (load_config(argv[1], &cfg) != 0) {
        fprintf(stderr, "%s: failed to load config %s\n", ENGINE_NAME, argv[1]);
        return 1;
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    (void)mkdir("/dev/net", 0755);
    if (access(TUN_DEVICE, F_OK) != 0) (void)system("mknod /dev/net/tun c 10 200 >/dev/null 2>&1 || true");
    (void)system("modprobe tun >/dev/null 2>&1 || true");
    cleanup_iface(cfg.iface);

    app_t app;
    if (initialize_app(&app, &cfg) != 0) {
        fprintf(stderr, "%s: invalid remote IPv4 %s\n", ENGINE_NAME, cfg.remote_ip);
        return 1;
    }

    app.tun_fd = tun_alloc_named(cfg.iface);
    if (app.tun_fd < 0) {
        perror("open TUN");
        return 1;
    }
    if (configure_tun(&cfg) != 0) {
        fprintf(stderr, "%s: failed to configure TUN interface %s\n", ENGINE_NAME, cfg.iface);
        close(app.tun_fd);
        cleanup_iface(cfg.iface);
        return 1;
    }

    if (transport_enabled(&cfg, "udp")) {
        app.udp_fd = create_udp_socket(&cfg);
        if (app.udp_fd < 0 && !strcmp(cfg.transport, "udp")) {
            perror("create UDP socket");
            close(app.tun_fd);
            cleanup_iface(cfg.iface);
            return 1;
        }
        if (app.udp_fd < 0) fprintf(stderr, "%s: UDP unavailable; TCP fallback remains enabled\n", ENGINE_NAME);
    }

    if (!strcmp(cfg.mode, "server") && transport_enabled(&cfg, "tcp")) {
        app.tcp_listen_fd = create_tcp_listener(&cfg);
        if (app.tcp_listen_fd < 0 && !strcmp(cfg.transport, "tcp")) {
            perror("create TCP listener");
            if (app.udp_fd >= 0) close(app.udp_fd);
            close(app.tun_fd);
            cleanup_iface(cfg.iface);
            return 1;
        }
        if (app.tcp_listen_fd < 0) fprintf(stderr, "%s: TCP fallback listener unavailable; UDP remains enabled\n", ENGINE_NAME);
    }

    if (app.udp_fd < 0 && app.tcp_listen_fd < 0 && !strcmp(cfg.mode, "server")) {
        fprintf(stderr, "%s: no transport could be started\n", ENGINE_NAME);
        close(app.tun_fd);
        cleanup_iface(cfg.iface);
        return 1;
    }

    char pidfile[160];
    snprintf(pidfile, sizeof(pidfile), "/run/%s.pid", cfg.iface);
    FILE *pf = fopen(pidfile, "w");
    if (pf) {
        fprintf(pf, "%d\n", getpid());
        fclose(pf);
    }

    fprintf(stderr, "%s %s started: iface=%s mode=%s transport=%s bind=%s port=%d remote=%s mtu=%d\n",
            ENGINE_NAME, ENGINE_VERSION, cfg.iface, cfg.mode, cfg.transport,
            cfg.bind_ip, cfg.port, cfg.remote_ip, cfg.mtu);
    if (!strcmp(cfg.mode, "client")) {
        fprintf(stderr, "%s: client uses ephemeral source ports; UDP is preferred and TCP is automatic fallback\n", ENGINE_NAME);
    }

    uint8_t tun_buf[MAX_PAYLOAD];
    while (g_running) {
        struct pollfd pfds[4];
        int nfds = 0;
        int tun_idx = -1, udp_idx = -1, listen_idx = -1, tcp_idx = -1;
        tun_idx = nfds;
        pfds[nfds++] = (struct pollfd){.fd = app.tun_fd, .events = POLLIN};
        if (app.udp_fd >= 0) {
            udp_idx = nfds;
            pfds[nfds++] = (struct pollfd){.fd = app.udp_fd, .events = POLLIN};
        }
        if (app.tcp_listen_fd >= 0) {
            listen_idx = nfds;
            pfds[nfds++] = (struct pollfd){.fd = app.tcp_listen_fd, .events = POLLIN};
        }
        if (app.tcp_fd >= 0) {
            tcp_idx = nfds;
            pfds[nfds++] = (struct pollfd){.fd = app.tcp_fd, .events = POLLIN | POLLERR | POLLHUP};
        }

        int rc = poll(pfds, (nfds_t)nfds, 250);
        if (rc < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }
        int64_t now = monotonic_ms();

        if (listen_idx >= 0 && (pfds[listen_idx].revents & POLLIN)) accept_tcp_client(&app);
        if (udp_idx >= 0 && (pfds[udp_idx].revents & POLLIN)) receive_udp(&app);
        if (tcp_idx >= 0 && pfds[tcp_idx].revents) {
            if (pfds[tcp_idx].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                close_tcp(&app);
            } else if ((pfds[tcp_idx].revents & POLLIN) && tcp_read_and_process(&app) != 0) {
                close_tcp(&app);
            }
        }

        if (tun_idx >= 0 && (pfds[tun_idx].revents & POLLIN)) {
            for (int i = 0; i < 128; i++) {
                ssize_t n = read(app.tun_fd, tun_buf, sizeof(tun_buf));
                if (n > 0) {
                    if (app.active == ACTIVE_NONE || send_control_or_data(&app, app.active, TYPE_DATA,
                                                                          tun_buf, (uint16_t)n) != 0) {
                        app.drops++;
                    }
                    continue;
                }
                if (n < 0 && errno == EINTR) continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                break;
            }
        }

        now = monotonic_ms();
        if (!strcmp(cfg.mode, "client") && app.active == ACTIVE_NONE) {
            if (app.udp_fd >= 0 && transport_enabled(&cfg, "udp") &&
                now - app.last_hello_udp_ms >= 1000LL) {
                (void)send_hello(&app, ACTIVE_UDP);
                app.last_hello_udp_ms = now;
            }
            int may_try_tcp = transport_enabled(&cfg, "tcp") && app.tcp_fd < 0;
            if (!strcmp(cfg.transport, "auto") && now - app.started_ms < (int64_t)cfg.handshake_timeout * 1000LL) {
                may_try_tcp = 0;
            }
            if (may_try_tcp && now - app.last_tcp_attempt_ms >= (int64_t)cfg.reconnect_interval * 1000LL) {
                (void)connect_tcp_fallback(&app);
            }
        }

        if (app.active != ACTIVE_NONE && now - app.last_tx_ms >= (int64_t)cfg.keepalive * 1000LL) {
            (void)send_control_or_data(&app, app.active, TYPE_PING, NULL, 0U);
        }

        if (app.active != ACTIVE_NONE && now - app.last_rx_ms >= (int64_t)cfg.peer_timeout * 1000LL) {
            fprintf(stderr, "%s: peer timeout on %s; reconnecting\n", ENGINE_NAME, active_name(app.active));
            if (!strcmp(cfg.mode, "client")) {
                reset_client_session(&app);
            } else {
                close_tcp(&app);
                app.active = ACTIVE_NONE;
                app.udp_peer_known = 0;
                app.session_nonce = 0;
                app.reconnects++;
                app.last_rx_ms = now;
            }
        }

        if (app.tcp_fd >= 0 && !app.tcp_authenticated &&
            now - app.tcp_connected_ms >= (int64_t)cfg.handshake_timeout * 1000LL) {
            close_tcp(&app);
            if (!strcmp(cfg.mode, "client")) app.last_tcp_attempt_ms = now;
        }

        if (now - app.last_stats_ms >= (int64_t)cfg.stats_interval * 1000LL) {
            write_stats(&app);
            app.last_stats_ms = now;
        }
    }

    write_stats(&app);
    close_tcp(&app);
    if (app.tcp_listen_fd >= 0) close(app.tcp_listen_fd);
    if (app.udp_fd >= 0) close(app.udp_fd);
    if (app.tun_fd >= 0) close(app.tun_fd);
    unlink(pidfile);
    cleanup_iface(cfg.iface);
    fprintf(stderr, "%s stopped\n", ENGINE_NAME);
    return 0;
}
ENGINEEOF

  if gcc -std=c11 -O3 -flto -Wall -Wextra -Werror -o "$VIRA7_BINARY.tmp" "$VIRA7_SOURCE"; then
    :
  elif gcc -std=c11 -O3 -Wall -Wextra -o "$VIRA7_BINARY.tmp" "$VIRA7_SOURCE"; then
    warn_msg "Vira7 engine compiled without LTO/Werror fallback."
  else
    rm -f "$VIRA7_BINARY.tmp"
    return 1
  fi
  if ! "$VIRA7_BINARY.tmp" --self-test >/dev/null 2>&1; then
    rm -f "$VIRA7_BINARY.tmp"
    err_msg "Vira Hybrid engine self-test failed."
    return 1
  fi
  install -m 755 "$VIRA7_BINARY.tmp" "$VIRA7_BINARY"
  rm -f "$VIRA7_BINARY.tmp"
}

vira7_write_service_template() {
  cat > "$VIRA7_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=Vira Hybrid Auto UDP/TCP Tunnel %i
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=/sbin/modprobe tun
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-vira7 %i
ExecStart=$VIRA7_BINARY $VIRA7_CONFIG_DIR/tunnel-%i.conf
Restart=always
RestartSec=2
TimeoutStopSec=8
KillSignal=SIGTERM
LimitNOFILE=131072
Nice=-5

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  systemctl daemon-reload
}

vira7_save_config() {
  mkdir -p "$VIRA7_CONFIG_DIR"
  local file tmp backup
  file="$(vira7_config_file "$TUNNEL_ID")"
  tmp="${file}.tmp.$$"
  backup="${file}.last-good"
  [ -f "$file" ] && cp -f "$file" "$backup"

  {
    write_var TUNNEL_TYPE "vira7"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var VIRA7_CONFIG_VERSION "3"
    write_var VIRA7_IFACE "$VIRA7_IFACE"
    write_var ROLE "$ROLE"
    write_var SERVER_ROLE "$SERVER_ROLE"
    write_var VIRA7_DIRECTION "$VIRA7_DIRECTION"
    write_var VIRA7_MODE "$VIRA7_MODE"
    write_var VIRA7_TRANSPORT "$VIRA7_TRANSPORT"
    write_var VIRA7_AUTH_KEY "$VIRA7_AUTH_KEY"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_VIRA7_IP "$LOCAL_VIRA7_IP"
    write_var REMOTE_VIRA7_IP "$REMOTE_VIRA7_IP"
    write_var VIRA7_PORT "$VIRA7_PORT"
    write_var VIRA7_LOCAL_PORT "$VIRA7_LOCAL_PORT"
    write_var VIRA7_MTU "$VIRA7_MTU"
    write_var VIRA7_KEEPALIVE "$VIRA7_KEEPALIVE"
    write_var VIRA7_HANDSHAKE_TIMEOUT "$VIRA7_HANDSHAKE_TIMEOUT"
    write_var VIRA7_PEER_TIMEOUT "$VIRA7_PEER_TIMEOUT"
    write_var VIRA7_RECONNECT_INTERVAL "$VIRA7_RECONNECT_INTERVAL"
    write_var VIRA7_BUFFER_SIZE "$VIRA7_BUFFER_SIZE"
    write_var VIRA7_QUEUE_LEN "$VIRA7_QUEUE_LEN"
    write_var VIRA7_PEER_LOCK "$VIRA7_PEER_LOCK"
    echo
    printf 'iface=%s\n' "$VIRA7_IFACE"
    printf 'mode=%s\n' "$VIRA7_MODE"
    printf 'transport=%s\n' "$VIRA7_TRANSPORT"
    printf 'bind_ip=%s\n' "$LOCAL_PUBLIC_IP"
    printf 'remote_ip=%s\n' "$REMOTE_PUBLIC_IP"
    printf 'local_priv=%s\n' "$LOCAL_VIRA7_IP"
    printf 'remote_priv=%s\n' "$REMOTE_VIRA7_IP"
    printf 'auth_key=%s\n' "$VIRA7_AUTH_KEY"
    printf 'tunnel_id=%s\n' "$TUNNEL_ID"
    printf 'port=%s\n' "$VIRA7_PORT"
    printf 'local_port=%s\n' "$VIRA7_LOCAL_PORT"
    printf 'mtu=%s\n' "$VIRA7_MTU"
    printf 'keepalive=%s\n' "$VIRA7_KEEPALIVE"
    printf 'handshake_timeout=%s\n' "$VIRA7_HANDSHAKE_TIMEOUT"
    printf 'peer_timeout=%s\n' "$VIRA7_PEER_TIMEOUT"
    printf 'reconnect_interval=%s\n' "$VIRA7_RECONNECT_INTERVAL"
    printf 'buffer_size=%s\n' "$VIRA7_BUFFER_SIZE"
    printf 'queue_len=%s\n' "$VIRA7_QUEUE_LEN"
    printf 'peer_lock=%s\n' "$VIRA7_PEER_LOCK"
    printf 'stats_interval=3\n'
  } > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
  echo "Saved Vira Hybrid tunnel $TUNNEL_ID configuration to $file"
}

vira7_load_config() {
  local id="${1:-${TUNNEL_ID:-}}"
  validate_tunnel_id "$id" || return 1
  local file
  file="$(vira7_config_file "$id")"
  [ -f "$file" ] || return 1

  unset TUNNEL_TYPE TUNNEL_ID VIRA7_CONFIG_VERSION VIRA7_IFACE ROLE SERVER_ROLE VIRA7_DIRECTION VIRA7_MODE
  unset VIRA7_TRANSPORT VIRA7_AUTH_KEY VIRA7_LOCAL_PORT VIRA7_HANDSHAKE_TIMEOUT VIRA7_RECONNECT_INTERVAL
  unset LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP LOCAL_VIRA7_IP REMOTE_VIRA7_IP VIRA7_PORT VIRA7_MTU
  unset VIRA7_KEEPALIVE VIRA7_BUFFER_SIZE VIRA7_QUEUE_LEN VIRA7_PEER_LOCK VIRA7_PEER_TIMEOUT
  unset iface mode transport bind_ip remote_ip local_priv remote_priv auth_key tunnel_id port local_port mtu
  unset keepalive handshake_timeout peer_timeout reconnect_interval buffer_size queue_len peer_lock stats_interval

  # shellcheck disable=SC1090
  source "$file"
  TUNNEL_ID="$id"
  VIRA7_CONFIG_VERSION="${VIRA7_CONFIG_VERSION:-1}"
  VIRA7_IFACE="${VIRA7_IFACE:-${iface:-$(vira7_iface_name "$id")}}"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
  REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
  LOCAL_VIRA7_IP="${LOCAL_VIRA7_IP:-${local_priv:-}}"
  REMOTE_VIRA7_IP="${REMOTE_VIRA7_IP:-${remote_priv:-}}"
  VIRA7_PORT="${VIRA7_PORT:-${port:-$(vira7_default_port "$id")}}"
  VIRA7_LOCAL_PORT="${VIRA7_LOCAL_PORT:-${local_port:-$VIRA7_DEFAULT_LOCAL_PORT}}"
  VIRA7_MTU="${VIRA7_MTU:-${mtu:-$VIRA7_DEFAULT_MTU}}"
  VIRA7_KEEPALIVE="${VIRA7_KEEPALIVE:-${keepalive:-$VIRA7_DEFAULT_KEEPALIVE}}"
  VIRA7_TRANSPORT="${VIRA7_TRANSPORT:-${transport:-$VIRA7_DEFAULT_TRANSPORT}}"
  VIRA7_AUTH_KEY="${VIRA7_AUTH_KEY:-${auth_key:-$(vira7_default_auth_key "$id" "$VIRA7_PORT")}}"
  VIRA7_HANDSHAKE_TIMEOUT="${VIRA7_HANDSHAKE_TIMEOUT:-${handshake_timeout:-$VIRA7_DEFAULT_HANDSHAKE_TIMEOUT}}"
  VIRA7_PEER_TIMEOUT="${VIRA7_PEER_TIMEOUT:-${peer_timeout:-$VIRA7_DEFAULT_PEER_TIMEOUT}}"
  VIRA7_RECONNECT_INTERVAL="${VIRA7_RECONNECT_INTERVAL:-${reconnect_interval:-$VIRA7_DEFAULT_RECONNECT_INTERVAL}}"
  VIRA7_BUFFER_SIZE="${VIRA7_BUFFER_SIZE:-${buffer_size:-$VIRA7_DEFAULT_BUFFER_SIZE}}"
  VIRA7_QUEUE_LEN="${VIRA7_QUEUE_LEN:-${queue_len:-$VIRA7_DEFAULT_QUEUE_LEN}}"
  VIRA7_PEER_LOCK="${VIRA7_PEER_LOCK:-${peer_lock:-$VIRA7_DEFAULT_PEER_LOCK}}"

  if [ -z "${ROLE:-}" ]; then
    if [ "${LOCAL_VIRA7_IP:-}" = "10.71.$id.1" ]; then ROLE="1"; else ROLE="2"; fi
  fi
  VIRA7_MODE="${VIRA7_MODE:-${mode:-$(vira7_mode_for_role "$ROLE" recommended)}}"
  VIRA7_DIRECTION="${VIRA7_DIRECTION:-$(vira7_infer_direction "$ROLE" "$VIRA7_MODE")}"
  SERVER_ROLE="${SERVER_ROLE:-$([ "$ROLE" = "1" ] && echo IRAN || echo KHAREJ)}"
}

vira7_validate_port_for_tunnel() {
  local port="$1" id="$2" existing_port="${3:-}" mode
  validate_port "$port" || { err_msg "Invalid port: $port"; return 1; }
  if udp_port_in_saved_configs "$port" "vira7" "$id"; then
    err_msg "Port $port is already assigned to another saved Vira tunnel."
    return 1
  fi
  mode="$(vira7_mode_for_role "$ROLE" "${VIRA7_DIRECTION:-recommended}")"
  # Client uses an ephemeral local UDP/TCP source port, so local listeners do not conflict.
  [ "$mode" = "client" ] && return 0

  local own_service=0
  if [ "$existing_port" = "$port" ] && systemctl is-active --quiet "$(vira7_service_name "$id")" 2>/dev/null; then
    own_service=1
  fi
  if udp_port_is_listening "$port" && [ "$own_service" -ne 1 ]; then
    err_msg "UDP port $port is already listening on this server."
    ss -H -lunp 2>/dev/null | grep -E "(^|[:.])${port}([[:space:]]|$)" || true
    return 1
  fi
  if ss -H -ltn 2>/dev/null | grep -Eq "(^|[:.])${port}([[:space:]]|$)"; then
    if [ "$own_service" -eq 1 ] && ss -H -ltnp 2>/dev/null | grep -E "(^|[:.])${port}([[:space:]]|$)" | grep -q 'vira7-engine'; then
      info_msg "TCP port $port is currently owned by this Vira service and will be reused."
    else
      err_msg "TCP port $port is already listening on this server. Auto fallback needs this TCP port too."
      ss -H -ltnp 2>/dev/null | grep -E "(^|[:.])${port}([[:space:]]|$)" || true
      return 1
    fi
  fi
}

vira7_apply_firewall_rules() {
  local id="$1"
  if ! vira7_load_config "$id"; then return 1; fi
  vira7_tune_kernel "$id"

  # Insert rules at the top so an earlier DROP rule cannot shadow them.
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport "$VIRA7_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$VIRA7_PORT" -j ACCEPT || true
    iptables -C INPUT -p tcp --dport "$VIRA7_PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$VIRA7_PORT" -j ACCEPT || true
    iptables -C OUTPUT -p udp -d "$REMOTE_PUBLIC_IP" --dport "$VIRA7_PORT" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p udp -d "$REMOTE_PUBLIC_IP" --dport "$VIRA7_PORT" -j ACCEPT || true
    iptables -C OUTPUT -p tcp -d "$REMOTE_PUBLIC_IP" --dport "$VIRA7_PORT" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p tcp -d "$REMOTE_PUBLIC_IP" --dport "$VIRA7_PORT" -j ACCEPT || true
    iptables -C INPUT -i "$VIRA7_IFACE" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$VIRA7_IFACE" -j ACCEPT || true
    iptables -C OUTPUT -o "$VIRA7_IFACE" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o "$VIRA7_IFACE" -j ACCEPT || true
    iptables -C FORWARD -i "$VIRA7_IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$VIRA7_IFACE" -j ACCEPT || true
    iptables -C FORWARD -o "$VIRA7_IFACE" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$VIRA7_IFACE" -j ACCEPT || true
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$VIRA7_PORT/udp" comment "vira7-$id-udp" >/dev/null 2>&1 || true
    ufw allow "$VIRA7_PORT/tcp" comment "vira7-$id-tcp" >/dev/null 2>&1 || true
    ufw allow in on "$VIRA7_IFACE" >/dev/null 2>&1 || true
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$VIRA7_PORT/udp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="$VIRA7_PORT/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-interface="$VIRA7_IFACE" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
  firewall_allow_ip_peer "Vira Hybrid tunnel $id remote inner" "$REMOTE_VIRA7_IP" "$VIRA7_IFACE" >/dev/null 2>&1 || true
  echo "Firewall opened for Vira Hybrid $id: UDP/TCP $VIRA7_PORT, peer $REMOTE_PUBLIC_IP"
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
  systemctl enable "$(vira7_service_name "$id")" >/dev/null || return 1
  if systemctl restart "$(vira7_service_name "$id")"; then
    sleep 1
    if systemctl is-active --quiet "$(vira7_service_name "$id")" && ip link show "$(vira7_iface_name "$id")" >/dev/null 2>&1; then
      ok_msg "Vira Hybrid service enabled and started ($(vira7_service_name "$id"))"
      return 0
    fi
  fi
  systemctl status "$(vira7_service_name "$id")" --no-pager -l 2>/dev/null || true
  journalctl -u "$(vira7_service_name "$id")" -n 50 --no-pager 2>/dev/null || true
  return 1
}

vira7_create_tunnel() {
  local interactive="${1:-0}"
  local file backup
  : "$interactive"
  validate_tunnel_id "${TUNNEL_ID:-}" || { echo "Invalid tunnel number." >&2; return 1; }
  VIRA7_IFACE="$(vira7_iface_name "$TUNNEL_ID")"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  [ -n "${LOCAL_PUBLIC_IP:-}" ] || { echo "Failed to detect local bind IPv4" >&2; return 1; }
  if [ "$LOCAL_PUBLIC_IP" != "0.0.0.0" ] && ! local_ipv4_is_assigned "$LOCAL_PUBLIC_IP"; then
    echo "Selected Vira bind IP is not assigned on this server: $LOCAL_PUBLIC_IP" >&2
    list_local_ipv4s >&2
    return 1
  fi

  SERVER_ROLE="$([ "$ROLE" = "1" ] && echo IRAN || echo KHAREJ)"
  VIRA7_DIRECTION="${VIRA7_DIRECTION:-recommended}"
  VIRA7_MODE="$(vira7_mode_for_role "$ROLE" "$VIRA7_DIRECTION")"
  LOCAL_VIRA7_IP="$(vira7_inner_ip_for_role "$TUNNEL_ID" "$ROLE")"
  REMOTE_VIRA7_IP="$(vira7_remote_inner_ip_for_role "$TUNNEL_ID" "$ROLE")"
  VIRA7_PORT="${VIRA7_PORT:-$(vira7_default_port "$TUNNEL_ID")}" 
  VIRA7_LOCAL_PORT="${VIRA7_LOCAL_PORT:-$VIRA7_DEFAULT_LOCAL_PORT}"
  VIRA7_MTU="${VIRA7_MTU:-$VIRA7_DEFAULT_MTU}"
  VIRA7_KEEPALIVE="${VIRA7_KEEPALIVE:-$VIRA7_DEFAULT_KEEPALIVE}"
  VIRA7_TRANSPORT="${VIRA7_TRANSPORT:-$VIRA7_DEFAULT_TRANSPORT}"
  VIRA7_AUTH_KEY="${VIRA7_AUTH_KEY:-$(vira7_default_auth_key "$TUNNEL_ID" "$VIRA7_PORT")}"
  VIRA7_HANDSHAKE_TIMEOUT="${VIRA7_HANDSHAKE_TIMEOUT:-$VIRA7_DEFAULT_HANDSHAKE_TIMEOUT}"
  VIRA7_PEER_TIMEOUT="${VIRA7_PEER_TIMEOUT:-$VIRA7_DEFAULT_PEER_TIMEOUT}"
  VIRA7_RECONNECT_INTERVAL="${VIRA7_RECONNECT_INTERVAL:-$VIRA7_DEFAULT_RECONNECT_INTERVAL}"
  VIRA7_BUFFER_SIZE="${VIRA7_BUFFER_SIZE:-$VIRA7_DEFAULT_BUFFER_SIZE}"
  VIRA7_QUEUE_LEN="${VIRA7_QUEUE_LEN:-$VIRA7_DEFAULT_QUEUE_LEN}"
  VIRA7_PEER_LOCK="${VIRA7_PEER_LOCK:-$VIRA7_DEFAULT_PEER_LOCK}"

  echo "[*] Vira Hybrid version: $SCRIPT_VERSION"
  echo "[*] Interface: $VIRA7_IFACE | role: $SERVER_ROLE | mode: $VIRA7_MODE"
  echo "[*] Transport: $VIRA7_TRANSPORT (UDP preferred, TCP fallback in auto mode)"
  echo "[*] Public path: $LOCAL_PUBLIC_IP -> $REMOTE_PUBLIC_IP:$VIRA7_PORT"
  echo "[*] Tunnel path: $LOCAL_VIRA7_IP -> $REMOTE_VIRA7_IP"
  echo "[*] Client source port: ephemeral | MTU: $VIRA7_MTU"

  enable_ip_forward
  vira7_tune_kernel "$TUNNEL_ID"
  modprobe tun || true
  vira7_compile_engine || return 1

  file="$(vira7_config_file "$TUNNEL_ID")"
  backup="${file}.last-good"
  vira7_save_config
  if ! "$VIRA7_BINARY" --check-config "$file"; then
    err_msg "Generated Vira config did not pass engine validation."
    [ -f "$backup" ] && cp -f "$backup" "$file"
    return 1
  fi
  vira7_apply_firewall_rules "$TUNNEL_ID" || true
  if vira7_install_service "$TUNNEL_ID"; then
    sleep 1
    local stats active
    stats="$(vira7_stats_file "$TUNNEL_ID")"
    active="$(awk -F= '$1=="active_transport"{print $2}' "$stats" 2>/dev/null || true)"
    if [ -n "$active" ] && [ "$active" != "none" ]; then
      ok_msg "Vira Hybrid tunnel connected through $active."
    else
      warn_msg "Engine is running but the peer is not connected yet. Configure/restart the other server, then use diagnostics."
    fi
    return 0
  fi

  err_msg "New Vira Hybrid service failed to start."
  if [ -f "$backup" ]; then
    warn_msg "Restoring the previous Vira config..."
    cp -f "$backup" "$file"
    systemctl restart "$(vira7_service_name "$TUNNEL_ID")" 2>/dev/null || true
  fi
  return 1
}

vira7_menu_config_tunnel() {
  show_header "Configure Vira Hybrid Auto UDP/TCP"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_port existing_mtu
  local existing_direction existing_transport existing_config_version direction_choice transport_choice
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter Vira tunnel number [1-254]: " || return

  existing_local_ip=""; existing_remote_ip=""; existing_port=""; existing_mtu=""
  existing_direction=""; existing_transport=""; existing_config_version="1"
  if vira7_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_port="${VIRA7_PORT:-}"
    existing_mtu="${VIRA7_MTU:-}"
    existing_direction="${VIRA7_DIRECTION:-}"
    existing_transport="${VIRA7_TRANSPORT:-}"
    existing_config_version="${VIRA7_CONFIG_VERSION:-1}"
  fi
  ROLE="$selected_role"
  if ! [[ "$existing_config_version" =~ ^[0-9]+$ ]] || [ "$existing_config_version" -lt 3 ]; then
    existing_mtu=""
    existing_transport=""
  fi

  echo
  echo "Vira Hybrid tunnel $TUNNEL_ID plan:"
  echo "  Interface       : $(vira7_iface_name "$TUNNEL_ID")"
  echo "  Iran tunnel IP  : 10.71.$TUNNEL_ID.1"
  echo "  Kharej tunnel IP: 10.71.$TUNNEL_ID.2"
  echo
  echo "Connection direction:"
  echo "  1) Recommended: Iran=Client -> Kharej=Server"
  echo "  2) Legacy: Iran=Server <- Kharej=Client"
  read -rp "Choose direction [1-2, default 1] (00=menu): " direction_choice
  if is_main_menu_token "$direction_choice"; then return_main_msg; return 99; fi
  case "${direction_choice:-1}" in
    1) VIRA7_DIRECTION="recommended" ;;
    2) VIRA7_DIRECTION="legacy" ;;
    *) err_msg "Invalid direction."; return 1 ;;
  esac

  echo
  echo "Transport mode:"
  echo "  1) Auto Hybrid: prefer UDP, automatically fallback to TCP (recommended)"
  echo "  2) UDP only"
  echo "  3) TCP only"
  local transport_default=1
  [ "$existing_transport" = "udp" ] && transport_default=2
  [ "$existing_transport" = "tcp" ] && transport_default=3
  read -rp "Choose transport [1-3, default $transport_default] (00=menu): " transport_choice
  if is_main_menu_token "$transport_choice"; then return_main_msg; return 99; fi
  transport_choice="${transport_choice:-$transport_default}"
  case "$transport_choice" in
    1) VIRA7_TRANSPORT="auto" ;;
    2) VIRA7_TRANSPORT="udp" ;;
    3) VIRA7_TRANSPORT="tcp" ;;
    *) err_msg "Invalid transport."; return 1 ;;
  esac

  echo
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL bind IPv4 (0.0.0.0 = all local IPv4 addresses)" || return
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return

  echo
  echo "The same numeric port is used for UDP and TCP on the Server side."
  echo "Both protocols can share one number, but no other TCP/UDP service may already own it."
  local port_default port_input
  port_default="${existing_port:-$(vira7_default_port "$TUNNEL_ID")}"
  read -rp "Enter Vira Hybrid port [$port_default] (00=menu): " port_input
  if is_main_menu_token "$port_input"; then return_main_msg; return 99; fi
  VIRA7_PORT="${port_input:-$port_default}"
  vira7_validate_port_for_tunnel "$VIRA7_PORT" "$TUNNEL_ID" "$existing_port" || return

  read -rp "Enter MTU [${existing_mtu:-$VIRA7_DEFAULT_MTU}] (00=menu): " VIRA7_MTU_INPUT
  if is_main_menu_token "$VIRA7_MTU_INPUT"; then return_main_msg; return 99; fi
  VIRA7_MTU="${VIRA7_MTU_INPUT:-${existing_mtu:-$VIRA7_DEFAULT_MTU}}"
  if ! [[ "$VIRA7_MTU" =~ ^[0-9]+$ ]] || [ "$VIRA7_MTU" -lt 576 ] || [ "$VIRA7_MTU" -gt 9000 ]; then
    err_msg "Invalid MTU. Recommended: 1280."
    return 1
  fi

  VIRA7_LOCAL_PORT="$VIRA7_DEFAULT_LOCAL_PORT"
  VIRA7_KEEPALIVE="$VIRA7_DEFAULT_KEEPALIVE"
  VIRA7_HANDSHAKE_TIMEOUT="$VIRA7_DEFAULT_HANDSHAKE_TIMEOUT"
  VIRA7_PEER_TIMEOUT="$VIRA7_DEFAULT_PEER_TIMEOUT"
  VIRA7_RECONNECT_INTERVAL="$VIRA7_DEFAULT_RECONNECT_INTERVAL"
  VIRA7_BUFFER_SIZE="$VIRA7_DEFAULT_BUFFER_SIZE"
  VIRA7_QUEUE_LEN="$VIRA7_DEFAULT_QUEUE_LEN"
  VIRA7_PEER_LOCK="$VIRA7_DEFAULT_PEER_LOCK"
  VIRA7_AUTH_KEY="$(vira7_default_auth_key "$TUNNEL_ID" "$VIRA7_PORT")"

  vira7_create_tunnel 1 || echo "Vira Hybrid tunnel creation/update failed"
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
  echo "Vira Hybrid tunnels:"
  local ids id ifc state svc_state mode direction port mtu transport active stats
  ids="$(vira7_collect_ids || true)"
  if [ -z "$ids" ]; then echo "  none"; return 0; fi
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(vira7_iface_name "$id")"
    state="inactive"; ip link show "$ifc" >/dev/null 2>&1 && state="active"
    svc_state="$(systemctl is-active "$(vira7_service_name "$id")" 2>/dev/null || true)"
    mode="?"; direction="?"; port="?"; mtu="?"; transport="?"; active="none"
    if vira7_load_config "$id"; then
      mode="$VIRA7_MODE"; direction="$VIRA7_DIRECTION"; port="$VIRA7_PORT"; mtu="$VIRA7_MTU"; transport="$VIRA7_TRANSPORT"
    fi
    stats="$(vira7_stats_file "$id")"
    [ -f "$stats" ] && active="$(awk -F= '$1=="active_transport"{print $2}' "$stats" 2>/dev/null || echo none)"
    echo "  - tunnel $id | $ifc | iface=$state service=$svc_state | $mode/$direction | mode=$transport active=$active | port=$port MTU=$mtu"
  done <<< "$ids"
}

vira7_remove_one_tunnel() {
  local id="$1"
  local ifc file port
  ifc="$(vira7_iface_name "$id")"
  file="$(vira7_config_file "$id")"
  port=""
  if vira7_load_config "$id"; then port="${VIRA7_PORT:-}"; fi
  echo "Removing Vira Hybrid tunnel $id ($ifc)..."
  systemctl disable --now "$(vira7_service_name "$id")" 2>/dev/null || true
  ip link delete "$ifc" 2>/dev/null || true
  if [ -n "$port" ] && command -v iptables >/dev/null 2>&1; then
    for proto in udp tcp; do
      while iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT || break; done
    done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
  fi
  if [ -n "$port" ] && command -v ufw >/dev/null 2>&1; then
    ufw delete allow "$port/udp" >/dev/null 2>&1 || true
    ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
  fi
  rm -f "$file" "${file}.last-good" "/run/$ifc.pid" "$(vira7_stats_file "$id")"
  systemctl daemon-reload 2>/dev/null || true
  echo "[OK] Vira Hybrid tunnel $id removed."
}

vira7_remove_menu() {
  show_header "Remove Vira Hybrid Tunnel"
  vira7_list_tunnels
  echo
  local ids selected_id
  ids="$(vira7_collect_ids || true)"
  if [ -z "$ids" ]; then echo "No Vira7 tunnels found."; return; fi
  read -rp "Enter Vira7 tunnel number to remove, or 00=menu: " selected_id
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
  [ -x "$VIRA7_BINARY" ] || vira7_compile_engine || return 1
  enable_ip_forward
  vira7_tune_kernel "$id"
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
  local id="$1" mode="${2:-auto}" file svc
  validate_tunnel_id "$id" || { echo "Invalid Vira tunnel number." >&2; return 1; }
  file="$(vira7_config_file "$id")"
  svc="$(vira7_service_name "$id")"
  [ -f "$file" ] || { echo "No Vira config found: $file" >&2; return 1; }
  case "$mode" in auto|udp|tcp) ;; *) return 1 ;; esac
  set_config_kv "$file" transport "$mode"
  set_config_kv "$file" VIRA7_TRANSPORT "$mode"
  vira7_compile_engine || return 1
  vira7_apply_firewall_rules "$id" || true
  if systemctl restart "$svc"; then
    echo "[OK] Vira tunnel $id restarted with transport=$mode"
    return 0
  fi
  systemctl status "$svc" --no-pager -l 2>/dev/null || true
  journalctl -u "$svc" -n 50 --no-pager 2>/dev/null || true
  return 1
}

vira7_optimize_cpu_menu() {
  show_header "Change Vira Transport Profile"
  vira7_list_tunnels
  echo
  local id mode_choice mode
  read -rp "Enter Vira tunnel number, 0=all, 00=menu: " id
  if is_main_menu_token "$id"; then return_main_msg; return 99; fi
  echo "1) Auto Hybrid UDP -> TCP fallback (recommended)"
  echo "2) UDP only"
  echo "3) TCP only"
  read -rp "Choose transport [1-3]: " mode_choice
  case "$mode_choice" in
    1) mode="auto" ;;
    2) mode="udp" ;;
    3) mode="tcp" ;;
    *) echo "Invalid mode."; return 1 ;;
  esac
  if [ "$id" = "0" ]; then
    local ids one
    ids="$(vira7_collect_ids || true)"
    [ -n "$ids" ] || { echo "No Vira tunnels found."; return 0; }
    while IFS= read -r one; do [ -n "$one" ] && vira7_optimize_cpu_one "$one" "$mode" || true; done <<< "$ids"
  else
    vira7_optimize_cpu_one "$id" "$mode"
  fi
}

vira7_diagnostics_one() {
  local id="$1" svc ifc stats now last age active
  validate_tunnel_id "$id" || return 1
  svc="$(vira7_service_name "$id")"
  ifc="$(vira7_iface_name "$id")"
  stats="$(vira7_stats_file "$id")"
  echo "============================================================"
  echo "Vira Hybrid tunnel $id diagnostics"
  echo "Service: $svc"
  if vira7_load_config "$id"; then
    echo "Role/direction : $SERVER_ROLE / $VIRA7_MODE / $VIRA7_DIRECTION"
    echo "Transport      : $VIRA7_TRANSPORT (UDP preferred; TCP fallback when auto)"
    echo "Public path    : $LOCAL_PUBLIC_IP -> $REMOTE_PUBLIC_IP:$VIRA7_PORT"
    echo "Tunnel path    : $LOCAL_VIRA7_IP -> $REMOTE_VIRA7_IP"
    echo "MTU/keepalive  : $VIRA7_MTU / ${VIRA7_KEEPALIVE}s"
  else
    echo "Config: missing"
  fi
  echo "Engine version : $($VIRA7_BINARY --version 2>/dev/null || echo missing)"
  echo "Service state  : $(systemctl is-active "$svc" 2>/dev/null || true)"
  echo "Enabled        : $(systemctl is-enabled "$svc" 2>/dev/null || true)"
  ip -br addr show "$ifc" 2>/dev/null || echo "Interface: missing"
  echo "UDP listener/socket:"
  ss -H -lunp 2>/dev/null | grep -E "(^|[:.])${VIRA7_PORT:-0}([[:space:]]|$)" || echo "  no server UDP listener (normal on Client because it uses an ephemeral port)"
  echo "TCP listener/connection:"
  ss -H -ltnp 2>/dev/null | grep -E "(^|[:.])${VIRA7_PORT:-0}([[:space:]]|$)" || echo "  no server TCP listener (normal on Client)"
  ss -H -tnp 2>/dev/null | grep -E "(^|[:.])${VIRA7_PORT:-0}([[:space:]]|$)" || true
  if [ -f "$stats" ]; then
    echo "Engine stats:"
    sed 's/^/  /' "$stats"
    active="$(awk -F= '$1=="active_transport"{print $2}' "$stats" 2>/dev/null || true)"
    last="$(awk -F= '$1=="last_rx_epoch"{print $2}' "$stats" 2>/dev/null || true)"
    if [[ "$last" =~ ^[0-9]+$ ]] && [ "$last" -gt 0 ]; then
      now="$(date +%s)"; age=$((now - last)); echo "  last_rx_age_seconds=$age"
    fi
    [ "$active" = "none" ] && warn_msg "No handshake yet. Check matching tunnel number, port, direction, remote IP, and the other service."
  else
    echo "Engine stats: not created yet"
  fi
  echo "Ping remote tunnel IP:"
  ping -c 4 -W 2 "${REMOTE_VIRA7_IP:-0.0.0.0}" || true
  echo "Last service logs:"
  journalctl -u "$svc" -n 50 --no-pager 2>/dev/null || true
}

vira7_diagnostics_menu() {
  show_header "Vira7 Diagnostics"
  vira7_list_tunnels
  echo
  local id ids one
  read -rp "Enter Vira7 tunnel number, 0=all, 00=menu: " id
  if is_main_menu_token "$id"; then return_main_msg; return 99; fi
  if [ "$id" = "0" ]; then
    ids="$(vira7_collect_ids || true)"
    [ -n "$ids" ] || { echo "No Vira7 tunnels found."; return 0; }
    while IFS= read -r one; do [ -n "$one" ] && vira7_diagnostics_one "$one"; done <<< "$ids"
  else
    vira7_diagnostics_one "$id"
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
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="Vira Hybrid"
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
    vira7) vira7_diagnostics_menu ;;
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
  vira7_compile_engine || warn_msg "Could not rebuild the Vira Hybrid engine before reset; existing binary will be used if available."
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
  show_header "GRE + WireGuard + Vira Hybrid Management"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel"
  echo -e "  ${C_RED}2)${C_RESET} remove tunnel"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} haproxy port manager"
  echo -e "  ${C_BLUE}6)${C_RESET} change Vira transport profile"
  echo -e "  ${C_CYAN}7)${C_RESET} Vira Hybrid diagnostics / logs"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  read -rp "Choose an option [0-7]: " CHOICE
  case "$CHOICE" in
    1) if menu_config_tunnel; then pause; fi ;;
    2) if remove_tun; then pause; fi ;;
    3) if reset_all_tunnels; then pause; fi ;;
    4) if test_tunnels_menu; then pause; fi ;;
    5) haproxy_menu || true ;;
    6) if vira7_optimize_cpu_menu; then pause; fi ;;
    7) if vira7_diagnostics_menu; then pause; fi ;;
    00) return_main_msg ;;
    0) echo "Bye"; exit 0 ;;
    *) err_msg "Invalid option"; sleep 1 ;;
  esac
}

### Script entry
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
    *)
      echo "Unknown service command. Supported: start-gre, firewall-wg, firewall-vira7, start-vira7." >&2
      exit 1
      ;;
  esac
fi

ensure_root
while true; do
  show_menu
done
