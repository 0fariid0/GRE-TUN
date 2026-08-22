#!/bin/bash
set -euo pipefail

# GRE + WireGuard + Vira7 + Reverse ViraTCP + HAProxy + Kernel Real-IP manager v9.0.0
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - WireGuard can use public UDP or automatically ride over an existing GRE tunnel as transport
# - Local tunnel/bind IPv4 can be selected manually for servers with multiple IPs
# - v8.5-safe-remove-heal prevents removing active transports used by WireGuard and re-heals remaining tunnels after deletion
# - v8.6-self-heal keeps GRE under a persistent supervisor, disables rp_filter for encapsulated paths,
#   pins public peer routes to the physical uplink, and repairs GRE/Vira7/WireGuard in dependency order
# - v8.6.1 fixes execution through bash <(curl ...) without consuming the script pipe
# - v8.6.2 fixes GRE creation on kernels that reject fixed TTL together with nopmtudisc
# - v8.6.3 displays the installed script version in the main menu header
# - v8.7.0 adds encrypted self-healing TCP-TUN (type 4) for paths that throttle/block GRE or UDP
# - v8.8.0 upgrades HAProxy forwarding with multi-port input, tunnel target picker, and automatic managed UDP companions for TCP rows
# - v8.8.1 fixes UDP companion forwarding by installing the proven DNAT/SNAT/FORWARD rules directly in built-in iptables chains
#   and migrates/cleans the v8.8.0 custom-chain implementation without touching unrelated firewall rules
# - v8.8.2 adds an interactive UDP repair action that detects every HAProxy TCP row, resolves its tunnel path,
#   rebuilds its UDP companion rules, and verifies DNAT/SNAT/FORWARD installation per port
# - v8.8.3 adds HAProxy UDP auto-heal: the existing 20s health monitor detects missing managed UDP rules
#   and repairs them immediately, while an hourly systemd timer force-runs the same repair as HAProxy option 8
# - v8.9.0 adds a separate Real-IP L3 forwarding engine beside HAProxy. It uses DNAT without SNAT,
#   preserves the original client source IP, has independent persistence/self-heal, one-time Kharej
#   return-policy routing, and safe per-port switching HAProxy <-> Real-IP without removing HAProxy.
# - v8.9.1 makes Real-IP safer for handshake-sensitive setups: TCP-only is now the default,
#   UDP is explicit/optional, Switch uses numbered ALL selection, and Real-IP menus are grouped more clearly.
# - v8.9.2 fixes Real-IP handshake spikes by adding automatic TCP MSS clamping
#   on DNAT-forwarded paths and MTU-aware Kharej return routes.
# - v9.0.0 makes Real-IP the low-CPU, no-PROXY-protocol path for 3x-ui/Xray,
#   adds transactional HAProxy <-> Real-IP switching with verified rollback,
#   hardens tunnel listeners to the configured peer, removes the unused Vira7
#   CPU menu, and exposes ViraTCP as a reverse L3 tunnel that carries TCP+UDP.
# - v9.0.0 also removes the static ViraTCP wire magic so a session no longer
#   starts every encrypted frame with a fixed, easily fingerprinted marker.

APP_VERSION="9.0.0"

GRE_CONFIG_DIR="/etc/gre-tunnels"
GRE_LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gretun-manager.sh"
GRE_SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
GRE_LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
GRE_SUPERVISOR_INTERVAL=10
GRE_SUPERVISOR_FAIL_LIMIT=3
HEALTH_SERVICE_UNIT="/etc/systemd/system/gretun-health.service"
HEALTH_TIMER_UNIT="/etc/systemd/system/gretun-health.timer"
HEALTH_STATE_DIR="/run/gretun-health"
HEALTH_FAIL_LIMIT=3
SELF_RAW_URL="https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh"

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
# Vira7 runtime defaults are fixed at creation time; there is no separate CPU
# tuning menu in v9.0.0. These values preserve the existing packet format.
VIRA7_DEFAULT_CHECKSUM=1
VIRA7_DEFAULT_VERIFY_CHECKSUM=0
VIRA7_DEFAULT_BATCH=128

# ViraTCP: encrypted TCP based TUN. Iran initiates the outbound TCP connection
# and Kharej listens, which is useful where GRE/UDP paths are short-lived or filtered.
VIRATCP_CONFIG_DIR="/etc/viratcp-tunnels"
VIRATCP_BINARY="/usr/local/bin/viratcp-engine"
VIRATCP_SOURCE="$VIRATCP_CONFIG_DIR/viratcp_engine.c"
VIRATCP_SERVICE_TEMPLATE="/etc/systemd/system/viratcp-tunnel@.service"
VIRATCP_IFACE_PREFIX="viratcp"
VIRATCP_DEFAULT_PORT=443
VIRATCP_DEFAULT_MTU=1280
VIRATCP_DEFAULT_KEEPALIVE=10
VIRATCP_DEFAULT_RECONNECT=3
VIRATCP_DEFAULT_TCP_USER_TIMEOUT=20000

HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
HAPROXY_BACKUP_DIR="/etc/haproxy/gretun-backups"
HAPROXY_MAXCONN=500000
HAPROXY_NOFILE_LIMIT=1048576
HAPROXY_UDP_SERVICE_NAME="gretun-haproxy-udp.service"
HAPROXY_UDP_SERVICE_UNIT="/etc/systemd/system/${HAPROXY_UDP_SERVICE_NAME}"
HAPROXY_UDP_REPAIR_SERVICE_NAME="gretun-haproxy-udp-repair.service"
HAPROXY_UDP_REPAIR_SERVICE_UNIT="/etc/systemd/system/${HAPROXY_UDP_REPAIR_SERVICE_NAME}"
HAPROXY_UDP_REPAIR_TIMER_NAME="gretun-haproxy-udp-repair.timer"
HAPROXY_UDP_REPAIR_TIMER_UNIT="/etc/systemd/system/${HAPROXY_UDP_REPAIR_TIMER_NAME}"

# Real-IP forwarding is a completely separate forwarding engine. It never
# replaces HAProxy globally: each local port can live in HAProxy or Real-IP.
# Real-IP keeps the client source address by doing DNAT + FORWARD only (no SNAT).
# Because Real-IP no longer terminates TCP like HAProxy, it must clamp MSS on
# GRE/TUN paths to avoid fragmented TLS/WS handshakes and repeated retries.
REALIP_CONFIG_DIR="/etc/gretun-realip"
REALIP_FORWARDS_FILE="$REALIP_CONFIG_DIR/forwards.conf"
REALIP_BACKUP_DIR="$REALIP_CONFIG_DIR/backups"
REALIP_RETURN_MARKER="$REALIP_CONFIG_DIR/return-routing.enabled"
REALIP_SERVICE_NAME="gretun-realip.service"
REALIP_SERVICE_UNIT="/etc/systemd/system/${REALIP_SERVICE_NAME}"
REALIP_RULE_PREFIX="gretun-realip"
FORWARD_SWITCH_LOCK="/run/gretun-forward-switch.lock"

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
  echo "4) Reverse ViraTCP encrypted TCP-TUN (Iran dials out; carries TCP + UDP)"
  echo
  read -rp "Choose [1-4] (00=menu): " TUNNEL_TYPE_CHOICE
  if is_main_menu_token "$TUNNEL_TYPE_CHOICE"; then return_main_msg; return 99; fi
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE="gre" ;;
    2) SELECTED_TUNNEL_TYPE="wireguard" ;;
    3) SELECTED_TUNNEL_TYPE="vira7" ;;
    4) SELECTED_TUNNEL_TYPE="viratcp" ;;
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

# Install a persistent copy safely. When this script is launched with
#   bash <(curl ...)
# $0 points to a live pipe (/dev/fd/N). Copying that pipe consumes the unread
# tail of the running script and makes the menu disappear. In that case fetch
# a complete regular-file copy instead; for normal file execution copy locally.
install_manager_binary() {
  local source_path="${BASH_SOURCE[0]:-$0}"
  local target_dir tmp candidate_version
  target_dir="$(dirname "$INSTALL_BIN")"
  tmp="${INSTALL_BIN}.tmp.$$"

  mkdir -p "$target_dir" || return 1
  rm -f "$tmp"

  case "$source_path" in
    /dev/fd/*|/proc/*/fd/*)
      if command -v curl >/dev/null 2>&1; then
        curl -fLsS --ipv4 "$SELF_RAW_URL" -o "$tmp" || { rm -f "$tmp"; return 1; }
      elif command -v wget >/dev/null 2>&1; then
        wget -qO "$tmp" "$SELF_RAW_URL" || { rm -f "$tmp"; return 1; }
      else
        return 1
      fi
      ;;
    *)
      [ -r "$source_path" ] || return 1
      cp -f "$source_path" "$tmp" || { rm -f "$tmp"; return 1; }
      ;;
  esac

  [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
  bash -n "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
  candidate_version="$(sed -n 's/^APP_VERSION="\([^"]*\)"/\1/p' "$tmp" | head -n1)"
  if [ "$candidate_version" != "$APP_VERSION" ]; then
    err_msg "Persistent manager version mismatch: running $APP_VERSION but downloaded ${candidate_version:-UNKNOWN}. Upload v$APP_VERSION to the configured raw URL first, or run this script from a local file."
    rm -f "$tmp"
    return 1
  fi
  chmod 755 "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$INSTALL_BIN"
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
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      iptables -C INPUT -s "$peer_ip" -p udp --dport "$port" -m comment --comment "gretun-peer-udp-$port" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -s "$peer_ip" -p udp --dport "$port" -m comment --comment "gretun-peer-udp-$port" -j ACCEPT || true
      iptables -C OUTPUT -d "$peer_ip" -p udp --dport "$peer_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -p udp --dport "$peer_port" -j ACCEPT || true
    else
      iptables -C INPUT -p udp --dport "$port" -m comment --comment "gretun-any-udp-$port" -j ACCEPT 2>/dev/null \
        || iptables -A INPUT -p udp --dport "$port" -m comment --comment "gretun-any-udp-$port" -j ACCEPT || true
    fi
    if [ -n "$ifc" ]; then
      iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -j ACCEPT || true
      iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -j ACCEPT || true
      iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ifc" -j ACCEPT || true
      iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$ifc" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      ufw allow from "$peer_ip" to any port "$port" proto udp >/dev/null 2>&1 || true
      ufw allow out to "$peer_ip" port "$peer_port" proto udp >/dev/null 2>&1 || true
    else
      ufw allow "$port/udp" >/dev/null 2>&1 || true
    fi
    if [ -n "$ifc" ]; then
      ufw allow in on "$ifc" >/dev/null 2>&1 || true
    fi
  fi

  echo "Firewall opened for $label: UDP $port, peer ${peer_ip:-any}, interface ${ifc:-none}"
}

firewall_allow_tcp_port_and_ip() {
  local label="$1"
  local port="$2"
  local peer_ip="${3:-}"
  local ifc="${4:-}"
  local listen_mode="${5:-0}"

  if command -v iptables >/dev/null 2>&1; then
    if [ "$listen_mode" = "1" ]; then
      if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
        iptables -C INPUT -s "$peer_ip" -p tcp --dport "$port" -m comment --comment "gretun-peer-tcp-$port" -j ACCEPT 2>/dev/null \
          || iptables -A INPUT -s "$peer_ip" -p tcp --dport "$port" -m comment --comment "gretun-peer-tcp-$port" -j ACCEPT || true
      else
        iptables -C INPUT -p tcp --dport "$port" -m comment --comment "gretun-any-tcp-$port" -j ACCEPT 2>/dev/null \
          || iptables -A INPUT -p tcp --dport "$port" -m comment --comment "gretun-any-tcp-$port" -j ACCEPT || true
      fi
    fi
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      iptables -C OUTPUT -d "$peer_ip" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -p tcp --dport "$port" -j ACCEPT || true
    fi
    if [ -n "$ifc" ]; then
      iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -j ACCEPT || true
      iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -j ACCEPT || true
      iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ifc" -j ACCEPT || true
      iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$ifc" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      ufw allow out to "$peer_ip" port "$port" proto tcp >/dev/null 2>&1 || true
      if [ "$listen_mode" = "1" ]; then ufw allow from "$peer_ip" to any port "$port" proto tcp >/dev/null 2>&1 || true; fi
    elif [ "$listen_mode" = "1" ]; then
      ufw allow "$port/tcp" >/dev/null 2>&1 || true
    fi
    if [ -n "$ifc" ]; then ufw allow in on "$ifc" >/dev/null 2>&1 || true; fi
  fi

  echo "Firewall opened for $label: TCP $port, peer ${peer_ip:-any}, interface ${ifc:-none}"
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
# Runtime stability / self-heal helpers
# -----------------------------
tunnel_iface_is_up() {
  local ifc="${1:-}"
  [ -n "$ifc" ] || return 1
  ip -o link show dev "$ifc" 2>/dev/null | grep -Eq '<[^>]*UP([,>])'
}

apply_tunnel_sysctls() {
  local sysctl_file="/etc/sysctl.d/99-gretun-self-heal.conf"
  mkdir -p /etc/sysctl.d 2>/dev/null || true
  if [ ! -f "$sysctl_file" ] || ! grep -q 'gretun-self-heal' "$sysctl_file" 2>/dev/null; then
    cat > "$sysctl_file" <<'EOF_SYSCTL'
# gretun-self-heal: stable settings for GRE/WireGuard/UDP-TUN encapsulation
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.tcp_mtu_probing=1
EOF_SYSCTL
  fi

  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>&1 || true

  local rp
  for rp in /proc/sys/net/ipv4/conf/*/rp_filter; do
    [ -e "$rp" ] && echo 0 > "$rp" 2>/dev/null || true
  done
}

# Keep the public peer reachable through the physical uplink. This avoids a
# recursive route after overlay routes are added or restored by other tools.
ensure_public_endpoint_route() {
  local remote_ip="${1:-}"
  local local_ip="${2:-}"
  local route dev gateway
  validate_ipv4 "$remote_ip" || return 0
  validate_ipv4 "$local_ip" || return 0
  [ "$remote_ip" != "$local_ip" ] || return 0

  route="$(ip -4 route get "$remote_ip" from "$local_ip" 2>/dev/null | head -n 1 || true)"
  dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
  gateway="$(awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' <<< "$route")"

  case "$dev" in
    gre*|wgtun*|vira7*|viratcp*|"")
      route="$(ip -4 route get 1.1.1.1 from "$local_ip" 2>/dev/null | head -n 1 || true)"
      dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
      gateway="$(awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' <<< "$route")"
      ;;
  esac

  [ -n "$dev" ] || return 0
  case "$dev" in gre*|wgtun*|vira7*|viratcp*) return 0 ;; esac
  if [ -n "$gateway" ]; then
    ip -4 route replace "$remote_ip/32" via "$gateway" dev "$dev" src "$local_ip" metric 5 2>/dev/null || true
  else
    ip -4 route replace "$remote_ip/32" dev "$dev" src "$local_ip" metric 5 2>/dev/null || true
  fi
}

quick_tunnel_ping() {
  local ifc="${1:-}"
  local target="${2:-}"
  target="${target%%/*}"
  [ -n "$ifc" ] && [ -n "$target" ] || return 1
  tunnel_iface_is_up "$ifc" || return 1
  ping -n -I "$ifc" -c 1 -W 2 "$target" >/dev/null 2>&1
}

health_counter_reset() {
  local kind="$1" id="$2"
  rm -f "$HEALTH_STATE_DIR/${kind}-${id}.fail" 2>/dev/null || true
}

health_counter_fail() {
  local kind="$1" id="$2" file count
  mkdir -p "$HEALTH_STATE_DIR" 2>/dev/null || true
  file="$HEALTH_STATE_DIR/${kind}-${id}.fail"
  count="$(cat "$file" 2>/dev/null || echo 0)"
  [[ "$count" =~ ^[0-9]+$ ]] || count=0
  count=$((count + 1))
  printf '%s\n' "$count" > "$file"
  printf '%s\n' "$count"
}

restart_wg_dependents_for_transport() {
  local transport_type="$1" transport_id="$2"
  local ids wg_id svc
  command -v systemctl >/dev/null 2>&1 || return 0
  ids="$(wg_collect_ids 2>/dev/null || true)"
  while IFS= read -r wg_id; do
    [ -n "$wg_id" ] || continue
    if wg_uses_transport_tunnel "$wg_id" "$transport_type" "$transport_id"; then
      wg_load_meta "$wg_id" || continue
      [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ] || continue
      svc="$(wg_service_name "$wg_id")"
      if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
        wg_apply_firewall_rules "$wg_id" >/dev/null 2>&1 || true
        systemctl restart "$svc" >/dev/null 2>&1 || true
      fi
    fi
  done <<< "$ids"
}

install_health_monitor() {
  command -v systemctl >/dev/null 2>&1 || return 0
  mkdir -p "$(dirname "$INSTALL_BIN")" "$HEALTH_STATE_DIR" 2>/dev/null || true
  if [ ! -s "$INSTALL_BIN" ]; then
    install_manager_binary >/dev/null 2>&1 || return 1
  fi

  cat > "$HEALTH_SERVICE_UNIT" <<EOF_HEALTH_SERVICE
[Unit]
Description=GRE/WireGuard/Vira7/ViraTCP dependency-aware health check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service health-check-all
EOF_HEALTH_SERVICE

  cat > "$HEALTH_TIMER_UNIT" <<'EOF_HEALTH_TIMER'
[Unit]
Description=Run GRE/WireGuard/Vira7/ViraTCP health check periodically

[Timer]
OnBootSec=25s
OnUnitActiveSec=20s
AccuracySec=3s
RandomizedDelaySec=2s
Persistent=true
Unit=gretun-health.service

[Install]
WantedBy=timers.target
EOF_HEALTH_TIMER

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now gretun-health.timer >/dev/null 2>&1 || true
}

# GRE uses a persistent supervisor instead of a oneshot service. A oneshot unit
# can remain "active" after the kernel interface has disappeared, which prevents
# systemd from repairing it. The supervisor verifies both interface presence and
# inner reachability, then recreates only this GRE and restarts dependent WG.
gre_supervisor() {
  local id="${1:-}" ifc target failures=0
  validate_tunnel_id "$id" || return 1
  trap 'exit 0' TERM INT HUP

  while true; do
    if ! gre_load_config "$id"; then
      echo "GRE supervisor: missing config for tunnel $id" >&2
      return 1
    fi
    ifc="$(gre_iface "$id")"
    target="${REMOTE_GRE_IP:-$(gre_remote_inner_ip_for_role "$id" "${ROLE:-2}")}"
    apply_tunnel_sysctls
    ensure_public_endpoint_route "${REMOTE_PUBLIC_IP:-}" "${LOCAL_PUBLIC_IP:-}"

    if ! tunnel_iface_is_up "$ifc"; then
      echo "GRE supervisor: $ifc is missing/down; recreating tunnel $id" >&2
      if gre_create_tunnel 0; then
        failures=0
        restart_wg_dependents_for_transport gre "$id"
      else
        sleep "$GRE_SUPERVISOR_INTERVAL"
        continue
      fi
    elif quick_tunnel_ping "$ifc" "$target"; then
      failures=0
    else
      failures=$((failures + 1))
      if [ "$failures" -ge "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        echo "GRE supervisor: tunnel $id failed $failures health checks; recreating" >&2
        if gre_create_tunnel 0; then
          restart_wg_dependents_for_transport gre "$id"
        fi
        failures=0
      fi
    fi

    sleep "$GRE_SUPERVISOR_INTERVAL" &
    wait $! || true
  done
}

gre_write_service_template() {
  cat > "$GRE_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=Normal GRE Tunnel %i Self-Healing Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/bin/bash $INSTALL_BIN --service supervise-gre %i
Restart=always
RestartSec=2
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

tunnel_health_check_all() {
  local lockdir="/run/gretun-health.lock"
  mkdir "$lockdir" 2>/dev/null || return 0
  trap 'rmdir /run/gretun-health.lock 2>/dev/null || true' EXIT
  apply_tunnel_sysctls

  local ids id ifc svc target count transport_ok

  # GRE first: the persistent service handles inner-ping repair itself. Here we
  # only revive a stopped service or a missing interface immediately.
  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(gre_service_name "$id")"
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      ifc="$(gre_iface "$id")"
      if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
        systemctl restart "$svc" >/dev/null 2>&1 || true
      fi
    fi
  done <<< "$ids"

  # Vira7 can stay alive while its UDP path is stale. Restart only after three
  # consecutive failed inner pings, then refresh dependent WireGuard tunnels.
  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(vira7_service_name "$id")"
    systemctl is-enabled --quiet "$svc" 2>/dev/null || continue
    vira7_load_config "$id" || continue
    ifc="$(vira7_iface_name "$id")"
    target="${REMOTE_VIRA7_IP:-${remote_priv:-}}"
    ensure_public_endpoint_route "${REMOTE_PUBLIC_IP:-${remote_ip:-}}" "${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
    vira7_apply_firewall_rules "$id" >/dev/null 2>&1 || true

    if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
      systemctl restart "$svc" >/dev/null 2>&1 || true
      health_counter_reset vira7 "$id"
      sleep 1
      restart_wg_dependents_for_transport vira7 "$id"
    elif quick_tunnel_ping "$ifc" "$target"; then
      health_counter_reset vira7 "$id"
    else
      count="$(health_counter_fail vira7 "$id")"
      if [ "$count" -ge "$HEALTH_FAIL_LIMIT" ]; then
        systemctl restart "$svc" >/dev/null 2>&1 || true
        health_counter_reset vira7 "$id"
        sleep 1
        restart_wg_dependents_for_transport vira7 "$id"
      fi
    fi
  done <<< "$ids"

  # ViraTCP maintains a reconnecting TCP session itself. The health timer only
  # restarts it after repeated inner-path failures or if the service/interface disappeared.
  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(viratcp_service_name "$id")"
    systemctl is-enabled --quiet "$svc" 2>/dev/null || continue
    viratcp_load_config "$id" || continue
    ifc="$(viratcp_iface_name "$id")"
    target="${REMOTE_VIRATCP_IP:-${remote_priv:-}}"
    ensure_public_endpoint_route "${REMOTE_PUBLIC_IP:-${remote_ip:-}}" "${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
    viratcp_apply_firewall_rules "$id" >/dev/null 2>&1 || true
    if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
      systemctl restart "$svc" >/dev/null 2>&1 || true
      health_counter_reset viratcp "$id"
    elif quick_tunnel_ping "$ifc" "$target"; then
      health_counter_reset viratcp "$id"
    else
      count="$(health_counter_fail viratcp "$id")"
      if [ "$count" -ge "$HEALTH_FAIL_LIMIT" ]; then
        systemctl restart "$svc" >/dev/null 2>&1 || true
        health_counter_reset viratcp "$id"
      fi
    fi
  done <<< "$ids"

  # WireGuard is checked last so its selected GRE/Vira7 transport is repaired
  # before the overlay is touched.
  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    wg_load_meta "$id" || continue
    [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ] || continue
    svc="$(wg_service_name "$id")"
    systemctl is-enabled --quiet "$svc" 2>/dev/null || continue
    ifc="$(wg_iface_name "$id")"
    target="${REMOTE_WG_IP:-}"
    transport_ok=1
    case "${WG_ENDPOINT_MODE:-public}" in
      gre|vira7)
        if ! tunnel_iface_is_up "${WG_TRANSPORT_IFACE:-}"; then transport_ok=0; fi
        ;;
    esac
    [ "$transport_ok" -eq 1 ] || { health_counter_reset wireguard "$id"; continue; }
    wg_apply_firewall_rules "$id" >/dev/null 2>&1 || true

    if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
      systemctl restart "$svc" >/dev/null 2>&1 || true
      health_counter_reset wireguard "$id"
    elif quick_tunnel_ping "$ifc" "$target"; then
      health_counter_reset wireguard "$id"
    else
      count="$(health_counter_fail wireguard "$id")"
      if [ "$count" -ge "$HEALTH_FAIL_LIMIT" ]; then
        systemctl restart "$svc" >/dev/null 2>&1 || true
        health_counter_reset wireguard "$id"
      fi
    fi
  done <<< "$ids"

  # HAProxy UDP companions are checked last. This is intentionally lightweight:
  # when all four managed rules exist for every TCP row, nothing is changed.
  # If firewall/NAT rules disappear, run the same rebuild+verify logic as menu option 8.
  haproxy_udp_self_heal_check || true

  # Real-IP has its own rule namespace and health check. When configured, repair
  # its DNAT/FORWARD rules and (on Kharej) the source-policy return route.
  realip_self_heal_check || true
}

bootstrap_runtime_repairs() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local migrate=0 ids id svc ifc
  mkdir -p "$(dirname "$INSTALL_BIN")" 2>/dev/null || true
  install_manager_binary >/dev/null 2>&1 || true
  if [ ! -f "$GRE_SERVICE_TEMPLATE" ] || ! grep -q 'supervise-gre' "$GRE_SERVICE_TEMPLATE" 2>/dev/null; then
    migrate=1
  fi
  gre_write_service_template
  install_health_monitor
  apply_tunnel_sysctls
  systemctl daemon-reload >/dev/null 2>&1 || true

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(gre_service_name "$id")"
    ifc="$(gre_iface "$id")"
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if [ "$migrate" -eq 1 ] || ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
        systemctl restart "$svc" >/dev/null 2>&1 || true
      fi
    fi
  done <<< "$ids"

  # Existing HAProxy users upgrading to v8.8.3 get the UDP repair timer
  # automatically on the next manager launch; no need to enter the HAProxy menu.
  if [ -f "$HAPROXY_CONFIG" ] && command -v haproxy >/dev/null 2>&1; then
    haproxy_install_udp_service >/dev/null 2>&1 || true
  fi

  # Restore Real-IP forwarding/return-routing after upgrades or reboot only if
  # the operator has configured this separate engine.
  if [ -s "$REALIP_FORWARDS_FILE" ] || [ -f "$REALIP_RETURN_MARKER" ]; then
    realip_install_service >/dev/null 2>&1 || true
    realip_sync_all >/dev/null 2>&1 || true
  fi
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
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^gre[0-9]+$' | sed 's/^gre//' | awk '$1 >= 1 && $1 <= 254' || true
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

    if tunnel_iface_is_up "$ifc"; then
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

  apply_tunnel_sysctls
  ensure_public_endpoint_route "$REMOTE_PUBLIC_IP" "$LOCAL_PUBLIC_IP"
  modprobe gre || true
  modprobe ip_gre || true

  # Remove only this GRE interface so other GRE/WireGuard tunnels stay intact.
  ip link set "$TUN_IFACE" down 2>/dev/null || true
  ip tunnel del "$TUN_IFACE" 2>/dev/null || true

  if ! ip tunnel add "$TUN_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$TUN_KEY" nopmtudisc; then
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

  if ! ip link set "$TUN_IFACE" mtu 1390 txqueuelen 1000 || ! ip link set "$TUN_IFACE" up; then
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
  apply_tunnel_sysctls

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
  if ! install_manager_binary; then
    echo "Failed to install the persistent manager copy at $INSTALL_BIN" >&2
    return 1
  fi

  gre_write_service_template
  install_health_monitor

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
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${WG_IFACE_PREFIX}[0-9]+$" | sed "s/^${WG_IFACE_PREFIX}//" | awk '$1 >= 1 && $1 <= 254' || true
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

    if tunnel_iface_is_up "$ifc"; then
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
  local selected_role existing_local_ip existing_remote_ip existing_peer_key
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter WireGuard tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  existing_peer_key=""
  local previous_endpoint_mode previous_endpoint_ip previous_transport_iface gre_saved_remote vira_saved_remote gre_cfg vira_cfg
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
  # Source a fixed validated path in a subshell so config variables cannot leak
  # into the selected WireGuard role and no shell command is assembled as text.
  gre_cfg="$GRE_CONFIG_DIR/tunnel-$TUNNEL_ID.conf"
  vira_cfg="$VIRA7_CONFIG_DIR/tunnel-$TUNNEL_ID.conf"
  if [ -f "$gre_cfg" ]; then
    # shellcheck disable=SC1090
    gre_saved_remote="$(unset REMOTE_PUBLIC_IP; source "$gre_cfg"; printf '%s' "${REMOTE_PUBLIC_IP:-}")"
  fi
  if [ -f "$vira_cfg" ]; then
    # shellcheck disable=SC1090
    vira_saved_remote="$(unset REMOTE_PUBLIC_IP remote_ip; source "$vira_cfg"; printf '%s' "${REMOTE_PUBLIC_IP:-${remote_ip:-}}")"
  fi
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
  if ! install_manager_binary; then
    echo "Failed to install the persistent manager copy at $INSTALL_BIN" >&2
    return 1
  fi
  install_health_monitor
  mkdir -p "/etc/systemd/system/wg-quick@$ifc.service.d"
  local transport_after=""
  if wg_load_meta "$id"; then
    case "${WG_ENDPOINT_MODE:-public}" in
      gre) transport_after="gre-tunnel@$id.service" ;;
      vira7) transport_after="vira7-tunnel@$id.service" ;;
    esac
  fi
  if [ -n "$transport_after" ]; then
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target $transport_after
Wants=$transport_after

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-wg $id
EOF_WG_FW
  else
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-wg $id
EOF_WG_FW
  fi

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
    int rc = system(cmd); (void)rc;
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
    if (access(TUN_DEVICE, F_OK) != 0) { int rc = system("mknod /dev/net/tun c 10 200 2>/dev/null || true"); (void)rc; }
    { int rc = system("modprobe tun 2>/dev/null || true"); (void)rc; }
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
                if (type == PKT_DATA && len > 0) {
                    ssize_t written = write(tun_fd, payload, len);
                    if (written != (ssize_t)len) continue;
                }
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
StartLimitIntervalSec=0

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
  if ! install_manager_binary; then
    echo "Failed to install the persistent manager copy at $INSTALL_BIN" >&2
    return 1
  fi
  install_health_monitor
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
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${VIRA7_IFACE_PREFIX}[0-9]+$" | sed "s/^${VIRA7_IFACE_PREFIX}//" | awk '$1 >= 1 && $1 <= 254' || true
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


# -----------------------------
# ViraTCP encrypted TCP-TUN helpers (tunnel type 4)
# -----------------------------
viratcp_iface_name() {
  echo "${VIRATCP_IFACE_PREFIX}$1"
}

viratcp_config_file() {
  echo "$VIRATCP_CONFIG_DIR/tunnel-$1.conf"
}

viratcp_service_name() {
  echo "viratcp-tunnel@$1.service"
}

viratcp_inner_ip_for_role() {
  local id="$1" role="$2"
  if [ "$role" = "1" ]; then echo "10.81.$id.1"; else echo "10.81.$id.2"; fi
}

viratcp_remote_inner_ip_for_role() {
  local id="$1" role="$2"
  if [ "$role" = "1" ]; then echo "10.81.$id.2"; else echo "10.81.$id.1"; fi
}

viratcp_generate_psk() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
  fi
}

viratcp_validate_psk() {
  [[ "${1:-}" =~ ^[A-Fa-f0-9]{64}$ ]]
}

viratcp_ensure_deps() {
  if command -v gcc >/dev/null 2>&1 && [ -f /usr/include/openssl/evp.h ]; then return 0; fi
  echo "Installing ViraTCP build/runtime dependencies..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential gcc libssl-dev iproute2 iptables kmod openssl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y gcc make openssl-devel iproute iptables kmod openssl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y gcc make openssl-devel iproute iptables kmod openssl
  else
    echo "No supported package manager found. Install gcc, OpenSSL development headers, iproute2 and iptables manually." >&2
    return 1
  fi
}

viratcp_compile_engine() {
  viratcp_ensure_deps || return 1
  mkdir -p "$VIRATCP_CONFIG_DIR"
  cat > "$VIRATCP_SOURCE" <<'VIRATCP_ENGINE_EOF'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
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

#define TUN_DEVICE "/dev/net/tun"
#define VT_MAGIC 0x56544350U
#define VT_VERSION 2U
#define VT_DATA 1U
#define VT_PING 2U
#define VT_PONG 3U
#define MAX_PACKET 65535U
#define TAG_LEN 16U
#define HEADER_LEN 20U

typedef struct {
    char iface[IFNAMSIZ];
    char mode[16];
    char bind_ip[64];
    char remote_ip[64];
    char local_priv[64];
    char remote_priv[64];
    char psk_hex[129];
    int port;
    int mtu;
    int keepalive;
    int reconnect;
    int tcp_user_timeout;
    int queue_len;
} vt_config_t;

typedef struct {
    unsigned char tx_key[32];
    unsigned char rx_key[32];
    unsigned char tx_nonce_prefix[4];
    unsigned char rx_nonce_prefix[4];
    unsigned char header_mask[8];
    uint64_t tx_seq;
    uint64_t rx_seq;
} crypto_state_t;

static volatile sig_atomic_t running = 1;
static void on_signal(int sig) { (void)sig; running = 0; }

static uint64_t bswap64_u(uint64_t x) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
}

static void trim(char *s) {
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n')) s[--n] = 0;
}

static int load_config(const char *path, vt_config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->iface, sizeof(c->iface), "viratcp");
    snprintf(c->mode, sizeof(c->mode), "client");
    c->port = 443; c->mtu = 1280; c->keepalive = 10; c->reconnect = 3;
    c->tcp_user_timeout = 20000; c->queue_len = 2000;
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        trim(line); if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '='); if (!eq) continue;
        *eq = 0; char *key = line; char *val = eq + 1; trim(key); trim(val);
        if (!strcmp(key, "iface")) snprintf(c->iface, sizeof(c->iface), "%s", val);
        else if (!strcmp(key, "mode")) snprintf(c->mode, sizeof(c->mode), "%s", val);
        else if (!strcmp(key, "bind_ip")) snprintf(c->bind_ip, sizeof(c->bind_ip), "%s", val);
        else if (!strcmp(key, "remote_ip")) snprintf(c->remote_ip, sizeof(c->remote_ip), "%s", val);
        else if (!strcmp(key, "local_priv")) snprintf(c->local_priv, sizeof(c->local_priv), "%s", val);
        else if (!strcmp(key, "remote_priv")) snprintf(c->remote_priv, sizeof(c->remote_priv), "%s", val);
        else if (!strcmp(key, "psk")) snprintf(c->psk_hex, sizeof(c->psk_hex), "%s", val);
        else if (!strcmp(key, "port")) c->port = atoi(val);
        else if (!strcmp(key, "mtu")) c->mtu = atoi(val);
        else if (!strcmp(key, "keepalive")) c->keepalive = atoi(val);
        else if (!strcmp(key, "reconnect")) c->reconnect = atoi(val);
        else if (!strcmp(key, "tcp_user_timeout")) c->tcp_user_timeout = atoi(val);
        else if (!strcmp(key, "queue_len")) c->queue_len = atoi(val);
    }
    fclose(f);
    if (!c->iface[0] || !c->local_priv[0] || !c->remote_priv[0] || strlen(c->psk_hex) != 64) return -1;
    if (strcmp(c->mode, "client") && strcmp(c->mode, "server")) return -1;
    if (!strcmp(c->mode, "client") && !c->remote_ip[0]) return -1;
    if (c->port < 1 || c->port > 65535) return -1;
    if (c->mtu < 576 || c->mtu > 1500) c->mtu = 1280;
    if (c->keepalive < 3 || c->keepalive > 60) c->keepalive = 10;
    if (c->reconnect < 1 || c->reconnect > 60) c->reconnect = 3;
    if (c->tcp_user_timeout < 5000 || c->tcp_user_timeout > 120000) c->tcp_user_timeout = 20000;
    if (c->queue_len < 100) c->queue_len = 2000;
    return 0;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen) {
    if (strlen(hex) != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return 0;
}

static void derive_session_value(const unsigned char psk[32], const unsigned char client_nonce[32],
                                 const unsigned char server_nonce[32], const char *label, unsigned char out[32]) {
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, psk, 32);
    SHA256_Update(&c, client_nonce, 32);
    SHA256_Update(&c, server_nonce, 32);
    SHA256_Update(&c, label, strlen(label));
    SHA256_Final(out, &c);
}

static int crypto_init_state(const vt_config_t *cfg, const unsigned char client_nonce[32],
                             const unsigned char server_nonce[32], crypto_state_t *st) {
    unsigned char psk[32], c2s[32], s2c[32], nc2s[32], ns2c[32], hmask[32];
    if (hex_to_bytes(cfg->psk_hex, psk, sizeof(psk)) != 0) return -1;
    derive_session_value(psk, client_nonce, server_nonce, "viratcp-c2s-key-v1", c2s);
    derive_session_value(psk, client_nonce, server_nonce, "viratcp-s2c-key-v1", s2c);
    derive_session_value(psk, client_nonce, server_nonce, "viratcp-c2s-nonce-v1", nc2s);
    derive_session_value(psk, client_nonce, server_nonce, "viratcp-s2c-nonce-v1", ns2c);
    derive_session_value(psk, client_nonce, server_nonce, "viratcp-header-mask-v2", hmask);
    memset(st, 0, sizeof(*st)); st->tx_seq = 1; st->rx_seq = 0;
    memcpy(st->header_mask, hmask, sizeof(st->header_mask));
    if (!strcmp(cfg->mode, "client")) {
        memcpy(st->tx_key, c2s, 32); memcpy(st->rx_key, s2c, 32);
        memcpy(st->tx_nonce_prefix, nc2s, 4); memcpy(st->rx_nonce_prefix, ns2c, 4);
    } else {
        memcpy(st->tx_key, s2c, 32); memcpy(st->rx_key, c2s, 32);
        memcpy(st->tx_nonce_prefix, ns2c, 4); memcpy(st->rx_nonce_prefix, nc2s, 4);
    }
    OPENSSL_cleanse(psk, sizeof(psk)); OPENSSL_cleanse(c2s, sizeof(c2s)); OPENSSL_cleanse(s2c, sizeof(s2c));
    OPENSSL_cleanse(nc2s, sizeof(nc2s)); OPENSSL_cleanse(ns2c, sizeof(ns2c));
    OPENSSL_cleanse(hmask, sizeof(hmask));
    return 0;
}

static int tun_alloc_named(const char *dev) {
    int fd = open(TUN_DEVICE, O_RDWR); if (fd < 0) return -1;
    struct ifreq ifr; memset(&ifr, 0, sizeof(ifr)); ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { close(fd); return -1; }
    return fd;
}

static void cleanup_iface(const char *iface) {
    char cmd[256]; snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", iface);
    int rc = system(cmd); (void)rc;
}

static int configure_tun(const vt_config_t *c) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s up mtu %d txqueuelen %d", c->iface, c->mtu, c->queue_len);
    if (system(cmd) != 0) return -1;
    snprintf(cmd, sizeof(cmd), "ip addr replace %s/32 peer %s dev %s", c->local_priv, c->remote_priv, c->iface);
    return system(cmd) == 0 ? 0 : -1;
}

static void set_sock_opts(int fd, const vt_config_t *c) {
    int one = 1, idle = c->keepalive, intvl = c->keepalive / 2; if (intvl < 2) intvl = 2; int cnt = 3;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
#endif
#ifdef TCP_KEEPCNT
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
#endif
#ifdef TCP_USER_TIMEOUT
    setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &c->tcp_user_timeout, sizeof(c->tcp_user_timeout));
#endif
    struct timeval tv; tv.tv_sec = c->keepalive * 4; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int create_listener(const vt_config_t *c) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a; memset(&a, 0, sizeof(a)); a.sin_family = AF_INET; a.sin_port = htons((uint16_t)c->port);
    if (c->bind_ip[0]) { if (inet_pton(AF_INET, c->bind_ip, &a.sin_addr) != 1) { close(fd); return -1; } }
    else a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(fd, 8) != 0) { close(fd); return -1; }
    return fd;
}

static int connect_client(const vt_config_t *c) {
    int fd = socket(AF_INET, SOCK_STREAM, 0); if (fd < 0) return -1;
    if (c->bind_ip[0]) {
        struct sockaddr_in l; memset(&l, 0, sizeof(l)); l.sin_family = AF_INET; l.sin_port = 0;
        if (inet_pton(AF_INET, c->bind_ip, &l.sin_addr) != 1 || bind(fd, (struct sockaddr *)&l, sizeof(l)) != 0) { close(fd); return -1; }
    }
    struct sockaddr_in r; memset(&r, 0, sizeof(r)); r.sin_family = AF_INET; r.sin_port = htons((uint16_t)c->port);
    if (inet_pton(AF_INET, c->remote_ip, &r.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&r, sizeof(r)) != 0) { close(fd); return -1; }
    set_sock_opts(fd, c); return fd;
}

static ssize_t read_full(int fd, void *buf, size_t len) {
    unsigned char *p = buf; size_t got = 0;
    while (got < len && running) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n == 0) return 0;
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        got += (size_t)n;
    }
    return (ssize_t)got;
}

static int write_full(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf; size_t sent = 0;
    while (sent < len && running) {
        ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        sent += (size_t)n;
    }
    return sent == len ? 0 : -1;
}

static void make_nonce(const unsigned char prefix[4], uint64_t seq, unsigned char nonce[12]) {
    uint64_t nseq = bswap64_u(seq); memcpy(nonce, prefix, 4); memcpy(nonce + 4, &nseq, 8);
}

static int aead_encrypt(const unsigned char key[32], const unsigned char nonce[12], const unsigned char *aad, int aad_len,
                        const unsigned char *plain, int plain_len, unsigned char *cipher, unsigned char tag[TAG_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return -1; int len = 0, out = 0, ok = -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto end;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto end;
    if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto end;
    if (plain_len && EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) != 1) goto end;
    out = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + out, &len) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto end;
    ok = 0;
end: EVP_CIPHER_CTX_free(ctx); return ok;
}

static int aead_decrypt(const unsigned char key[32], const unsigned char nonce[12], const unsigned char *aad, int aad_len,
                        const unsigned char *cipher, int cipher_len, const unsigned char tag[TAG_LEN], unsigned char *plain) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if (!ctx) return -1; int len = 0, out = 0, ok = -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto end;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) goto end;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto end;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto end;
    if (cipher_len && EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len) != 1) goto end;
    out = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) goto end;
    if (EVP_DecryptFinal_ex(ctx, plain + out, &len) != 1) goto end;
    ok = 0;
end: EVP_CIPHER_CTX_free(ctx); return ok;
}

static void put_u32(unsigned char *p, uint32_t v) { v = htonl(v); memcpy(p, &v, 4); }
static uint32_t get_u32(const unsigned char *p) { uint32_t v; memcpy(&v, p, 4); return ntohl(v); }
static void put_u64(unsigned char *p, uint64_t v) { v = bswap64_u(v); memcpy(p, &v, 8); }
static uint64_t get_u64(const unsigned char *p) { uint64_t v; memcpy(&v, p, 8); return bswap64_u(v); }

static int send_frame(int fd, crypto_state_t *st, uint8_t type, const unsigned char *payload, uint32_t len) {
    if (len > MAX_PACKET) return -1;
    unsigned char hdr[HEADER_LEN], nonce[12], tag[TAG_LEN];
    unsigned char *cipher = malloc(len ? len : 1); if (!cipher) return -1;
    uint64_t seq = st->tx_seq++;
    put_u32(hdr, VT_MAGIC); hdr[4] = VT_VERSION; hdr[5] = type; hdr[6] = hdr[7] = 0;
    put_u64(hdr + 8, seq); put_u32(hdr + 16, len); make_nonce(st->tx_nonce_prefix, seq, nonce);
    /* Hide the fixed magic/version/type bytes with a per-session PSK-derived mask.
       Sequence and length remain readable for bounded TCP framing; the static VTCP
       marker is never sent on the wire. The masked header is authenticated as AAD. */
    for (size_t i = 0; i < 8; i++) hdr[i] ^= st->header_mask[i];
    if (aead_encrypt(st->tx_key, nonce, hdr, HEADER_LEN, payload, (int)len, cipher, tag) != 0) { free(cipher); return -1; }
    int rc = write_full(fd, hdr, HEADER_LEN);
    if (rc == 0 && len) rc = write_full(fd, cipher, len);
    if (rc == 0) rc = write_full(fd, tag, TAG_LEN);
    free(cipher); return rc;
}

static int recv_frame(int fd, crypto_state_t *st, uint8_t *type, unsigned char **payload, uint32_t *len) {
    unsigned char hdr[HEADER_LEN], wire_hdr[HEADER_LEN], nonce[12], tag[TAG_LEN];
    ssize_t n = read_full(fd, hdr, HEADER_LEN); if (n <= 0) return -1;
    memcpy(wire_hdr, hdr, HEADER_LEN);
    for (size_t i = 0; i < 8; i++) hdr[i] ^= st->header_mask[i];
    if (get_u32(hdr) != VT_MAGIC || hdr[4] != VT_VERSION) return -1;
    uint64_t seq = get_u64(hdr + 8); uint32_t plen = get_u32(hdr + 16);
    if (plen > MAX_PACKET || seq <= st->rx_seq) return -1;
    unsigned char *cipher = malloc(plen ? plen : 1), *plain = malloc(plen ? plen : 1);
    if (!cipher || !plain) { free(cipher); free(plain); return -1; }
    if (plen && read_full(fd, cipher, plen) != (ssize_t)plen) { free(cipher); free(plain); return -1; }
    if (read_full(fd, tag, TAG_LEN) != TAG_LEN) { free(cipher); free(plain); return -1; }
    make_nonce(st->rx_nonce_prefix, seq, nonce);
    if (aead_decrypt(st->rx_key, nonce, wire_hdr, HEADER_LEN, cipher, (int)plen, tag, plain) != 0) { free(cipher); free(plain); return -1; }
    free(cipher); st->rx_seq = seq; *type = hdr[5]; *payload = plain; *len = plen; return 0;
}

static int session_handshake(int sock, const vt_config_t *cfg, crypto_state_t *st) {
    unsigned char client_nonce[32], server_nonce[32];
    if (!strcmp(cfg->mode, "client")) {
        if (RAND_bytes(client_nonce, sizeof(client_nonce)) != 1) return -1;
        if (write_full(sock, client_nonce, sizeof(client_nonce)) != 0) return -1;
        if (read_full(sock, server_nonce, sizeof(server_nonce)) != (ssize_t)sizeof(server_nonce)) return -1;
    } else {
        if (read_full(sock, client_nonce, sizeof(client_nonce)) != (ssize_t)sizeof(client_nonce)) return -1;
        if (RAND_bytes(server_nonce, sizeof(server_nonce)) != 1) return -1;
        if (write_full(sock, server_nonce, sizeof(server_nonce)) != 0) return -1;
    }
    return crypto_init_state(cfg, client_nonce, server_nonce, st);
}

static int connected_loop(int sock, int tun_fd, const vt_config_t *cfg) {
    crypto_state_t st;
    if (session_handshake(sock, cfg, &st) != 0) return -1;
    time_t last_tx = time(NULL), last_rx = time(NULL);
    while (running) {
        struct pollfd fds[2]; fds[0].fd = tun_fd; fds[0].events = POLLIN; fds[1].fd = sock; fds[1].events = POLLIN;
        int pr = poll(fds, 2, 1000); if (pr < 0) { if (errno == EINTR) continue; return -1; }
        if (fds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
        if (fds[0].revents & POLLIN) {
            unsigned char packet[MAX_PACKET]; ssize_t n = read(tun_fd, packet, sizeof(packet));
            if (n > 0 && send_frame(sock, &st, VT_DATA, packet, (uint32_t)n) != 0) return -1;
            if (n > 0) last_tx = time(NULL);
        }
        if (fds[1].revents & POLLIN) {
            uint8_t type; unsigned char *payload = NULL; uint32_t len = 0;
            if (recv_frame(sock, &st, &type, &payload, &len) != 0) { free(payload); return -1; }
            last_rx = time(NULL);
            if (type == VT_DATA && len > 0) {
                ssize_t w = write(tun_fd, payload, len); free(payload); if (w != (ssize_t)len) return -1;
            } else if (type == VT_PING) {
                free(payload); if (send_frame(sock, &st, VT_PONG, NULL, 0) != 0) return -1; last_tx = time(NULL);
            } else free(payload);
        }
        time_t now = time(NULL);
        if (now - last_tx >= cfg->keepalive) {
            if (send_frame(sock, &st, VT_PING, NULL, 0) != 0) return -1;
            last_tx = now;
        }
        if (now - last_rx > cfg->keepalive * 4 + 5) return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2 || getuid() != 0) return 1;
    vt_config_t cfg; if (load_config(argv[1], &cfg) != 0) { fprintf(stderr, "invalid ViraTCP config\n"); return 1; }
    signal(SIGINT, on_signal); signal(SIGTERM, on_signal); signal(SIGPIPE, SIG_IGN);
    mkdir("/dev/net", 0755);
    if (access(TUN_DEVICE, F_OK) != 0) { int rc = system("mknod /dev/net/tun c 10 200 2>/dev/null || true"); (void)rc; }
    { int rc = system("modprobe tun 2>/dev/null || true"); (void)rc; }
    cleanup_iface(cfg.iface);
    int tun_fd = tun_alloc_named(cfg.iface); if (tun_fd < 0 || configure_tun(&cfg) != 0) { cleanup_iface(cfg.iface); if (tun_fd >= 0) close(tun_fd); return 1; }
    int listener = -1;
    if (!strcmp(cfg.mode, "server")) {
        listener = create_listener(&cfg); if (listener < 0) { perror("ViraTCP listen"); cleanup_iface(cfg.iface); close(tun_fd); return 1; }
        fprintf(stderr, "ViraTCP server listening on %s:%d\n", cfg.bind_ip[0] ? cfg.bind_ip : "0.0.0.0", cfg.port);
    }
    while (running) {
        int sock = -1;
        if (!strcmp(cfg.mode, "client")) {
            sock = connect_client(&cfg);
            if (sock < 0) { sleep((unsigned int)cfg.reconnect); continue; }
            fprintf(stderr, "ViraTCP connected to %s:%d\n", cfg.remote_ip, cfg.port);
        } else {
            struct sockaddr_in peer; socklen_t sl = sizeof(peer); sock = accept(listener, (struct sockaddr *)&peer, &sl);
            if (sock < 0) { if (errno == EINTR) continue; sleep(1); continue; }
            set_sock_opts(sock, &cfg); fprintf(stderr, "ViraTCP accepted client\n");
        }
        connected_loop(sock, tun_fd, &cfg); close(sock);
        if (running) { fprintf(stderr, "ViraTCP connection lost; reconnecting\n"); sleep((unsigned int)cfg.reconnect); }
    }
    if (listener >= 0) close(listener);
    close(tun_fd);
    cleanup_iface(cfg.iface);
    return 0;
}
VIRATCP_ENGINE_EOF
  if ! gcc -O2 -Wall -Wextra -Wno-deprecated-declarations -o "$VIRATCP_BINARY" "$VIRATCP_SOURCE" -lcrypto; then
    echo "Failed to compile ViraTCP engine." >&2
    return 1
  fi
  chmod 755 "$VIRATCP_BINARY"
}

viratcp_write_service_template() {
  cat > "$VIRATCP_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=ViraTCP Encrypted TCP-TUN %i Self-Healing Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=$VIRATCP_BINARY $VIRATCP_CONFIG_DIR/tunnel-%i.conf
Restart=always
RestartSec=2
TimeoutStopSec=10
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  systemctl daemon-reload >/dev/null 2>&1 || true
}

viratcp_save_config() {
  mkdir -p "$VIRATCP_CONFIG_DIR"
  local file; file="$(viratcp_config_file "$TUNNEL_ID")"
  cat > "$file" <<EOF_CONF
TUNNEL_TYPE=viratcp
TUNNEL_ID=$TUNNEL_ID
ROLE=$ROLE
VIRATCP_IFACE=$VIRATCP_IFACE
VIRATCP_MODE=$VIRATCP_MODE
LOCAL_PUBLIC_IP=$LOCAL_PUBLIC_IP
REMOTE_PUBLIC_IP=$REMOTE_PUBLIC_IP
LOCAL_VIRATCP_IP=$LOCAL_VIRATCP_IP
REMOTE_VIRATCP_IP=$REMOTE_VIRATCP_IP
VIRATCP_PORT=$VIRATCP_PORT
VIRATCP_MTU=$VIRATCP_MTU
VIRATCP_PSK=$VIRATCP_PSK
VIRATCP_KEEPALIVE=${VIRATCP_KEEPALIVE:-$VIRATCP_DEFAULT_KEEPALIVE}
VIRATCP_RECONNECT=${VIRATCP_RECONNECT:-$VIRATCP_DEFAULT_RECONNECT}
VIRATCP_TCP_USER_TIMEOUT=${VIRATCP_TCP_USER_TIMEOUT:-$VIRATCP_DEFAULT_TCP_USER_TIMEOUT}

iface=$VIRATCP_IFACE
mode=$VIRATCP_MODE
bind_ip=$LOCAL_PUBLIC_IP
remote_ip=$REMOTE_PUBLIC_IP
local_priv=$LOCAL_VIRATCP_IP
remote_priv=$REMOTE_VIRATCP_IP
port=$VIRATCP_PORT
mtu=$VIRATCP_MTU
psk=$VIRATCP_PSK
keepalive=${VIRATCP_KEEPALIVE:-$VIRATCP_DEFAULT_KEEPALIVE}
reconnect=${VIRATCP_RECONNECT:-$VIRATCP_DEFAULT_RECONNECT}
tcp_user_timeout=${VIRATCP_TCP_USER_TIMEOUT:-$VIRATCP_DEFAULT_TCP_USER_TIMEOUT}
queue_len=2000
EOF_CONF
  chmod 600 "$file"
  echo "Saved ViraTCP tunnel $TUNNEL_ID configuration to $file"
}

viratcp_load_config() {
  local id="${1:-${TUNNEL_ID:-}}" file
  validate_tunnel_id "$id" || return 1
  file="$(viratcp_config_file "$id")"; [ -f "$file" ] || return 1
  VIRATCP_IFACE=""; VIRATCP_MODE=""; ROLE=""; LOCAL_PUBLIC_IP=""; REMOTE_PUBLIC_IP=""
  LOCAL_VIRATCP_IP=""; REMOTE_VIRATCP_IP=""; VIRATCP_PORT=""; VIRATCP_MTU=""; VIRATCP_PSK=""
  # shellcheck disable=SC1090
  source "$file"
  TUNNEL_ID="$id"
  VIRATCP_IFACE="${VIRATCP_IFACE:-${iface:-$(viratcp_iface_name "$id")}}"
  VIRATCP_MODE="${VIRATCP_MODE:-${mode:-client}}"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
  REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
  LOCAL_VIRATCP_IP="${LOCAL_VIRATCP_IP:-${local_priv:-}}"
  REMOTE_VIRATCP_IP="${REMOTE_VIRATCP_IP:-${remote_priv:-}}"
  VIRATCP_PORT="${VIRATCP_PORT:-${port:-$VIRATCP_DEFAULT_PORT}}"
  VIRATCP_MTU="${VIRATCP_MTU:-${mtu:-$VIRATCP_DEFAULT_MTU}}"
  VIRATCP_PSK="${VIRATCP_PSK:-${psk:-}}"
  VIRATCP_KEEPALIVE="${VIRATCP_KEEPALIVE:-${keepalive:-$VIRATCP_DEFAULT_KEEPALIVE}}"
  VIRATCP_RECONNECT="${VIRATCP_RECONNECT:-${reconnect:-$VIRATCP_DEFAULT_RECONNECT}}"
  VIRATCP_TCP_USER_TIMEOUT="${VIRATCP_TCP_USER_TIMEOUT:-${tcp_user_timeout:-$VIRATCP_DEFAULT_TCP_USER_TIMEOUT}}"
  if [ -z "${ROLE:-}" ]; then if [ "$LOCAL_VIRATCP_IP" = "10.81.$id.1" ]; then ROLE="1"; else ROLE="2"; fi; fi
}

viratcp_apply_firewall_rules() {
  local id="$1" listen_mode=0
  viratcp_load_config "$id" || return 1
  [ "$VIRATCP_MODE" = "server" ] && listen_mode=1
  enable_ip_forward
  ensure_public_endpoint_route "$REMOTE_PUBLIC_IP" "$LOCAL_PUBLIC_IP"
  firewall_allow_tcp_port_and_ip "ViraTCP tunnel $id" "$VIRATCP_PORT" "$REMOTE_PUBLIC_IP" "$VIRATCP_IFACE" "$listen_mode"
  firewall_allow_ip_peer "ViraTCP tunnel $id remote inner" "$REMOTE_VIRATCP_IP" "$VIRATCP_IFACE"
}

viratcp_install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  validate_tunnel_id "$id" || return 1
  command -v systemctl >/dev/null 2>&1 || return 1
  viratcp_compile_engine || return 1
  install_manager_binary || { echo "Failed to install manager binary" >&2; return 1; }
  viratcp_write_service_template
  install_health_monitor
  systemctl enable "$(viratcp_service_name "$id")" >/dev/null || return 1
  if systemctl restart "$(viratcp_service_name "$id")"; then
    echo "ViraTCP service enabled and started ($(viratcp_service_name "$id"))"
    return 0
  fi
  systemctl status "$(viratcp_service_name "$id")" --no-pager -l 2>/dev/null || true
  journalctl -u "$(viratcp_service_name "$id")" -n 40 --no-pager 2>/dev/null || true
  return 1
}

viratcp_create_tunnel() {
  validate_tunnel_id "${TUNNEL_ID:-}" || { echo "Invalid tunnel number." >&2; return 1; }
  VIRATCP_IFACE="$(viratcp_iface_name "$TUNNEL_ID")"
  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  local_ipv4_is_assigned "$LOCAL_PUBLIC_IP" || { echo "Selected ViraTCP local IP is not assigned: $LOCAL_PUBLIC_IP" >&2; return 1; }
  if [ "$ROLE" = "1" ]; then
    SERVER_ROLE="IRAN"; VIRATCP_MODE="client"; LOCAL_VIRATCP_IP="10.81.$TUNNEL_ID.1"; REMOTE_VIRATCP_IP="10.81.$TUNNEL_ID.2"
  else
    SERVER_ROLE="KHAREJ"; VIRATCP_MODE="server"; LOCAL_VIRATCP_IP="10.81.$TUNNEL_ID.2"; REMOTE_VIRATCP_IP="10.81.$TUNNEL_ID.1"
  fi
  VIRATCP_PORT="${VIRATCP_PORT:-$VIRATCP_DEFAULT_PORT}"
  VIRATCP_MTU="${VIRATCP_MTU:-$VIRATCP_DEFAULT_MTU}"
  VIRATCP_KEEPALIVE="${VIRATCP_KEEPALIVE:-$VIRATCP_DEFAULT_KEEPALIVE}"
  VIRATCP_RECONNECT="${VIRATCP_RECONNECT:-$VIRATCP_DEFAULT_RECONNECT}"
  VIRATCP_TCP_USER_TIMEOUT="${VIRATCP_TCP_USER_TIMEOUT:-$VIRATCP_DEFAULT_TCP_USER_TIMEOUT}"
  viratcp_validate_psk "$VIRATCP_PSK" || { echo "Invalid ViraTCP PSK; it must be exactly 64 hexadecimal characters." >&2; return 1; }

  echo "[*] Local server public IP: $LOCAL_PUBLIC_IP"
  echo "[*] Tunnel type: ViraTCP encrypted TCP-TUN"
  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $VIRATCP_IFACE"
  echo "[*] Server role: $SERVER_ROLE ($VIRATCP_MODE)"
  echo "[*] Remote server public IP: $REMOTE_PUBLIC_IP"
  echo "[*] Local ViraTCP IP: $LOCAL_VIRATCP_IP"
  echo "[*] Remote ViraTCP IP: $REMOTE_VIRATCP_IP"
  echo "[*] TCP port: $VIRATCP_PORT"
  echo "[*] MTU: $VIRATCP_MTU"
  echo "[*] Encryption: AES-256-GCM with pre-shared key"

  modprobe tun || true
  enable_ip_forward
  viratcp_compile_engine || return 1
  viratcp_save_config
  viratcp_apply_firewall_rules "$TUNNEL_ID" || true
  viratcp_install_service "$TUNNEL_ID"
}

viratcp_menu_config_tunnel() {
  show_header "Configure Reverse ViraTCP Encrypted TCP-TUN"
  echo "Iran opens one persistent outbound TCP tunnel; Kharej listens on the selected TCP port."
  echo "The L3 tunnel carries both TCP and UDP payloads without a per-forwarder handshake."
  echo "ViraTCP wire format v2 requires GRE-TUN v9.0.0 on BOTH servers."
  echo "Use the exact same port and 64-character PSK on both servers."
  echo
  prompt_role || return
  local selected_role existing_local_ip="" existing_remote_ip="" existing_port="" existing_mtu="" existing_psk="" input
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter ViraTCP tunnel number before IP [1-254]: " || return
  if viratcp_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"; existing_remote_ip="${REMOTE_PUBLIC_IP:-}"; existing_port="${VIRATCP_PORT:-}"
    existing_mtu="${VIRATCP_MTU:-}"; existing_psk="${VIRATCP_PSK:-}"
  fi
  ROLE="$selected_role"
  echo
  echo "ViraTCP tunnel $TUNNEL_ID plan:"
  echo "  Interface       : $(viratcp_iface_name "$TUNNEL_ID")"
  echo "  Config file     : $(viratcp_config_file "$TUNNEL_ID")"
  echo "  Service         : $(viratcp_service_name "$TUNNEL_ID")"
  echo "  Iran role       : client / 10.81.$TUNNEL_ID.1"
  echo "  Kharej role     : server / 10.81.$TUNNEL_ID.2"
  echo
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for ViraTCP" || return
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return
  echo
  read -rp "Enter ViraTCP TCP port [${existing_port:-$VIRATCP_DEFAULT_PORT}] (00=menu): " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  VIRATCP_PORT="${input:-${existing_port:-$VIRATCP_DEFAULT_PORT}}"
  validate_port "$VIRATCP_PORT" || { echo "Invalid TCP port."; return; }
  if [ "$ROLE" = "2" ] && [ "$VIRATCP_PORT" != "${existing_port:-}" ] && command -v ss >/dev/null 2>&1 && ss -H -ltn "sport = :$VIRATCP_PORT" 2>/dev/null | grep -q .; then
    warn_msg "TCP port $VIRATCP_PORT is already listening on this Kharej server. Choose another unused port, or stop the current service first."
    return 1
  fi
  read -rp "Enter ViraTCP MTU [${existing_mtu:-$VIRATCP_DEFAULT_MTU}] (00=menu): " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  VIRATCP_MTU="${input:-${existing_mtu:-$VIRATCP_DEFAULT_MTU}}"
  [[ "$VIRATCP_MTU" =~ ^[0-9]+$ ]] && [ "$VIRATCP_MTU" -ge 576 ] && [ "$VIRATCP_MTU" -le 1500 ] || { echo "Invalid MTU."; return 1; }
  echo
  if [ -n "$existing_psk" ]; then
    read -rp "ViraTCP PSK [press Enter to keep existing, or paste a new 64-hex key] (00=menu): " input
    if is_main_menu_token "$input"; then return_main_msg; return 99; fi
    VIRATCP_PSK="${input:-$existing_psk}"
  else
    read -rp "Paste the SAME 64-hex PSK used on the other server, or press Enter to generate one (00=menu): " input
    if is_main_menu_token "$input"; then return_main_msg; return 99; fi
    VIRATCP_PSK="${input:-$(viratcp_generate_psk)}"
  fi
  viratcp_validate_psk "$VIRATCP_PSK" || { echo "Invalid PSK. Use exactly 64 hexadecimal characters."; return 1; }
  echo
  echo -e "${C_YELLOW}${C_BOLD}ViraTCP PSK (copy this exact value to the other server):${C_RESET}"
  echo "$VIRATCP_PSK"
  echo
  viratcp_create_tunnel || echo "ViraTCP tunnel creation failed"
}

viratcp_collect_ids() {
  {
    if [ -d "$VIRATCP_CONFIG_DIR" ]; then
      local f id
      for f in "$VIRATCP_CONFIG_DIR"/tunnel-*.conf; do
        [ -e "$f" ] || continue; id="${f##*/tunnel-}"; id="${id%.conf}"; validate_tunnel_id "$id" && echo "$id"
      done
    fi
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${VIRATCP_IFACE_PREFIX}[0-9]+$" | sed "s/^${VIRATCP_IFACE_PREFIX}//" | awk '$1 >= 1 && $1 <= 254' || true
  } | sort -n -u
}

viratcp_list_tunnels() {
  echo "ViraTCP encrypted TCP-TUN tunnels:"
  local ids id ifc state mode port
  ids="$(viratcp_collect_ids || true)"; [ -n "$ids" ] || { echo "  none"; return 0; }
  while IFS= read -r id; do
    [ -n "$id" ] || continue; ifc="$(viratcp_iface_name "$id")"; state="inactive"; mode="unknown"; port="unknown"
    tunnel_iface_is_up "$ifc" && state="active"
    if viratcp_load_config "$id"; then mode="${VIRATCP_MODE:-unknown}"; port="${VIRATCP_PORT:-unknown}"; fi
    echo "  - tunnel $id | iface $ifc | $state | mode: $mode | TCP: $port | config: $(viratcp_config_file "$id") | service: $(systemctl is-enabled "$(viratcp_service_name "$id")" 2>/dev/null || true)"
  done <<< "$ids"
}

viratcp_remove_one_tunnel() {
  local id="$1" ifc file port mode
  ifc="$(viratcp_iface_name "$id")"; file="$(viratcp_config_file "$id")"; port=""; mode=""
  if viratcp_load_config "$id"; then port="${VIRATCP_PORT:-}"; mode="${VIRATCP_MODE:-}"; fi
  echo "Removing ViraTCP tunnel $id ($ifc)..."
  systemctl disable --now "$(viratcp_service_name "$id")" 2>/dev/null || true
  ip link delete "$ifc" 2>/dev/null || true
  if [ "$mode" = "server" ] && [ -n "$port" ] && command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport "$port" -j ACCEPT || break; done
  fi
  rm -f "$file"
  systemctl daemon-reload >/dev/null 2>&1 || true
  echo "[OK] ViraTCP tunnel $id removed."
}

viratcp_restart_one_tunnel() {
  local id="$1"
  viratcp_load_config "$id" || return 1
  viratcp_compile_engine || return 1
  viratcp_write_service_template
  viratcp_apply_firewall_rules "$id" >/dev/null 2>&1 || true
  systemctl enable "$(viratcp_service_name "$id")" >/dev/null 2>&1 || true
  systemctl restart "$(viratcp_service_name "$id")"
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
    if tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
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
    if tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
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
    if tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
    INV_TYPE+=("vira7"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
  done <<< "$ids"

  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(viratcp_iface_name "$id")"
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="ViraTCP encrypted TCP-TUN"
    if viratcp_load_config "$id"; then
      local_ip="${LOCAL_VIRATCP_IP:-${local_priv:-}}"
      target="${REMOTE_VIRATCP_IP:-${remote_priv:-}}"
      local_pub="${LOCAL_PUBLIC_IP:-${bind_ip:-}}"
      remote_pub="${REMOTE_PUBLIC_IP:-${remote_ip:-}}"
    fi
    if tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
    INV_TYPE+=("viratcp"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
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
    viratcp) viratcp_remove_one_tunnel "$id" ;;
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
    viratcp) test_viratcp_tunnel_ping "$id" ;;
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

  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if viratcp_load_config "$id"; then
      ifc="$(viratcp_iface_name "$id")"
      viratcp_apply_firewall_rules "$id" >/dev/null 2>&1 || true
      svc="$(viratcp_service_name "$id")"
      if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$svc" 2>/dev/null && ! tunnel_iface_is_up "$ifc"; then
        warn_msg "Remaining ViraTCP tunnel $id is enabled but inactive; restarting only this tunnel."
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
    viratcp) viratcp_menu_config_tunnel ;;
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
    echo -e "${C_RED}${C_BOLD}WARNING:${C_RESET} this will remove ALL GRE, WireGuard, Vira7, and ViraTCP tunnels."
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
    ids="$(viratcp_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && viratcp_remove_one_tunnel "$id"; done <<< "$ids"
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
  for phase in wireguard vira7 viratcp gre; do
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
  echo
  viratcp_list_tunnels
}

ping4_target() {
  local label="$1"
  local target_ip="$2"
  local bind_if="${3:-}"
  if [ -z "${target_ip:-}" ]; then
    echo "[SKIP] $label: remote IP is empty"
    return 1
  fi
  target_ip="${target_ip%%/*}"
  echo
  echo "============================================================"
  echo "Testing: $label"
  echo "Target : $target_ip"
  if [ -n "$bind_if" ]; then
    echo "Command: ping -I $bind_if -c 4 -W 2 $target_ip"
  else
    echo "Command: ping -c 4 -W 2 $target_ip"
  fi
  echo "------------------------------------------------------------"
  if [ -n "$bind_if" ]; then
    if ping -I "$bind_if" -c 4 -W 2 "$target_ip"; then
      echo "[OK] $label ping success"
      return 0
    fi
  else
    if ping -c 4 -W 2 "$target_ip"; then
      echo "[OK] $label ping success"
      return 0
    fi
  fi
  echo "[FAIL] $label ping failed"
  return 1
}

test_gre_tunnel_ping() {
  local id="$1" ifc svc
  if ! gre_load_config "$id"; then
    echo "[SKIP] GRE tunnel $id: no saved config"
    return 1
  fi
  local target="${REMOTE_GRE_IP:-}"
  if [ -z "$target" ] && [ -n "${ROLE:-}" ]; then
    target="$(gre_remote_inner_ip_for_role "$id" "$ROLE")"
  fi
  ifc="$(gre_iface "$id")"
  svc="$(gre_service_name "$id")"
  if ! tunnel_iface_is_up "$ifc"; then
    echo "[REPAIR] $ifc is inactive; restarting its self-healing service..."
    if command -v systemctl >/dev/null 2>&1; then
      systemctl restart "$svc" >/dev/null 2>&1 || gre_service_start "$id" || true
    else
      gre_service_start "$id" || true
    fi
    sleep 2
  fi
  ping4_target "GRE tunnel $id ($ifc) remote inner IP" "$target" "$ifc"
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
  ping4_target "WireGuard tunnel $id ($(wg_iface_name "$id")) remote inner IP" "${REMOTE_WG_IP:-}" "$(wg_iface_name "$id")"
}

test_vira7_tunnel_ping() {
  local id="$1"
  if ! vira7_load_config "$id"; then
    echo "[SKIP] Vira7 tunnel $id: no saved config"
    return 1
  fi
  ping4_target "Vira7 tunnel $id ($(vira7_iface_name "$id")) remote inner IP" "${REMOTE_VIRA7_IP:-${remote_priv:-}}" "$(vira7_iface_name "$id")"
}

test_viratcp_tunnel_ping() {
  local id="$1" ifc svc
  if ! viratcp_load_config "$id"; then
    echo "[SKIP] ViraTCP tunnel $id: no saved config"
    return 1
  fi
  ifc="$(viratcp_iface_name "$id")"; svc="$(viratcp_service_name "$id")"
  if ! tunnel_iface_is_up "$ifc"; then
    echo "[REPAIR] $ifc is inactive; restarting ViraTCP service..."
    systemctl restart "$svc" >/dev/null 2>&1 || true
    sleep 2
  fi
  ping4_target "ViraTCP tunnel $id ($ifc) remote inner IP" "${REMOTE_VIRATCP_IP:-${remote_priv:-}}" "$ifc"
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
    viratcp) test_viratcp_tunnel_ping "$TUNNEL_ID" ;;
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
  echo "Testing all saved ViraTCP tunnels..."
  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    total=$((total + 1))
    if test_viratcp_tunnel_ping "$id"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
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
  echo "This will restart/recreate all saved GRE, WireGuard, Vira7, and ViraTCP tunnels from their saved configs."
  echo "It will also re-enable their systemd services for boot."
  echo
  if ! confirm_yes "Continue with reset all tunnels?"; then
    echo "Cancelled."
    return
  fi

  echo
  echo "Stopping WireGuard, Vira7, and ViraTCP first..."
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

  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl stop "$(viratcp_service_name "$id")" 2>/dev/null || true
    ip link delete "$(viratcp_iface_name "$id")" 2>/dev/null || true
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
  echo "Starting ViraTCP tunnels..."
  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if viratcp_restart_one_tunnel "$id"; then
      echo "[OK] ViraTCP tunnel $id reset"
    else
      echo "[WARN] ViraTCP tunnel $id reset failed"
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
# v8.8.x HAProxy additions:
# - add/update multiple ports in one step (comma or whitespace separated)
# - choose a target from the unified tunnel inventory or enter a custom IPv4
# - explicit HTTP vs TCP selection
# - TCP forwards automatically receive matching UDP DNAT/SNAT/FORWARD rules
# - UDP rules live in dedicated iptables chains and are rebuilt from HAProxy state
# - changing TCP <-> HTTP, deleting a port, or changing its target automatically
#   adds/removes/updates the managed UDP forwarding rules
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

# Convert "2086 443 2052" or "2086,443,2052" (or a mixture) into HAP_PORTS[].
# Duplicate ports are removed while preserving the first occurrence.
haproxy_parse_port_list() {
  local raw="${1:-}" token
  local -A seen=()
  HAP_PORTS=()
  raw="${raw//,/ }"
  for token in $raw; do
    validate_port "$token" || { err_msg "Invalid port: $token"; return 1; }
    if [ -z "${seen[$token]+x}" ]; then
      HAP_PORTS+=("$token")
      seen[$token]=1
    fi
  done
  [ "${#HAP_PORTS[@]}" -gt 0 ] || { err_msg "No valid port was entered."; return 1; }
}

haproxy_prompt_protocol() {
  local input
  echo -e "${C_BOLD}${C_WHITE}Forward protocol:${C_RESET}"
  echo -e "  ${C_YELLOW}1)${C_RESET} TCP  ${C_DIM}(HAProxy TCP + automatic UDP forward; recommended for Shadowsocks/raw TCP)${C_RESET}"
  echo -e "  ${C_CYAN}2)${C_RESET} HTTP ${C_DIM}(HAProxy HTTP/WebSocket only; managed UDP rules are removed)${C_RESET}"
  echo
  read -rp "Choose protocol [1=tcp, 2=http] (00=menu): " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  case "$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]')" in
    1|tcp|t) HAP_SELECTED_PROTO="tcp" ;;
    2|http|h) HAP_SELECTED_PROTO="http" ;;
    *) err_msg "Invalid protocol selection."; return 1 ;;
  esac
}

haproxy_target_inventory() {
  build_tunnel_inventory
  local count="${#INV_TYPE[@]}"
  [ "$count" -gt 0 ] || return 1

  echo -e "${C_BOLD}${C_WHITE}Available tunnel targets:${C_RESET}"
  printf "${C_DIM}%4s  %-11s %-10s %-15s %-15s %-15s %-15s %-8s${C_RESET}\n" \
    "No" "Type" "Interface" "Local-Tun" "Remote-Tun" "Local-Pub" "Remote-Pub" "State"
  printf "${C_DIM}%s${C_RESET}\n" "------------------------------------------------------------------------------------------------------------------"

  local i idx type ifc local_tun remote_tun local_pub remote_pub state color
  for i in "${!INV_TYPE[@]}"; do
    idx=$((i + 1))
    type="${INV_TYPE[$i]}"
    ifc="${INV_IFACE[$i]:-N/A}"
    local_tun="${INV_LOCAL[$i]:-N/A}"; local_tun="${local_tun%%/*}"
    remote_tun="${INV_TARGET[$i]:-N/A}"; remote_tun="${remote_tun%%/*}"
    local_pub="${INV_LOCAL_PUBLIC[$i]:-N/A}"
    remote_pub="${INV_REMOTE_PUBLIC[$i]:-N/A}"
    state="${INV_STATE[$i]:-unknown}"
    if [ "$state" = "active" ]; then color="$C_GREEN"; else color="$C_YELLOW"; fi
    printf "%4s  %-11s %-10s %-15s %-15s %-15s %-15s ${color}%-8s${C_RESET}\n" \
      "$idx" "$type" "$ifc" "$local_tun" "$remote_tun" "$local_pub" "$remote_pub" "$state"
  done
  echo
}

# Sets HAP_TARGET_IP. The operator may choose a numbered tunnel row or type any IPv4.
haproxy_prompt_target_ip() {
  local prompt_label="${1:-Select target tunnel number or enter target IPv4}"
  local input idx count target

  build_tunnel_inventory
  count="${#INV_TYPE[@]}"
  if [ "$count" -gt 0 ]; then
    haproxy_target_inventory || true
    echo "Choose a row number to use its Remote-Tun address, or type a custom IPv4 exactly as before."
  else
    warn_msg "No managed tunnel was found. You can still enter a target IPv4 manually."
  fi

  read -rp "$prompt_label (00=menu): " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi

  if validate_ipv4 "$input"; then
    HAP_TARGET_IP="$input"
    return 0
  fi

  if [[ "$input" =~ ^[0-9]+$ ]] && [ "$input" -ge 1 ] && [ "$input" -le "$count" ]; then
    idx=$((input - 1))
    target="${INV_TARGET[$idx]:-}"
    target="${target%%/*}"
    if ! validate_ipv4 "$target"; then
      err_msg "Selected tunnel does not have a valid remote tunnel IPv4."
      return 1
    fi
    HAP_TARGET_IP="$target"
    info_msg "Selected ${INV_TYPE[$idx]} ${INV_IFACE[$idx]} -> $HAP_TARGET_IP"
    return 0
  fi

  err_msg "Invalid selection/IP: $input"
  return 1
}

# -----------------------------
# Managed UDP companion forwarding for TCP HAProxy rows
# -----------------------------
# HAProxy itself forwards TCP/HTTP only. For TCP rows (e.g. Shadowsocks), UDP
# on the same public port is forwarded at L3 with the exact direct DNAT/SNAT/
# FORWARD rules that are known to work with GRE. v8.8.0 used intermediate
# custom chains; some hosts/firewall stacks did not reliably traverse those
# jumps. v8.8.1 writes only our own commented rules directly into the built-in
# chains and removes only rules carrying the gretun-hap-udp-* marker.
HAP_UDP_PRE_CHAIN="GRETUN_HAP_UDP_PRE"       # legacy v8.8.0 migration only
HAP_UDP_POST_CHAIN="GRETUN_HAP_UDP_POST"     # legacy v8.8.0 migration only
HAP_UDP_FWD_CHAIN="GRETUN_HAP_UDP_FWD"       # legacy v8.8.0 migration only

# Resolve the tunnel/uplink interface and local source IP for a target.
# Prefer the saved tunnel inventory, then fall back to the kernel route lookup
# so manually-entered target IPs continue to work exactly like before.
haproxy_udp_resolve_path() {
  local target="$1" i inv_target route
  HAP_UDP_IFACE=""
  HAP_UDP_LOCAL_IP=""

  build_tunnel_inventory
  for i in "${!INV_TYPE[@]}"; do
    inv_target="${INV_TARGET[$i]:-}"; inv_target="${inv_target%%/*}"
    if [ "$inv_target" = "$target" ]; then
      HAP_UDP_IFACE="${INV_IFACE[$i]:-}"
      HAP_UDP_LOCAL_IP="${INV_LOCAL[$i]:-}"; HAP_UDP_LOCAL_IP="${HAP_UDP_LOCAL_IP%%/*}"
      if [ -n "$HAP_UDP_IFACE" ] && validate_ipv4 "$HAP_UDP_LOCAL_IP"; then
        return 0
      fi
    fi
  done

  route="$(ip -4 route get "$target" 2>/dev/null | head -n 1 || true)"
  HAP_UDP_IFACE="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
  HAP_UDP_LOCAL_IP="$(awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' <<< "$route")"

  [ -n "$HAP_UDP_IFACE" ] && validate_ipv4 "$HAP_UDP_LOCAL_IP"
}

# Remove one exact rule repeatedly. This also adopts/removes an equivalent
# un-commented rule that may have been added manually while troubleshooting.
haproxy_udp_delete_exact_rule() {
  local table="$1" chain="$2"
  shift 2
  if [ "$table" = "filter" ]; then
    while iptables -w 5 -C "$chain" "$@" 2>/dev/null; do
      iptables -w 5 -D "$chain" "$@" 2>/dev/null || break
    done
  else
    while iptables -w 5 -t "$table" -C "$chain" "$@" 2>/dev/null; do
      iptables -w 5 -t "$table" -D "$chain" "$@" 2>/dev/null || break
    done
  fi
}

# Remove only rules tagged by this script from a built-in chain. Deletion is
# done by line number in descending order so unrelated rules keep their order.
haproxy_udp_delete_commented_rules() {
  local table="$1" chain="$2" marker="$3" n
  local -a nums=()
  if [ "$table" = "filter" ]; then
    mapfile -t nums < <(iptables -w 5 -L "$chain" --line-numbers -n 2>/dev/null | awk -v m="$marker" 'index($0,m){print $1}' | sort -rn)
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] && iptables -w 5 -D "$chain" "$n" 2>/dev/null || true
    done
  else
    mapfile -t nums < <(iptables -w 5 -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v m="$marker" 'index($0,m){print $1}' | sort -rn)
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] && iptables -w 5 -t "$table" -D "$chain" "$n" 2>/dev/null || true
    done
  fi
}

# Clean the v8.8.0 custom-chain implementation. These chain names are private
# to GRE-TUN, so deleting their jumps/chains does not touch user firewall rules.
haproxy_udp_cleanup_legacy_chains() {
  command -v iptables >/dev/null 2>&1 || return 0

  while iptables -w 5 -t nat -C PREROUTING -p udp -j "$HAP_UDP_PRE_CHAIN" 2>/dev/null; do
    iptables -w 5 -t nat -D PREROUTING -p udp -j "$HAP_UDP_PRE_CHAIN" 2>/dev/null || break
  done
  while iptables -w 5 -t nat -C POSTROUTING -p udp -j "$HAP_UDP_POST_CHAIN" 2>/dev/null; do
    iptables -w 5 -t nat -D POSTROUTING -p udp -j "$HAP_UDP_POST_CHAIN" 2>/dev/null || break
  done
  while iptables -w 5 -C FORWARD -p udp -j "$HAP_UDP_FWD_CHAIN" 2>/dev/null; do
    iptables -w 5 -D FORWARD -p udp -j "$HAP_UDP_FWD_CHAIN" 2>/dev/null || break
  done

  iptables -w 5 -t nat -F "$HAP_UDP_PRE_CHAIN" 2>/dev/null || true
  iptables -w 5 -t nat -X "$HAP_UDP_PRE_CHAIN" 2>/dev/null || true
  iptables -w 5 -t nat -F "$HAP_UDP_POST_CHAIN" 2>/dev/null || true
  iptables -w 5 -t nat -X "$HAP_UDP_POST_CHAIN" 2>/dev/null || true
  iptables -w 5 -F "$HAP_UDP_FWD_CHAIN" 2>/dev/null || true
  iptables -w 5 -X "$HAP_UDP_FWD_CHAIN" 2>/dev/null || true
}

# Flush only GRE-TUN managed direct companion rules. No other DNAT/SNAT/FORWARD
# entries are touched.
haproxy_udp_flush_managed_rules() {
  command -v iptables >/dev/null 2>&1 || return 0
  haproxy_udp_cleanup_legacy_chains
  haproxy_udp_delete_commented_rules nat PREROUTING  'gretun-hap-udp-pre-'
  haproxy_udp_delete_commented_rules nat POSTROUTING 'gretun-hap-udp-post-'
  haproxy_udp_delete_commented_rules filter FORWARD  'gretun-hap-udp-'
}

# Remove an exact companion set first. Besides preventing duplicates, this
# migrates the same four un-commented rules that were previously added by hand.
haproxy_udp_remove_equivalent_rules() {
  local port="$1" target="$2" tport="$3" ifc="$4" local_ip="$5"

  haproxy_udp_delete_exact_rule nat PREROUTING \
    -p udp --dport "$port" \
    -j DNAT --to-destination "$target:$tport"

  haproxy_udp_delete_exact_rule nat POSTROUTING \
    -o "$ifc" -p udp -d "$target" --dport "$tport" \
    -j SNAT --to-source "$local_ip"

  haproxy_udp_delete_exact_rule filter FORWARD \
    -o "$ifc" -p udp -d "$target" --dport "$tport" \
    -j ACCEPT

  haproxy_udp_delete_exact_rule filter FORWARD \
    -i "$ifc" -p udp -s "$target" --sport "$tport" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -j ACCEPT
}

haproxy_udp_add_rule() {
  local port="$1" target="$2" tport="$3" ifc="$4" local_ip="$5"

  # Use direct built-in-chain rules, matching the proven manual fix.
  iptables -w 5 -t nat -I PREROUTING 1 \
    -p udp --dport "$port" \
    -m comment --comment "gretun-hap-udp-pre-$port" \
    -j DNAT --to-destination "$target:$tport"

  iptables -w 5 -t nat -I POSTROUTING 1 \
    -o "$ifc" -p udp -d "$target" --dport "$tport" \
    -m comment --comment "gretun-hap-udp-post-$port" \
    -j SNAT --to-source "$local_ip"

  iptables -w 5 -I FORWARD 1 \
    -o "$ifc" -p udp -d "$target" --dport "$tport" \
    -m comment --comment "gretun-hap-udp-out-$port" \
    -j ACCEPT

  iptables -w 5 -I FORWARD 1 \
    -i "$ifc" -p udp -s "$target" --sport "$tport" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "gretun-hap-udp-back-$port" \
    -j ACCEPT
}

haproxy_sync_udp_rules() {
  command -v iptables >/dev/null 2>&1 || {
    warn_msg "iptables is not available; HAProxy TCP/HTTP works, but automatic UDP forwarding cannot be configured."
    return 0
  }

  enable_ip_forward
  haproxy_udp_flush_managed_rules

  local entries port target tport proto count=0 skipped=0
  entries="$(haproxy_export_entries || true)"
  [ -n "$entries" ] || { info_msg "Managed HAProxy UDP rules: none"; return 0; }

  # First remove an exact un-commented manual companion, if one exists for the
  # current row/target. This lets v8.8.1 take ownership without duplicates.
  while read -r port target tport proto; do
    [ -n "${port:-}" ] || continue
    if haproxy_udp_resolve_path "$target"; then
      haproxy_udp_remove_equivalent_rules "$port" "$target" "$tport" "$HAP_UDP_IFACE" "$HAP_UDP_LOCAL_IP"
    fi
  done <<< "$entries"

  # Then create companions only for TCP rows. HTTP rows therefore have no UDP
  # rule; toggling TCP -> HTTP removes UDP automatically on this same sync.
  while read -r port target tport proto; do
    [ -n "${port:-}" ] || continue
    proto="$(haproxy_normalize_proto "${proto:-http}")"
    [ "$proto" = "tcp" ] || continue

    if ! haproxy_udp_resolve_path "$target"; then
      warn_msg "UDP companion skipped for port $port: cannot resolve route/local source for target $target."
      skipped=$((skipped + 1))
      continue
    fi

    haproxy_udp_add_rule "$port" "$target" "$tport" "$HAP_UDP_IFACE" "$HAP_UDP_LOCAL_IP"
    count=$((count + 1))
  done <<< "$entries"

  if [ "$count" -gt 0 ]; then
    ok_msg "Managed UDP forwarding synced for $count TCP HAProxy port(s) using direct iptables rules."
  else
    info_msg "Managed HAProxy UDP rules: none (no TCP forwards)."
  fi
  [ "$skipped" -eq 0 ] || warn_msg "$skipped UDP forward(s) were skipped because their route could not be resolved."
}

haproxy_install_udp_service() {
  command -v systemctl >/dev/null 2>&1 || return 0
  install_manager_binary >/dev/null 2>&1 || true
  [ -s "$INSTALL_BIN" ] || return 0

  # Boot-time sync service kept exactly as before.
  cat > "$HAPROXY_UDP_SERVICE_UNIT" <<EOF_UDP_SERVICE
[Unit]
Description=GRE-TUN managed UDP companions for HAProxy TCP forwards
After=network-online.target haproxy.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service haproxy-udp-sync
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_UDP_SERVICE

  # v8.8.3: non-interactive equivalent of HAProxy menu option 8.
  # It uses the existing haproxy_repair_udp() function, so no HAProxy rows,
  # target IPs, tunnel definitions, or unrelated firewall rules are modified.
  cat > "$HAPROXY_UDP_REPAIR_SERVICE_UNIT" <<EOF_UDP_REPAIR_SERVICE
[Unit]
Description=GRE-TUN HAProxy UDP automatic repair (same as menu option 8)
After=network-online.target haproxy.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service haproxy-udp-repair
TimeoutStartSec=90
EOF_UDP_REPAIR_SERVICE

  # Force one full repair every hour. The 20-second health monitor below also
  # repairs immediately when it detects that one of our managed rules vanished.
  cat > "$HAPROXY_UDP_REPAIR_TIMER_UNIT" <<EOF_UDP_REPAIR_TIMER
[Unit]
Description=Run GRE-TUN HAProxy UDP repair hourly

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
AccuracySec=20s
Persistent=true
Unit=$HAPROXY_UDP_REPAIR_SERVICE_NAME

[Install]
WantedBy=timers.target
EOF_UDP_REPAIR_TIMER

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$HAPROXY_UDP_SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl enable --now "$HAPROXY_UDP_REPAIR_TIMER_NAME" >/dev/null 2>&1 || true
}

haproxy_list_forwards() {
  echo -e "${C_BOLD}${C_WHITE}HAProxy forwarded ports:${C_RESET}"
  local entries proto color udp
  entries="$(haproxy_export_entries || true)"
  if [ -z "$entries" ]; then
    warn_msg "No forwarded ports found in $HAPROXY_CONFIG"
    return 0
  fi
  printf "${C_DIM}%8s  %-15s %-12s %-8s %-6s${C_RESET}\n" "Port" "Target-IP" "Target-Port" "Protocol" "UDP"
  printf "${C_DIM}%s${C_RESET}\n" "-------------------------------------------------------------"
  while read -r port ip tport proto; do
    [ -n "${port:-}" ] || continue
    proto="$(haproxy_normalize_proto "${proto:-http}")"
    if [ "$proto" = "tcp" ]; then color="$C_YELLOW"; udp="AUTO"; else color="$C_CYAN"; udp="OFF"; fi
    printf "%8s  ${C_MAGENTA}%-15s${C_RESET} %-12s ${color}%-8s${C_RESET} %-6s\n" "$port" "$ip" "$tport" "$proto" "$udp"
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
  local previous had_previous=0 backup_file
  # Validate quietly first so HAProxy NOTICE/WARNING lines do not confuse the menu output.
  # If validation fails, run it again without -q to print the real error.
  if ! haproxy -c -q -f "$tmp" >/dev/null 2>&1; then
    haproxy -c -f "$tmp" || true
    err_msg "HAProxy config validation failed. Nothing changed."
    rm -f "$tmp"
    return 1
  fi
  mkdir -p "$HAPROXY_BACKUP_DIR"
  previous="$(mktemp)"
  if [ -f "$HAPROXY_CONFIG" ]; then
    had_previous=1
    cp -f "$HAPROXY_CONFIG" "$previous"
    backup_file="$HAPROXY_BACKUP_DIR/haproxy.cfg.$(date +%Y%m%d-%H%M%S).bak"
    cp -f "$HAPROXY_CONFIG" "$backup_file" 2>/dev/null || true
  fi
  mv -f "$tmp" "$HAPROXY_CONFIG"
  haproxy_apply_high_limits
  haproxy_ensure_maxconn_in_config
  systemctl enable haproxy >/dev/null 2>&1 || true
  if systemctl restart haproxy; then
    rm -f "$previous"
    ok_msg "HAProxy restarted successfully."
    return 0
  fi

  err_msg "HAProxy restart failed; restoring the last working configuration."
  if [ "$had_previous" -eq 1 ]; then
    cp -f "$previous" "$HAPROXY_CONFIG"
    if haproxy -c -q -f "$HAPROXY_CONFIG" >/dev/null 2>&1 && systemctl restart haproxy; then
      warn_msg "Rollback succeeded; previous HAProxy service is running."
    else
      err_msg "HAProxy rollback also failed. Check: journalctl -u haproxy -n 50 --no-pager"
    fi
  else
    rm -f "$HAPROXY_CONFIG"
  fi
  rm -f "$previous"
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

  if haproxy_validate_and_restart "$tmp"; then
    haproxy_install_udp_service
    haproxy_sync_udp_rules
    return 0
  fi
  return 1
}

haproxy_entries_tmp() {
  local tmp
  tmp="$(mktemp)"
  haproxy_export_entries > "$tmp" || true
  echo "$tmp"
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
  haproxy_install_udp_service
  haproxy_sync_udp_rules >/dev/null 2>&1 || true
}

haproxy_add_port() {
  local raw_ports tmp port
  echo "00) Back to main menu"
  echo "Examples: 2044   |   2086 443 2052   |   2086,443,2052"
  read -rp "Enter local port(s) to add/update (comma or space separated): " raw_ports
  if is_main_menu_token "$raw_ports"; then return_main_msg; return 99; fi
  haproxy_parse_port_list "$raw_ports" || return 1

  echo
  haproxy_prompt_target_ip "Select target tunnel number or enter target IPv4" || return $?
  echo
  haproxy_prompt_protocol || return $?

  tmp="$(haproxy_entries_tmp)"
  for port in "${HAP_PORTS[@]}"; do
    if awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$tmp"; then
      warn_msg "Port $port already exists; replacing target/protocol."
    fi
    awk -v p="$port" '$1!=p' "$tmp" > "$tmp.new" || true
    printf '%s %s %s %s\n' "$port" "$HAP_TARGET_IP" "$port" "$HAP_SELECTED_PROTO" >> "$tmp.new"
    mv -f "$tmp.new" "$tmp"
  done

  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
  ok_msg "Applied ${#HAP_PORTS[@]} port(s) -> $HAP_TARGET_IP using $HAP_SELECTED_PROTO."
  if [ "$HAP_SELECTED_PROTO" = "tcp" ]; then
    info_msg "UDP companion forwarding was also synchronized automatically for these TCP port(s)."
  fi
}

haproxy_change_all_ips() {
  local tmp
  tmp="$(haproxy_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No forwarded ports to update."; rm -f "$tmp"; return 0; fi
  echo "00) Back to main menu"
  haproxy_prompt_target_ip "Select new target for ALL ports (number or IPv4)" || { local rc=$?; rm -f "$tmp"; return "$rc"; }
  awk -v ip="$HAP_TARGET_IP" '{proto=$4; if(proto=="") proto="http"; print $1, ip, $3, proto}' "$tmp" > "$tmp.new"
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
  ok_msg "Port $port removed. Any managed UDP companion rule for it was removed too."
}

haproxy_change_one_ip() {
  local port tmp rc
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

  haproxy_prompt_target_ip "Select new target for port $port (number or IPv4)"
  rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return "$rc"; fi

  awk -v p="$port" -v ip="$HAP_TARGET_IP" '{proto=$4; if(proto=="") proto="http"; if ($1==p) print $1, ip, $3, proto; else print $1, $2, $3, proto}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  haproxy_write_entries_file "$tmp"
  rm -f "$tmp"
}

haproxy_show_protocol_rows() {
  local entries="$1"
  local n=0 proto color udp
  printf "${C_DIM}%4s  %8s  %-15s %-12s %-8s %-6s${C_RESET}\n" "No" "Port" "Target-IP" "Target-Port" "Protocol" "UDP"
  printf "${C_DIM}%s${C_RESET}\n" "-------------------------------------------------------------------"
  while read -r port ip tport proto; do
    [ -n "${port:-}" ] || continue
    n=$((n + 1))
    proto="$(haproxy_normalize_proto "${proto:-http}")"
    if [ "$proto" = "tcp" ]; then color="$C_YELLOW"; udp="AUTO"; else color="$C_CYAN"; udp="OFF"; fi
    printf "%4s  %8s  ${C_MAGENTA}%-15s${C_RESET} %-12s ${color}%-8s${C_RESET} %-6s\n" "$n" "$port" "$ip" "$tport" "$proto" "$udp"
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
  echo -e "${C_GREEN}0)${C_RESET} ALL ports - toggle TCP <-> TCP+UDP"
  echo -e "${C_DIM}00) Back to main menu${C_RESET}"
  echo
  read -rp "Choose row number to toggle protocol [number/0/00]: " selected

  if is_main_menu_token "$selected"; then rm -f "$tmp"; return_main_msg; return 99; fi

  if [ "$selected" = "0" ]; then
    awk '{proto=$4; if(proto=="") proto="http"; if(proto=="tcp") proto="http"; else proto="tcp"; print $1, $2, $3, proto}' "$tmp" > "$tmp.new"
    mv -f "$tmp.new" "$tmp"
    haproxy_write_entries_file "$tmp"
    rm -f "$tmp"
    ok_msg "Protocol toggled for all HAProxy ports; UDP companions were synchronized automatically."
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

  if [ "$new_proto" = "tcp" ]; then
    ok_msg "Port $port protocol changed: $old_proto -> $new_proto (UDP companion added)."
  else
    ok_msg "Port $port protocol changed: $old_proto -> $new_proto (managed UDP companion removed)."
  fi
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
  ok_msg "HAProxy silent WebSocket optimization applied. Existing TCP rows keep automatic UDP companions; HTTP rows stay UDP-off."
}

# Return success only when every HAProxy TCP row has all four managed UDP
# companion rules installed for its currently resolved tunnel path. This check
# never deletes/reorders firewall rules and is safe to call frequently.
haproxy_udp_rules_healthy() {
  command -v iptables >/dev/null 2>&1 || return 0
  [ -f "$HAPROXY_CONFIG" ] || return 0

  local entries tcp_entries port target tport proto
  entries="$(haproxy_export_entries || true)"
  [ -n "$entries" ] || return 0
  tcp_entries="$(awk '{p=$4; if(p=="") p="http"; if(tolower(p)=="tcp") print $0}' <<< "$entries")"
  [ -n "$tcp_entries" ] || return 0

  while read -r port target tport proto; do
    [ -n "${port:-}" ] || continue
    haproxy_udp_resolve_path "$target" || return 1

    iptables -w 5 -t nat -C PREROUTING \
      -p udp --dport "$port" \
      -m comment --comment "gretun-hap-udp-pre-$port" \
      -j DNAT --to-destination "$target:$tport" 2>/dev/null || return 1

    iptables -w 5 -t nat -C POSTROUTING \
      -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-post-$port" \
      -j SNAT --to-source "$HAP_UDP_LOCAL_IP" 2>/dev/null || return 1

    iptables -w 5 -C FORWARD \
      -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-out-$port" \
      -j ACCEPT 2>/dev/null || return 1

    iptables -w 5 -C FORWARD \
      -i "$HAP_UDP_IFACE" -p udp -s "$target" --sport "$tport" \
      -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "gretun-hap-udp-back-$port" \
      -j ACCEPT 2>/dev/null || return 1
  done <<< "$tcp_entries"

  return 0
}

# Called by the existing 20-second gretun health timer. It does nothing when
# UDP rules are healthy; when any managed rule is missing it runs option-8
# repair immediately. A lock prevents overlap with the hourly forced repair.
haproxy_udp_self_heal_check() {
  command -v haproxy >/dev/null 2>&1 || return 0
  command -v iptables >/dev/null 2>&1 || return 0
  [ -f "$HAPROXY_CONFIG" ] || return 0

  if haproxy_udp_rules_healthy; then
    return 0
  fi

  local lockdir="/run/gretun-haproxy-udp-repair.lock"
  mkdir "$lockdir" 2>/dev/null || return 0
  info_msg "HAProxy UDP self-heal detected missing/stale managed rules; running automatic repair..."
  local rc=0
  haproxy_repair_udp || rc=$?
  rmdir "$lockdir" 2>/dev/null || true
  return "$rc"
}

# Non-interactive hourly service wrapper. This intentionally force-runs the
# exact same repair as menu option 8 even if the rules still look present.
haproxy_periodic_udp_repair() {
  command -v haproxy >/dev/null 2>&1 || return 0
  [ -f "$HAPROXY_CONFIG" ] || return 0

  local lockdir="/run/gretun-haproxy-udp-repair.lock"
  mkdir "$lockdir" 2>/dev/null || return 0
  local rc=0
  haproxy_repair_udp || rc=$?
  rmdir "$lockdir" 2>/dev/null || true
  return "$rc"
}

# Rebuild UDP companions for every existing HAProxy TCP row without touching
# HTTP rows or changing the HAProxy configuration itself. This is an operator-
# initiated recovery action for cases where firewall/NAT state was lost or a
# previous automatic sync did not take effect.
haproxy_repair_udp() {
  local entries tcp_entries port target tport proto
  local resolved=0 unresolved=0 verified=0 failed=0

  command -v iptables >/dev/null 2>&1 || {
    err_msg "iptables is not available; UDP repair cannot continue."
    return 1
  }

  entries="$(haproxy_export_entries || true)"
  if [ -z "$entries" ]; then
    warn_msg "No HAProxy forwarded ports were found."
    return 0
  fi

  tcp_entries="$(awk '{p=$4; if(p=="") p="http"; if(tolower(p)=="tcp") print $0}' <<< "$entries")"
  if [ -z "$tcp_entries" ]; then
    warn_msg "No TCP HAProxy ports were found. HTTP rows intentionally have UDP disabled."
    return 0
  fi

  echo -e "${C_BOLD}${C_WHITE}TCP ports detected for UDP repair:${C_RESET}"
  printf "${C_DIM}%8s  %-15s %-12s %-10s %-15s %-10s${C_RESET}\n" \
    "Port" "Target-IP" "Target-Port" "Interface" "Local-Tun-IP" "Status"
  printf "${C_DIM}%s${C_RESET}\n" "-------------------------------------------------------------------------------"

  while read -r port target tport proto; do
    [ -n "${port:-}" ] || continue
    if haproxy_udp_resolve_path "$target"; then
      printf "%8s  %-15s %-12s %-10s %-15s ${C_GREEN}%-10s${C_RESET}\n" \
        "$port" "$target" "$tport" "$HAP_UDP_IFACE" "$HAP_UDP_LOCAL_IP" "ready"
      resolved=$((resolved + 1))
    else
      printf "%8s  %-15s %-12s %-10s %-15s ${C_RED}%-10s${C_RESET}\n" \
        "$port" "$target" "$tport" "?" "?" "unresolved"
      unresolved=$((unresolved + 1))
    fi
  done <<< "$tcp_entries"

  echo
  if [ "$resolved" -eq 0 ]; then
    err_msg "None of the TCP targets could be mapped to a tunnel/route; no UDP rules were changed."
    return 1
  fi

  info_msg "Repairing UDP companions: removing managed stale rules and rebuilding all TCP UDP forwards..."
  haproxy_install_udp_service
  haproxy_sync_udp_rules

  echo
  echo -e "${C_BOLD}${C_WHITE}UDP repair verification:${C_RESET}"
  while read -r port target tport proto; do
    [ -n "${port:-}" ] || continue
    if ! haproxy_udp_resolve_path "$target"; then
      warn_msg "UDP $port -> $target:$tport : skipped (route unresolved)"
      failed=$((failed + 1))
      continue
    fi

    if iptables -w 5 -t nat -C PREROUTING \
         -p udp --dport "$port" \
         -m comment --comment "gretun-hap-udp-pre-$port" \
         -j DNAT --to-destination "$target:$tport" 2>/dev/null \
       && iptables -w 5 -t nat -C POSTROUTING \
         -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
         -m comment --comment "gretun-hap-udp-post-$port" \
         -j SNAT --to-source "$HAP_UDP_LOCAL_IP" 2>/dev/null \
       && iptables -w 5 -C FORWARD \
         -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
         -m comment --comment "gretun-hap-udp-out-$port" \
         -j ACCEPT 2>/dev/null \
       && iptables -w 5 -C FORWARD \
         -i "$HAP_UDP_IFACE" -p udp -s "$target" --sport "$tport" \
         -m conntrack --ctstate ESTABLISHED,RELATED \
         -m comment --comment "gretun-hap-udp-back-$port" \
         -j ACCEPT 2>/dev/null; then
      ok_msg "UDP $port -> $target:$tport via $HAP_UDP_IFACE ($HAP_UDP_LOCAL_IP) repaired"
      verified=$((verified + 1))
    else
      err_msg "UDP $port -> $target:$tport verification failed"
      failed=$((failed + 1))
    fi
  done <<< "$tcp_entries"

  echo
  if [ "$failed" -eq 0 ] && [ "$unresolved" -eq 0 ]; then
    ok_msg "UDP repair complete: $verified TCP port(s) rebuilt and verified successfully."
    return 0
  fi

  warn_msg "UDP repair finished with $verified verified, $failed failed, and $unresolved initially unresolved port(s)."
  return 1
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
    echo -e "  ${C_GREEN}2)${C_RESET} add/update port(s) ${C_DIM}(comma/space supported)${C_RESET}"
    echo -e "  ${C_YELLOW}3)${C_RESET} change ALL target IPs"
    echo -e "  ${C_RED}4)${C_RESET} delete port"
    echo -e "  ${C_CYAN}5)${C_RESET} change target IP for one port"
    echo -e "  ${C_MAGENTA}6)${C_RESET} change protocol http/tcp ${C_DIM}(UDP auto-sync)${C_RESET}"
    echo -e "  ${C_CYAN}7)${C_RESET} optimize WebSocket / silent HAProxy no access-log"
    echo -e "  ${C_GREEN}8)${C_RESET} repair UDP for all TCP ports ${C_DIM}(detect + rebuild + verify)${C_RESET}"
    echo -e "  ${C_YELLOW}9)${C_RESET} switch HAProxy -> Real-IP ${C_DIM}(0 = ALL; TCP-only default)${C_RESET}"
    echo -e "  ${C_DIM}00) Back to main menu${C_RESET}"
    echo
    read -rp "Choose HAProxy option [1-9/00]: " HAP_CHOICE
    case "$HAP_CHOICE" in
      1) haproxy_run_action haproxy_list_forwards || return 0 ;;
      2) haproxy_run_action haproxy_add_port || return 0 ;;
      3) haproxy_run_action haproxy_change_all_ips || return 0 ;;
      4) haproxy_run_action haproxy_delete_port || return 0 ;;
      5) haproxy_run_action haproxy_change_one_ip || return 0 ;;
      6) haproxy_run_action haproxy_change_protocol || return 0 ;;
      7) haproxy_run_action haproxy_optimize_websocket_nolog || return 0 ;;
      8) haproxy_run_action haproxy_repair_udp || return 0 ;;
      9) haproxy_run_action switch_haproxy_to_realip || return 0 ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}


# -----------------------------
# Real-IP L3 port forward manager (v8.9.1)
# -----------------------------
# This is intentionally independent from HAProxy:
#   HAProxy : local proxy connection + optional UDP DNAT/SNAT companion
#   Real-IP : direct TCP/UDP DNAT through an L3 tunnel WITHOUT SNAT
#
# Real-IP config format:
#   local_port target_ip target_port l3_protocol haproxy_restore_protocol
# l3_protocol: tcp | both
# restore protocol is kept so a switched port can return to the same HAProxy
# HTTP/TCP mode with one action.

realip_normalize_proto() {
  case "$(printf '%s' "${1:-both}" | tr '[:upper:]' '[:lower:]')" in
    tcp) echo "tcp" ;;
    *) echo "both" ;;
  esac
}

realip_proto_label() {
  if [ "$(realip_normalize_proto "${1:-both}")" = "tcp" ]; then
    echo "TCP"
  else
    echo "TCP+UDP"
  fi
}

realip_restore_proto_for_l3() {
  if [ "$(realip_normalize_proto "${1:-both}")" = "tcp" ]; then
    echo "http"
  else
    echo "tcp"
  fi
}

realip_export_entries() {
  [ -f "$REALIP_FORWARDS_FILE" ] || return 0
  awk '
    NF >= 3 && $1 ~ /^[0-9]+$/ {
      p=$1; ip=$2; tp=$3; l3=$4; hp=$5;
      if (l3 != "tcp") l3="both";
      if (hp != "http" && hp != "tcp") hp=(l3=="both" ? "tcp" : "http");
      print p, ip, tp, l3, hp;
    }
  ' "$REALIP_FORWARDS_FILE" | sort -n -k1,1 -u
}

realip_entries_tmp() {
  local tmp
  tmp="$(mktemp)"
  realip_export_entries > "$tmp" || true
  echo "$tmp"
}

realip_write_entries_file() {
  local src="$1"
  local staged
  mkdir -p "$REALIP_CONFIG_DIR"
  staged="$(mktemp "$REALIP_CONFIG_DIR/.forwards.XXXXXX")"
  if [ -s "$src" ]; then
    awk '!seen[$1]++ {print $1, $2, $3, $4, $5}' "$src" | sort -n -k1,1 > "$staged"
  else
    : > "$staged"
  fi
  chmod 600 "$staged"
  mv -f "$staged" "$REALIP_FORWARDS_FILE"
}

# Validate the complete candidate before touching either the saved state or the
# running firewall. An inactive or unsupported tunnel is rejected here instead
# of silently leaving only part of the selected ports online.
realip_validate_entries_file() {
  local src="$1" port target tport proto restore
  local -A seen=()
  [ -s "$src" ] || return 0
  while read -r port target tport proto restore; do
    [ -n "${port:-}" ] || continue
    validate_port "$port" || { err_msg "Real-IP candidate has invalid local port: $port"; return 1; }
    validate_ipv4 "$target" || { err_msg "Real-IP candidate has invalid target: $target"; return 1; }
    validate_port "$tport" || { err_msg "Real-IP candidate has invalid target port: $tport"; return 1; }
    [ -z "${seen[$port]+x}" ] || { err_msg "Real-IP candidate contains duplicate port: $port"; return 1; }
    seen[$port]=1
    case "$(realip_normalize_proto "$proto")" in tcp|both) ;; *) return 1 ;; esac
    if ! realip_resolve_target "$target" >/dev/null 2>&1 || ! tunnel_iface_is_up "$REALIP_IFACE"; then
      err_msg "Real-IP candidate rejected: $target is not on an active GRE/Vira7/Reverse-ViraTCP path."
      return 1
    fi
  done < "$src"
}

# Commit a complete Real-IP table and verify every generated rule. If anything
# fails, restore the previous table and rebuild its rules automatically.
realip_commit_entries_file() {
  local candidate="$1" previous had_previous=0 backup_file
  previous="$(mktemp)"
  if [ -f "$REALIP_FORWARDS_FILE" ]; then
    had_previous=1
    cp -f "$REALIP_FORWARDS_FILE" "$previous"
  fi

  if ! realip_validate_entries_file "$candidate"; then
    rm -f "$previous"
    return 1
  fi

  mkdir -p "$REALIP_BACKUP_DIR"
  if [ "$had_previous" -eq 1 ]; then
    backup_file="$REALIP_BACKUP_DIR/forwards.$(date +%Y%m%d-%H%M%S)-$RANDOM.bak"
    cp -f "$previous" "$backup_file" 2>/dev/null || true
  fi

  realip_write_entries_file "$candidate"
  realip_install_service
  if realip_sync_rules && realip_rules_healthy; then
    rm -f "$previous"
    return 0
  fi

  err_msg "Real-IP apply/verification failed; rolling back to the previous forwarding table."
  if [ "$had_previous" -eq 1 ]; then
    realip_write_entries_file "$previous"
  else
    : > "$previous"
    realip_write_entries_file "$previous"
  fi
  realip_sync_rules >/dev/null 2>&1 || true
  rm -f "$previous"
  return 1
}

# Resolve a Real-IP target to an L3 tunnel. The current WireGuard implementation
# intentionally uses peer /32 AllowedIPs, so arbitrary Internet-destination
# reply packets cannot be sent through it without changing WG semantics. For
# safety, Real-IP therefore supports GRE, Vira7 and ViraTCP here.
realip_resolve_target() {
  local target="$1" i inv_target route ifc local_ip
  REALIP_IFACE=""; REALIP_LOCAL_IP=""; REALIP_TYPE=""; REALIP_ID=""
  build_tunnel_inventory

  for i in "${!INV_TYPE[@]}"; do
    inv_target="${INV_TARGET[$i]:-}"; inv_target="${inv_target%%/*}"
    [ "$inv_target" = "$target" ] || continue
    case "${INV_TYPE[$i]:-}" in
      gre|vira7|viratcp)
        REALIP_IFACE="${INV_IFACE[$i]:-}"
        REALIP_LOCAL_IP="${INV_LOCAL[$i]:-}"; REALIP_LOCAL_IP="${REALIP_LOCAL_IP%%/*}"
        REALIP_TYPE="${INV_TYPE[$i]}"
        REALIP_ID="${INV_ID[$i]}"
        [ -n "$REALIP_IFACE" ] && validate_ipv4 "$REALIP_LOCAL_IP" && return 0
        ;;
      wireguard)
        err_msg "Real-IP target $target is WireGuard. This script keeps WireGuard AllowedIPs at peer /32, so Real-IP return traffic is not enabled for WireGuard. Use GRE, Vira7 or ViraTCP."
        return 1
        ;;
    esac
  done

  # Keep custom tunnel IPv4 support when the kernel route clearly points to one
  # of the compatible L3 interfaces.
  route="$(ip -4 route get "$target" 2>/dev/null | head -n 1 || true)"
  ifc="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
  local_ip="$(awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' <<< "$route")"
  case "$ifc" in
    gre*) REALIP_TYPE="gre"; REALIP_ID="${ifc#gre}" ;;
    vira7*) REALIP_TYPE="vira7"; REALIP_ID="${ifc#vira7}" ;;
    viratcp*) REALIP_TYPE="viratcp"; REALIP_ID="${ifc#viratcp}" ;;
    *) return 1 ;;
  esac
  REALIP_IFACE="$ifc"; REALIP_LOCAL_IP="$local_ip"
  [ -n "$REALIP_IFACE" ] && validate_ipv4 "$REALIP_LOCAL_IP"
}

realip_prompt_target_ip() {
  haproxy_prompt_target_ip "Select Real-IP target tunnel number or enter tunnel IPv4" || return $?
  if ! realip_resolve_target "$HAP_TARGET_IP"; then
    err_msg "Selected target cannot be used by the Real-IP engine. Pick a GRE, Vira7 or ViraTCP remote tunnel IP."
    return 1
  fi
  REALIP_TARGET_IP="$HAP_TARGET_IP"
  info_msg "Real-IP path: ${REALIP_TYPE}${REALIP_ID:+$REALIP_ID} $REALIP_IFACE ($REALIP_LOCAL_IP -> $REALIP_TARGET_IP)"
}

realip_prompt_protocol() {
  local input
  echo -e "${C_BOLD}${C_WHITE}Real-IP protocol mode:${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} TCP only ${C_DIM}(recommended/default; lighter handshakes, best for VLESS/VMess/TLS/WebSocket)${C_RESET}"
  echo -e "  ${C_YELLOW}2)${C_RESET} TCP + UDP ${C_DIM}(enable only when this inbound really needs UDP, e.g. Shadowsocks UDP/QUIC/gaming)${C_RESET}"
  echo
  read -rp "Choose protocol [1=TCP default, 2=TCP+UDP, 00=menu]: " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  input="${input:-1}"
  case "$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]')" in
    1|tcp|t) REALIP_SELECTED_PROTO="tcp" ;;
    2|both|udp|tcpudp|tcp+udp) REALIP_SELECTED_PROTO="both" ;;
    *) err_msg "Invalid protocol selection."; return 1 ;;
  esac
}

realip_prompt_switch_protocol() {
  local input
  echo -e "${C_BOLD}${C_WHITE}Real-IP protocol for switched port(s):${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} TCP only ${C_DIM}(recommended/default; avoids extra UDP traffic and lower handshake pressure)${C_RESET}"
  echo -e "  ${C_CYAN}2)${C_RESET} keep HAProxy mode ${C_DIM}(HAProxy TCP -> TCP+UDP, HAProxy HTTP -> TCP only)${C_RESET}"
  echo -e "  ${C_YELLOW}3)${C_RESET} force TCP + UDP ${C_DIM}(only if the inbound really needs UDP)${C_RESET}"
  echo
  read -rp "Choose switch protocol [1/2/3, 00=menu]: " input
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  input="${input:-1}"
  case "$input" in
    1) REALIP_SWITCH_PROTO_MODE="tcp" ;;
    2) REALIP_SWITCH_PROTO_MODE="keep" ;;
    3) REALIP_SWITCH_PROTO_MODE="both" ;;
    *) err_msg "Invalid protocol selection."; return 1 ;;
  esac
}

select_ports_from_tmp() {
  local engine_name="$1" tmp="$2" raw manual
  SELECTED_PORTS=()
  echo -e "${C_BOLD}${C_WHITE}$engine_name port selection:${C_RESET}"
  echo -e "  ${C_GREEN}0)${C_RESET} ALL ports"
  echo -e "  ${C_CYAN}1)${C_RESET} choose specific port(s)"
  echo -e "  ${C_DIM}00) Back${C_RESET}"
  echo
  read -rp "Choose [0=ALL, 1=specific, 00=menu]: " raw
  if is_main_menu_token "$raw"; then return_main_msg; return 99; fi
  case "$raw" in
    0)
      mapfile -t SELECTED_PORTS < <(awk '{print $1}' "$tmp")
      ;;
    1)
      echo "Examples: 443   |   443 8443 2053   |   443,8443,2053"
      read -rp "Enter port(s): " manual
      if is_main_menu_token "$manual"; then return_main_msg; return 99; fi
      haproxy_parse_port_list "$manual" || return 1
      SELECTED_PORTS=("${HAP_PORTS[@]}")
      ;;
    *)
      err_msg "Invalid selection. Use 0 for ALL or 1 for selected ports."
      return 1
      ;;
  esac
  [ "${#SELECTED_PORTS[@]}" -gt 0 ] || { warn_msg "No ports selected."; return 1; }
}

realip_delete_commented_rules() {
  local table="$1" chain="$2" marker="$3" n
  local -a nums=()
  if [ "$table" = "filter" ]; then
    mapfile -t nums < <(iptables -w 5 -L "$chain" --line-numbers -n 2>/dev/null | awk -v m="$marker" 'index($0,m){print $1}' | sort -rn)
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] && iptables -w 5 -D "$chain" "$n" 2>/dev/null || true
    done
  else
    mapfile -t nums < <(iptables -w 5 -t "$table" -L "$chain" --line-numbers -n 2>/dev/null | awk -v m="$marker" 'index($0,m){print $1}' | sort -rn)
    for n in "${nums[@]}"; do
      [[ "$n" =~ ^[0-9]+$ ]] && iptables -w 5 -t "$table" -D "$chain" "$n" 2>/dev/null || true
    done
  fi
}

realip_flush_managed_rules() {
  command -v iptables >/dev/null 2>&1 || return 0
  realip_delete_commented_rules nat PREROUTING "$REALIP_RULE_PREFIX-"
  realip_delete_commented_rules mangle FORWARD "$REALIP_RULE_PREFIX-"
  realip_delete_commented_rules filter FORWARD "$REALIP_RULE_PREFIX-"
}


realip_mss_for_iface() {
  local ifc="$1" mtu mss
  mtu="$(cat "/sys/class/net/$ifc/mtu" 2>/dev/null || true)"
  if ! [[ "$mtu" =~ ^[0-9]+$ ]]; then
    mtu="$(ip -o link show dev "$ifc" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  fi
  [[ "$mtu" =~ ^[0-9]+$ ]] || mtu=1390
  # IPv4 TCP header budget: 20 bytes IP + 20 bytes TCP.
  # Clamp a little below the tunnel MTU so TLS/WebSocket ClientHello packets do not fragment.
  mss=$((mtu - 40))
  [ "$mss" -lt 536 ] && mss=536
  [ "$mss" -gt 1460 ] && mss=1460
  echo "$mss"
}

realip_add_tcp_mss_rules() {
  local port="$1" target="$2" tport="$3" ifc="$4" mss
  mss="$(realip_mss_for_iface "$ifc")"

  # Forward path: client SYN enters Iran, is DNATed, then exits through the tunnel.
  iptables -w 5 -t mangle -I FORWARD 1 \
    -o "$ifc" -p tcp -d "$target" --dport "$tport" \
    --tcp-flags SYN,RST SYN \
    -m comment --comment "$REALIP_RULE_PREFIX-tcp-mss-out-$port" \
    -j TCPMSS --set-mss "$mss" \
    || warn_msg "Real-IP MSS clamp could not be installed for outgoing TCP port $port."

  # Return path on Iran: SYN-ACK comes back through the same tunnel before reverse NAT.
  iptables -w 5 -t mangle -I FORWARD 1 \
    -i "$ifc" -p tcp -s "$target" --sport "$tport" \
    --tcp-flags SYN,RST SYN \
    -m comment --comment "$REALIP_RULE_PREFIX-tcp-mss-back-$port" \
    -j TCPMSS --set-mss "$mss" \
    || warn_msg "Real-IP return MSS clamp could not be installed for TCP port $port."
}

realip_tcp_mss_rules_exist() {
  local port="$1" target="$2" tport="$3" ifc="$4" mss
  mss="$(realip_mss_for_iface "$ifc")"
  iptables -w 5 -t mangle -C FORWARD \
    -o "$ifc" -p tcp -d "$target" --dport "$tport" \
    --tcp-flags SYN,RST SYN \
    -m comment --comment "$REALIP_RULE_PREFIX-tcp-mss-out-$port" \
    -j TCPMSS --set-mss "$mss" 2>/dev/null \
  && iptables -w 5 -t mangle -C FORWARD \
    -i "$ifc" -p tcp -s "$target" --sport "$tport" \
    --tcp-flags SYN,RST SYN \
    -m comment --comment "$REALIP_RULE_PREFIX-tcp-mss-back-$port" \
    -j TCPMSS --set-mss "$mss" 2>/dev/null
}

realip_add_l4_rule() {
  local l4="$1" port="$2" target="$3" tport="$4" ifc="$5"
  # IMPORTANT: there is deliberately no POSTROUTING SNAT rule here.
  iptables -w 5 -t nat -I PREROUTING 1 \
    -p "$l4" --dport "$port" \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-pre-$port" \
    -j DNAT --to-destination "$target:$tport"

  if [ "$l4" = "tcp" ]; then
    realip_add_tcp_mss_rules "$port" "$target" "$tport" "$ifc"
  fi

  iptables -w 5 -I FORWARD 1 \
    -o "$ifc" -p "$l4" -d "$target" --dport "$tport" \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-out-$port" \
    -j ACCEPT

  iptables -w 5 -I FORWARD 1 \
    -i "$ifc" -p "$l4" -s "$target" --sport "$tport" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-back-$port" \
    -j ACCEPT
}

realip_sync_rules() {
  command -v iptables >/dev/null 2>&1 || { err_msg "iptables is required for Real-IP forwarding."; return 1; }
  enable_ip_forward
  apply_tunnel_sysctls
  realip_flush_managed_rules

  local entries port target tport proto restore count=0 skipped=0
  entries="$(realip_export_entries || true)"
  [ -n "$entries" ] || return 0

  while read -r port target tport proto restore; do
    [ -n "${port:-}" ] || continue
    if ! realip_resolve_target "$target"; then
      warn_msg "Real-IP port $port skipped: target $target is not a supported/active L3 tunnel path."
      skipped=$((skipped + 1))
      continue
    fi
    realip_add_l4_rule tcp "$port" "$target" "$tport" "$REALIP_IFACE"
    if [ "$(realip_normalize_proto "$proto")" = "both" ]; then
      realip_add_l4_rule udp "$port" "$target" "$tport" "$REALIP_IFACE"
    fi
    count=$((count + 1))
  done <<< "$entries"

  [ "$count" -eq 0 ] || ok_msg "Real-IP rules synchronized for $count port(s); source IP preservation is ON, MSS clamp is ON, and no SNAT rule was added."
  [ "$skipped" -eq 0 ] || warn_msg "$skipped Real-IP port(s) could not be synchronized."
  [ "$skipped" -eq 0 ]
}

realip_rule_exists_l4() {
  local l4="$1" port="$2" target="$3" tport="$4" ifc="$5"
  iptables -w 5 -t nat -C PREROUTING \
    -p "$l4" --dport "$port" \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-pre-$port" \
    -j DNAT --to-destination "$target:$tport" 2>/dev/null \
  && iptables -w 5 -C FORWARD \
    -o "$ifc" -p "$l4" -d "$target" --dport "$tport" \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-out-$port" \
    -j ACCEPT 2>/dev/null \
  && iptables -w 5 -C FORWARD \
    -i "$ifc" -p "$l4" -s "$target" --sport "$tport" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "$REALIP_RULE_PREFIX-$l4-back-$port" \
    -j ACCEPT 2>/dev/null || return 1

  if [ "$l4" = "tcp" ]; then
    realip_tcp_mss_rules_exist "$port" "$target" "$tport" "$ifc" || return 1
  fi
}


realip_rules_healthy() {
  command -v iptables >/dev/null 2>&1 || return 1
  local entries port target tport proto restore
  entries="$(realip_export_entries || true)"
  [ -n "$entries" ] || return 0
  while read -r port target tport proto restore; do
    [ -n "${port:-}" ] || continue
    realip_resolve_target "$target" >/dev/null 2>&1 || return 1
    realip_rule_exists_l4 tcp "$port" "$target" "$tport" "$REALIP_IFACE" || return 1
    if [ "$(realip_normalize_proto "$proto")" = "both" ]; then
      realip_rule_exists_l4 udp "$port" "$target" "$tport" "$REALIP_IFACE" || return 1
    fi
  done <<< "$entries"
  return 0
}

realip_config_file_for_item() {
  local type="$1" id="$2"
  case "$type" in
    gre) gre_config_file "$id" ;;
    vira7) vira7_config_file "$id" ;;
    viratcp) viratcp_config_file "$id" ;;
    wireguard) wg_meta_file "$id" ;;
    *) return 1 ;;
  esac
}

realip_saved_role_for_item() {
  local type="$1" id="$2" file value
  file="$(realip_config_file_for_item "$type" "$id" 2>/dev/null || true)"
  [ -n "$file" ] && [ -f "$file" ] || return 1
  value="$(grep -m1 '^ROLE=' "$file" 2>/dev/null | cut -d= -f2- | tr -d "'\" " || true)"
  [ "$value" = "1" ] || [ "$value" = "2" ] || return 1
  printf '%s\n' "$value"
}

# Reserve only three narrow priority bands and matching private table bands.
# A rule is considered ours only when BOTH its priority and lookup table match.
realip_route_numbers() {
  local type="$1" id="$2" basep baset
  case "$type" in
    gre) basep=25000; baset=51000 ;;
    vira7) basep=25300; baset=52000 ;;
    viratcp) basep=25600; baset=53000 ;;
    *) return 1 ;;
  esac
  REALIP_ROUTE_PRIO=$((basep + id))
  REALIP_ROUTE_TABLE=$((baset + id))
}

realip_cleanup_return_routing() {
  command -v ip >/dev/null 2>&1 || return 0
  local line prio table
  while IFS= read -r line; do
    prio="${line%%:*}"
    table="$(awk '{for(i=1;i<=NF;i++) if($i=="lookup") {print $(i+1); exit}}' <<< "$line")"
    [[ "$prio" =~ ^[0-9]+$ ]] || continue
    [[ "$table" =~ ^[0-9]+$ ]] || continue
    if { [ "$prio" -ge 25001 ] && [ "$prio" -le 25254 ] && [ "$table" -ge 51001 ] && [ "$table" -le 51254 ]; } \
       || { [ "$prio" -ge 25301 ] && [ "$prio" -le 25554 ] && [ "$table" -ge 52001 ] && [ "$table" -le 52254 ]; } \
       || { [ "$prio" -ge 25601 ] && [ "$prio" -le 25854 ] && [ "$table" -ge 53001 ] && [ "$table" -le 53254 ]; }; then
      # Delete only the matching reserved priority/table pair; do not sweep any
      # unrelated rule that might coincidentally share the same priority.
      ip rule del priority "$prio" lookup "$table" 2>/dev/null || true
      ip route flush table "$table" 2>/dev/null || true
    fi
  done < <(ip -4 rule show 2>/dev/null)
}


realip_prepare_return_iface() {
  local ifc="$1"
  [ -n "$ifc" ] || return 0
  sysctl -w "net.ipv4.conf.$ifc.rp_filter=0" >/dev/null 2>&1 || true
  ip link set dev "$ifc" txqueuelen 1000 >/dev/null 2>&1 || true
}

realip_apply_return_routing() {
  [ -f "$REALIP_RETURN_MARKER" ] || return 0
  command -v ip >/dev/null 2>&1 || return 1
  apply_tunnel_sysctls
  realip_cleanup_return_routing

  build_tunnel_inventory
  local i type id role ifc local_ip remote_ip applied=0 route_mtu
  for i in "${!INV_TYPE[@]}"; do
    type="${INV_TYPE[$i]:-}"; id="${INV_ID[$i]:-}"
    case "$type" in gre|vira7|viratcp) ;; *) continue ;; esac
    role="$(realip_saved_role_for_item "$type" "$id" 2>/dev/null || true)"
    [ "$role" = "2" ] || continue
    ifc="${INV_IFACE[$i]:-}"
    local_ip="${INV_LOCAL[$i]:-}"; local_ip="${local_ip%%/*}"
    remote_ip="${INV_TARGET[$i]:-}"; remote_ip="${remote_ip%%/*}"
    validate_ipv4 "$local_ip" || continue
    validate_ipv4 "$remote_ip" || continue
    tunnel_iface_is_up "$ifc" || { warn_msg "Return route skipped for $type$id: $ifc is down."; continue; }
    realip_route_numbers "$type" "$id" || continue

    realip_prepare_return_iface "$ifc"
    route_mtu="$(cat "/sys/class/net/$ifc/mtu" 2>/dev/null || echo 1390)"
    [[ "$route_mtu" =~ ^[0-9]+$ ]] || route_mtu=1390

    # The peer /32 keeps the tunnel peer reachable inside the dedicated table;
    # arbitrary client destinations are then sent back through the same L3 tunnel.
    # The explicit MTU avoids large SYN-ACK / TLS records selecting the physical MTU.
    ip route replace "$remote_ip/32" dev "$ifc" scope link table "$REALIP_ROUTE_TABLE"
    ip route replace default dev "$ifc" mtu "$route_mtu" table "$REALIP_ROUTE_TABLE"
    ip rule add priority "$REALIP_ROUTE_PRIO" from "$local_ip/32" lookup "$REALIP_ROUTE_TABLE"
    applied=$((applied + 1))
  done
  ip route flush cache 2>/dev/null || true
  [ "$applied" -gt 0 ] || { warn_msg "Real-IP return routing is enabled, but no Kharej-role GRE/Vira7/ViraTCP tunnel was available."; return 1; }
  return 0
}

realip_return_routing_healthy() {
  [ -f "$REALIP_RETURN_MARKER" ] || return 0
  build_tunnel_inventory
  local i type id role ifc local_ip found=0
  for i in "${!INV_TYPE[@]}"; do
    type="${INV_TYPE[$i]:-}"; id="${INV_ID[$i]:-}"
    case "$type" in gre|vira7|viratcp) ;; *) continue ;; esac
    role="$(realip_saved_role_for_item "$type" "$id" 2>/dev/null || true)"
    [ "$role" = "2" ] || continue
    found=1
    ifc="${INV_IFACE[$i]:-}"
    local_ip="${INV_LOCAL[$i]:-}"; local_ip="${local_ip%%/*}"
    realip_route_numbers "$type" "$id" || return 1
    ip -4 rule show 2>/dev/null | grep -Eq "^${REALIP_ROUTE_PRIO}:.*from ${local_ip}([ /]|$).*lookup ${REALIP_ROUTE_TABLE}([[:space:]]|$)" || return 1
    ip -4 route show table "$REALIP_ROUTE_TABLE" 2>/dev/null | grep -Eq "^default .*dev ${ifc}([[:space:]]|$)" || return 1
  done
  [ "$found" -eq 1 ]
}

realip_sync_all() {
  local rc=0
  realip_sync_rules || rc=1
  if [ -f "$REALIP_RETURN_MARKER" ]; then realip_apply_return_routing || rc=1; fi
  return "$rc"
}

realip_install_service() {
  command -v systemctl >/dev/null 2>&1 || return 0
  mkdir -p "$REALIP_CONFIG_DIR"
  install_manager_binary >/dev/null 2>&1 || true
  [ -s "$INSTALL_BIN" ] || return 1
  cat > "$REALIP_SERVICE_UNIT" <<EOF_REALIP_SERVICE
[Unit]
Description=GRE-TUN Real-IP DNAT forwarding and return policy routing
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service realip-sync
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_REALIP_SERVICE
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$REALIP_SERVICE_NAME" >/dev/null 2>&1 || true
}

realip_self_heal_check() {
  [ -s "$REALIP_FORWARDS_FILE" ] || [ -f "$REALIP_RETURN_MARKER" ] || return 0
  local need=0
  realip_rules_healthy || need=1
  realip_return_routing_healthy || need=1
  [ "$need" -eq 0 ] && return 0
  local lockdir="/run/gretun-realip-repair.lock"
  mkdir "$lockdir" 2>/dev/null || return 0
  info_msg "Real-IP self-heal detected missing/stale rules; rebuilding..."
  realip_sync_all || true
  rmdir "$lockdir" 2>/dev/null || true
}

realip_list_forwards() {
  echo -e "${C_BOLD}${C_WHITE}Real-IP forwarded ports (DNAT without SNAT):${C_RESET}"
  local entries proto restore
  entries="$(realip_export_entries || true)"
  if [ -z "$entries" ]; then warn_msg "No Real-IP forwarded ports configured."; return 0; fi
  printf "${C_DIM}%8s  %-15s %-12s %-10s %-12s${C_RESET}\n" "Port" "Target-IP" "Target-Port" "L3" "HAProxy-back"
  printf "${C_DIM}%s${C_RESET}\n" "---------------------------------------------------------------------"
  while read -r port ip tport proto restore; do
    printf "%8s  ${C_MAGENTA}%-15s${C_RESET} %-12s ${C_GREEN}%-10s${C_RESET} %-12s\n" \
      "$port" "$ip" "$tport" "$(realip_proto_label "$proto")" "$restore"
  done <<< "$entries"
  echo
  if [ -f "$REALIP_RETURN_MARKER" ]; then
    echo -e "Kharej return routing: ${C_GREEN}ENABLED${C_RESET}"
  else
    echo -e "Kharej return routing: ${C_YELLOW}NOT ENABLED on this server${C_RESET}"
  fi
}

realip_add_port() {
  local raw_ports tmp port restore
  echo "00) Back to main menu"
  echo "Examples: 443   |   443 8443 2053   |   443,8443,2053"
  echo -e "${C_DIM}Tip: Real-IP defaults to TCP only. Turn UDP on only for ports that really need UDP.${C_RESET}"
  read -rp "Enter local port(s) to add/update: " raw_ports
  if is_main_menu_token "$raw_ports"; then return_main_msg; return 99; fi
  haproxy_parse_port_list "$raw_ports" || return 1

  # Never allow one public port to be owned by both engines accidentally.
  local hap_entries conflicts=""
  hap_entries="$(haproxy_export_entries || true)"
  for port in "${HAP_PORTS[@]}"; do
    if awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' <<< "$hap_entries"; then conflicts+=" $port"; fi
  done
  if [ -n "$conflicts" ]; then
    err_msg "Port(s)$conflicts are currently owned by HAProxy. Use Switch Forwarding Engine instead of creating duplicate rules."
    return 1
  fi

  echo
  realip_prompt_target_ip || return $?
  echo
  realip_prompt_protocol || return $?
  restore="$(realip_restore_proto_for_l3 "$REALIP_SELECTED_PROTO")"

  tmp="$(realip_entries_tmp)"
  for port in "${HAP_PORTS[@]}"; do
    awk -v p="$port" '$1!=p' "$tmp" > "$tmp.new" || true
    printf '%s %s %s %s %s\n' "$port" "$REALIP_TARGET_IP" "$port" "$REALIP_SELECTED_PROTO" "$restore" >> "$tmp.new"
    mv -f "$tmp.new" "$tmp"
  done
  if ! realip_commit_entries_file "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  ok_msg "Applied ${#HAP_PORTS[@]} Real-IP port(s) -> $REALIP_TARGET_IP. Client source IP is preserved."
}

realip_change_all_ips() {
  local tmp
  tmp="$(realip_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No Real-IP forwards to update."; rm -f "$tmp"; return 0; fi
  realip_prompt_target_ip || { local rc=$?; rm -f "$tmp"; return "$rc"; }
  awk -v ip="$REALIP_TARGET_IP" '{print $1, ip, $3, $4, $5}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  if ! realip_commit_entries_file "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
}

realip_delete_port() {
  local port tmp before after
  tmp="$(realip_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No Real-IP forwards to delete."; rm -f "$tmp"; return 0; fi
  realip_list_forwards; echo
  read -rp "Enter Real-IP local port to delete (00=menu): " port
  if is_main_menu_token "$port"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_port "$port" || { err_msg "Invalid port."; rm -f "$tmp"; return 1; }
  before="$(wc -l < "$tmp" | tr -d ' ')"
  awk -v p="$port" '$1!=p' "$tmp" > "$tmp.new" || true
  after="$(wc -l < "$tmp.new" | tr -d ' ')"
  if [ "$before" = "$after" ]; then warn_msg "Port $port was not found."; rm -f "$tmp" "$tmp.new"; return 0; fi
  mv -f "$tmp.new" "$tmp"
  if ! realip_commit_entries_file "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  ok_msg "Real-IP port $port removed; HAProxy was not changed."
}

realip_change_one_ip() {
  local port tmp rc
  tmp="$(realip_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No Real-IP forwards to update."; rm -f "$tmp"; return 0; fi
  realip_list_forwards; echo
  read -rp "Enter Real-IP local port to change target (00=menu): " port
  if is_main_menu_token "$port"; then rm -f "$tmp"; return_main_msg; return 99; fi
  validate_port "$port" || { err_msg "Invalid port."; rm -f "$tmp"; return 1; }
  awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$tmp" || { warn_msg "Port $port was not found."; rm -f "$tmp"; return 0; }
  realip_prompt_target_ip; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return "$rc"; fi
  awk -v p="$port" -v ip="$REALIP_TARGET_IP" '{if($1==p) print $1,ip,$3,$4,$5; else print}' "$tmp" > "$tmp.new"
  mv -f "$tmp.new" "$tmp"
  if ! realip_commit_entries_file "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
}

realip_change_protocol() {
  local tmp port restore rc changed=0
  tmp="$(realip_entries_tmp)"
  if [ ! -s "$tmp" ]; then warn_msg "No Real-IP forwards found."; rm -f "$tmp"; return 0; fi

  realip_list_forwards
  echo
  select_ports_from_tmp "Real-IP protocol / UDP mode" "$tmp"; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return "$rc"; fi

  echo
  realip_prompt_protocol; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return "$rc"; fi
  restore="$(realip_restore_proto_for_l3 "$REALIP_SELECTED_PROTO")"

  for port in "${SELECTED_PORTS[@]}"; do
    awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$tmp" || { err_msg "Real-IP port $port was not found."; rm -f "$tmp"; return 1; }
    awk -v p="$port" -v proto="$REALIP_SELECTED_PROTO" -v hp="$restore" '{if($1==p) print $1,$2,$3,proto,hp; else print}' "$tmp" > "$tmp.new"
    mv -f "$tmp.new" "$tmp"
    changed=$((changed + 1))
  done

  if ! realip_commit_entries_file "$tmp"; then rm -f "$tmp"; return 1; fi
  rm -f "$tmp"
  ok_msg "Updated protocol for $changed Real-IP port(s) to $(realip_proto_label "$REALIP_SELECTED_PROTO")."
  [ "$REALIP_SELECTED_PROTO" = "tcp" ] && info_msg "UDP is now OFF for the selected Real-IP port(s), which should reduce handshake/latency pressure."
}

realip_repair() {
  realip_install_service
  realip_sync_all
  if realip_rules_healthy && realip_return_routing_healthy; then
    ok_msg "Real-IP repair/verification completed successfully."
  else
    err_msg "Real-IP verification still reports a missing rule/path."
    return 1
  fi
}

realip_doctor() {
  local entries port target tport proto restore route failed=0
  echo -e "${C_BOLD}${C_WHITE}Kernel Real-IP / 3x-ui diagnostic${C_RESET}"
  echo "Mode: direct DNAT without SNAT"
  echo "3x-ui inbound Proxy Protocol: keep DISABLED (this mode does not send a PROXY header)"
  echo

  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = "1" ]; then
    ok_msg "IPv4 forwarding is enabled."
  else
    err_msg "IPv4 forwarding is disabled."
    failed=1
  fi

  entries="$(realip_export_entries || true)"
  if [ -z "$entries" ]; then
    warn_msg "No Real-IP ports are configured on this server."
    return "$failed"
  fi

  while read -r port target tport proto restore; do
    [ -n "${port:-}" ] || continue
    if realip_resolve_target "$target" >/dev/null 2>&1 && tunnel_iface_is_up "$REALIP_IFACE"; then
      route="$(ip -4 route get "$target" 2>/dev/null | head -n1 || true)"
      ok_msg "$port -> $target:$tport ($(realip_proto_label "$proto")) via $REALIP_IFACE | ${route:-route unavailable}"
    else
      err_msg "$port -> $target:$tport has no active supported tunnel path."
      failed=1
    fi
  done <<< "$entries"

  if realip_rules_healthy; then
    ok_msg "All managed DNAT/FORWARD/MSS rules are present."
  else
    err_msg "One or more managed Real-IP rules are missing. Run Repair."
    failed=1
  fi

  echo
  info_msg "KHAREJ must have return routing enabled once; otherwise Xray receives the SYN but replies leave through the public gateway."
  return "$failed"
}

realip_enable_return_routing() {
  build_tunnel_inventory
  local i type id role found=0
  for i in "${!INV_TYPE[@]}"; do
    type="${INV_TYPE[$i]:-}"; id="${INV_ID[$i]:-}"
    case "$type" in gre|vira7|viratcp) ;; *) continue ;; esac
    role="$(realip_saved_role_for_item "$type" "$id" 2>/dev/null || true)"
    [ "$role" = "2" ] && { found=1; break; }
  done
  if [ "$found" -ne 1 ]; then
    err_msg "No Kharej-role GRE/Vira7/ViraTCP tunnel was detected on this server. Enable return routing on the KHAREJ server, not the Iran entry server."
    return 1
  fi
  mkdir -p "$REALIP_CONFIG_DIR"
  printf 'enabled\n' > "$REALIP_RETURN_MARKER"
  chmod 600 "$REALIP_RETURN_MARKER"
  realip_install_service
  realip_apply_return_routing
  ok_msg "Kharej Real-IP return routing ENABLED. Future health checks will keep it repaired."
}

realip_disable_return_routing() {
  rm -f "$REALIP_RETURN_MARKER"
  realip_cleanup_return_routing
  ok_msg "Kharej Real-IP return routing DISABLED on this server. Real-IP port definitions were not deleted."
}

realip_toggle_return_routing() {
  if [ -f "$REALIP_RETURN_MARKER" ]; then
    realip_disable_return_routing
  else
    realip_enable_return_routing
  fi
}

# Move one or many HAProxy rows into Real-IP without changing tunnel definitions.
# Existing HAProxy functionality remains installed; only the selected ports move.
switch_haproxy_to_realip_impl() {
  local hap_tmp real_tmp real_before port target tport hp l3 selected_count=0 rc
  hap_tmp="$(haproxy_entries_tmp)"; real_tmp="$(realip_entries_tmp)"
  real_before="$(mktemp)"
  cp -f "$real_tmp" "$real_before"
  if [ ! -s "$hap_tmp" ]; then warn_msg "No HAProxy ports are available to switch."; rm -f "$hap_tmp" "$real_tmp" "$real_before"; return 0; fi

  haproxy_list_forwards
  echo
  select_ports_from_tmp "HAProxy -> Real-IP" "$hap_tmp"; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$hap_tmp" "$real_tmp" "$real_before"; return "$rc"; fi

  echo
  realip_prompt_switch_protocol; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$hap_tmp" "$real_tmp" "$real_before"; return "$rc"; fi

  # Validate every selected row/path before changing either engine.
  for port in "${SELECTED_PORTS[@]}"; do
    target="$(awk -v p="$port" '$1==p{print $2; exit}' "$hap_tmp")"
    [ -n "$target" ] || { err_msg "HAProxy port $port was not found."; rm -f "$hap_tmp" "$real_tmp" "$real_before"; return 1; }
    if ! realip_resolve_target "$target" >/dev/null 2>&1; then
      err_msg "Port $port targets $target, which is not a supported GRE/Vira7/ViraTCP Real-IP path. Nothing was switched."
      rm -f "$hap_tmp" "$real_tmp" "$real_before"; return 1
    fi
  done

  for port in "${SELECTED_PORTS[@]}"; do
    read -r _ target tport hp < <(awk -v p="$port" '$1==p{print; exit}' "$hap_tmp")
    hp="$(haproxy_normalize_proto "${hp:-http}")"
    case "$REALIP_SWITCH_PROTO_MODE" in
      tcp) l3="tcp" ;;
      both) l3="both" ;;
      keep) [ "$hp" = "tcp" ] && l3="both" || l3="tcp" ;;
      *) l3="tcp" ;;
    esac
    awk -v p="$port" '$1!=p' "$real_tmp" > "$real_tmp.new" || true
    printf '%s %s %s %s %s\n' "$port" "$target" "$tport" "$l3" "$hp" >> "$real_tmp.new"
    mv -f "$real_tmp.new" "$real_tmp"
    awk -v p="$port" '$1!=p' "$hap_tmp" > "$hap_tmp.new" || true
    mv -f "$hap_tmp.new" "$hap_tmp"
    selected_count=$((selected_count + 1))
  done

  # Stage and verify the kernel path first. New packets can traverse Real-IP
  # immediately while the old HAProxy listener still exists, so there is no
  # empty forwarding window. Then remove only the selected HAProxy listeners.
  if ! realip_commit_entries_file "$real_tmp"; then
    err_msg "Real-IP preflight/apply failed; HAProxy was left unchanged."
    rm -f "$hap_tmp" "$real_tmp" "$real_before"; return 1
  fi
  if ! haproxy_write_entries_file "$hap_tmp"; then
    err_msg "HAProxy rewrite failed; restoring the previous Real-IP table."
    realip_write_entries_file "$real_before"
    realip_sync_rules >/dev/null 2>&1 || true
    rm -f "$hap_tmp" "$real_tmp" "$real_before"; return 1
  fi
  rm -f "$hap_tmp" "$real_tmp" "$real_before"
  ok_msg "Switched $selected_count port(s): HAProxy -> Real-IP."
  info_msg "Real-IP protocol used: $(case "$REALIP_SWITCH_PROTO_MODE" in tcp) echo TCP-only ;; both) echo TCP+UDP ;; keep) echo preserve-HAProxy-mode ;; esac)."
  info_msg "Handshake fix: Real-IP now clamps TCP MSS on the tunnel path. Keep UDP off unless the inbound really needs UDP."
  info_msg "One-time requirement: on the KHAREJ server open Real-IP Manager and enable 'Kharej return routing'. After that, future switches are done only here."
}

switch_realip_to_haproxy_impl() {
  local hap_tmp real_tmp hap_before port target tport l3 restore selected_count=0 rc
  haproxy_ensure_ready || return 1
  hap_tmp="$(haproxy_entries_tmp)"; real_tmp="$(realip_entries_tmp)"
  hap_before="$(mktemp)"
  cp -f "$hap_tmp" "$hap_before"
  if [ ! -s "$real_tmp" ]; then warn_msg "No Real-IP ports are available to switch."; rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return 0; fi

  realip_list_forwards
  echo
  select_ports_from_tmp "Real-IP -> HAProxy" "$real_tmp"; rc=$?
  if [ "$rc" -ne 0 ]; then rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return "$rc"; fi

  for port in "${SELECTED_PORTS[@]}"; do
    awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$real_tmp" || { err_msg "Real-IP port $port was not found."; rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return 1; }
    if awk -v p="$port" '$1==p{found=1} END{exit found?0:1}' "$hap_tmp"; then
      err_msg "HAProxy already contains port $port. Resolve the duplicate manually; nothing was switched."
      rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return 1
    fi
  done

  for port in "${SELECTED_PORTS[@]}"; do
    read -r _ target tport l3 restore < <(awk -v p="$port" '$1==p{print; exit}' "$real_tmp")
    restore="$(haproxy_normalize_proto "${restore:-$(realip_restore_proto_for_l3 "$l3")}")"
    printf '%s %s %s %s\n' "$port" "$target" "$tport" "$restore" >> "$hap_tmp"
    awk -v p="$port" '$1!=p' "$real_tmp" > "$real_tmp.new" || true
    mv -f "$real_tmp.new" "$real_tmp"
    selected_count=$((selected_count + 1))
  done

  # Start HAProxy first, then remove the Real-IP NAT rules. This avoids a gap if HAProxy validation fails.
  if ! haproxy_write_entries_file "$hap_tmp"; then
    err_msg "HAProxy validation/restart failed; Real-IP configuration was kept unchanged."
    rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return 1
  fi
  if ! realip_commit_entries_file "$real_tmp"; then
    err_msg "Real-IP removal failed; restoring the previous HAProxy table to avoid mixed ownership."
    haproxy_write_entries_file "$hap_before" >/dev/null 2>&1 || true
    rm -f "$hap_tmp" "$real_tmp" "$hap_before"; return 1
  fi
  rm -f "$hap_tmp" "$real_tmp" "$hap_before"
  ok_msg "Switched $selected_count port(s): Real-IP -> HAProxy. Original HAProxy protocol mode was restored."
}

# Serialize operator switches so the 20-second health repair cannot overlap a
# second manual switch. flock is part of util-linux on the supported distros.
switch_haproxy_to_realip() {
  if command -v flock >/dev/null 2>&1; then
    ( flock -w 20 9 || { err_msg "Another forwarding switch is still running."; return 1; }; switch_haproxy_to_realip_impl ) 9>"$FORWARD_SWITCH_LOCK"
  else
    switch_haproxy_to_realip_impl
  fi
}

switch_realip_to_haproxy() {
  if command -v flock >/dev/null 2>&1; then
    ( flock -w 20 9 || { err_msg "Another forwarding switch is still running."; return 1; }; switch_realip_to_haproxy_impl ) 9>"$FORWARD_SWITCH_LOCK"
  else
    switch_realip_to_haproxy_impl
  fi
}

forward_switch_menu() {
  while true; do
    show_header "Switch Forwarding Engine"
    echo -e "${C_BOLD}${C_WHITE}Switch Menu${C_RESET}"
    echo -e "  ${C_CYAN}1)${C_RESET} show HAProxy + Real-IP tables"
    echo -e "  ${C_GREEN}2)${C_RESET} HAProxy -> Real-IP ${C_DIM}(0 = ALL during selection; TCP-only default)${C_RESET}"
    echo -e "  ${C_YELLOW}3)${C_RESET} Real-IP -> HAProxy ${C_DIM}(0 = ALL during selection)${C_RESET}"
    echo -e "  ${C_GREEN}4)${C_RESET} repair/sync Real-IP rules"
    echo -e "  ${C_DIM}00) Back${C_RESET}"
    echo
    read -rp "Choose switch option [1-4/00]: " FWD_SWITCH_CHOICE
    case "$FWD_SWITCH_CHOICE" in
      1) haproxy_list_forwards; echo; realip_list_forwards; pause ;;
      2) haproxy_run_action switch_haproxy_to_realip || return 0 ;;
      3) haproxy_run_action switch_realip_to_haproxy || return 0 ;;
      4) haproxy_run_action realip_repair || return 0 ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

realip_menu() {
  mkdir -p "$REALIP_CONFIG_DIR"
  while true; do
    show_header "Real-IP Port Forward Manager"
    echo -e "${C_BOLD}${C_WHITE}Real-IP Menu (DNAT without SNAT + MSS clamp)${C_RESET}"
    echo -e "${C_DIM}Status${C_RESET}"
    echo -e "  ${C_GREEN}1)${C_RESET} list Real-IP ports + return-routing status"
    echo
    echo -e "${C_DIM}Quick switch${C_RESET}"
    echo -e "  ${C_GREEN}2)${C_RESET} switch HAProxy -> Real-IP ${C_DIM}(0 = ALL; TCP-only default)${C_RESET}"
    echo -e "  ${C_YELLOW}3)${C_RESET} switch Real-IP -> HAProxy ${C_DIM}(0 = ALL)${C_RESET}"
    echo
    echo -e "${C_DIM}Real-IP ports${C_RESET}"
    echo -e "  ${C_GREEN}4)${C_RESET} add/update Real-IP port(s) ${C_DIM}(TCP-only default)${C_RESET}"
    echo -e "  ${C_CYAN}5)${C_RESET} change target for one port"
    echo -e "  ${C_YELLOW}6)${C_RESET} change target for ALL ports"
    echo -e "  ${C_MAGENTA}7)${C_RESET} set protocol / UDP mode ${C_DIM}(0 = ALL; choose TCP-only or TCP+UDP)${C_RESET}"
    echo -e "  ${C_RED}8)${C_RESET} delete port"
    echo
    echo -e "${C_DIM}Repair / backend${C_RESET}"
    echo -e "  ${C_GREEN}9)${C_RESET} repair + verify Real-IP rules"
    echo -e "  ${C_BLUE}10)${C_RESET} toggle KHAREJ return routing ${C_DIM}(one-time backend setup)${C_RESET}"
    echo -e "  ${C_CYAN}11)${C_RESET} 3x-ui Real-IP doctor ${C_DIM}(Proxy Protocol stays OFF)${C_RESET}"
    echo -e "  ${C_DIM}00) Back to main menu${C_RESET}"
    echo
    read -rp "Choose Real-IP option [1-11/00]: " REALIP_CHOICE
    case "$REALIP_CHOICE" in
      1) haproxy_run_action realip_list_forwards || return 0 ;;
      2) haproxy_run_action switch_haproxy_to_realip || return 0 ;;
      3) haproxy_run_action switch_realip_to_haproxy || return 0 ;;
      4) haproxy_run_action realip_add_port || return 0 ;;
      5) haproxy_run_action realip_change_one_ip || return 0 ;;
      6) haproxy_run_action realip_change_all_ips || return 0 ;;
      7) haproxy_run_action realip_change_protocol || return 0 ;;
      8) haproxy_run_action realip_delete_port || return 0 ;;
      9) haproxy_run_action realip_repair || return 0 ;;
      10) haproxy_run_action realip_toggle_return_routing || return 0 ;;
      11) haproxy_run_action realip_doctor || return 0 ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

show_menu() {
  show_header "GRE + WireGuard + Vira7 + Reverse ViraTCP v${APP_VERSION}"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel"
  echo -e "  ${C_RED}2)${C_RESET} remove tunnel"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} haproxy port manager"
  echo -e "  ${C_BLUE}6)${C_RESET} reverse tunnel wizard ${C_DIM}(ViraTCP; TCP transport carries TCP + UDP)${C_RESET}"
  echo -e "  ${C_GREEN}7)${C_RESET} Real-IP port manager ${C_DIM}(lowest CPU; Proxy Protocol OFF)${C_RESET}"
  echo -e "  ${C_YELLOW}8)${C_RESET} switch forwarding engine ${C_DIM}(HAProxy <-> Real-IP)${C_RESET}"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  read -rp "Choose an option [0-8]: " CHOICE
  case "$CHOICE" in
    1) if menu_config_tunnel; then pause; fi ;;
    2) if remove_tun; then pause; fi ;;
    3) if reset_all_tunnels; then pause; fi ;;
    4) if test_tunnels_menu; then pause; fi ;;
    5) haproxy_menu || true ;;
    6) if viratcp_menu_config_tunnel; then pause; fi ;;
    7) realip_menu || true ;;
    8) forward_switch_menu || true ;;
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
    supervise-gre)
      ensure_root
      gre_supervisor "${3:-}"
      exit $?
      ;;
    health-check-all)
      ensure_root
      tunnel_health_check_all
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
    start-viratcp)
      ensure_root
      viratcp_restart_one_tunnel "${3:-}"
      exit $?
      ;;
    haproxy-udp-sync)
      ensure_root
      haproxy_sync_udp_rules
      exit $?
      ;;
    haproxy-udp-repair)
      ensure_root
      haproxy_periodic_udp_repair
      exit $?
      ;;
    realip-sync)
      ensure_root
      realip_sync_all
      exit $?
      ;;
    *)
      echo "Unknown service command. Use --service supervise-gre <id>, health-check-all, haproxy-udp-sync, haproxy-udp-repair, or realip-sync." >&2
      exit 1
      ;;
  esac
fi

ensure_root
bootstrap_runtime_repairs >/dev/null 2>&1 || true
while true; do
  show_menu
done
