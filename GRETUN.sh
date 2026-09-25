#!/bin/bash
set -euo pipefail

# GRE + GRE Plus + WireGuard + HAProxy tunnel manager v12.0.0
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - WireGuard can use public UDP or automatically ride over an existing GRE tunnel as transport
# - Local tunnel/bind IPv4 can be selected manually for servers with multiple IPs
# - v8.5-safe-remove-heal prevents removing active transports used by WireGuard and re-heals remaining tunnels after deletion
# - v8.6-self-heal keeps GRE under a persistent supervisor, disables rp_filter for encapsulated paths,
#   pins public peer routes to the physical uplink, and repairs GRE/WireGuard in dependency order
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
# - v8.8.4 adds iperf3 tunnel throughput tests.
# - v10.1.0 removes aggregation from the main menu and adds persistent disconnect/error diagnostics.
#   Health failures, automatic/manual restarts, service state, interface state, routes, and recent journal
#   messages are retained under /var/log/gretun-manager for troubleshooting short interruptions.
# - v11.0.0 removes Vira7/ViraTCP and ECMP aggregation from the manager.
#   It adds verified WSTunnel 11.0.0 as an HTTPS/WebSocket transport for WireGuard, keeps GRE->WireGuard
#   as the preferred fast path, prevents health/reset races, and adds safe capacity/performance tuning.
# - v11.0.1 makes the WSS WireGuard UDP port deterministic (51800 + tunnel number)
#   on both peers, removes the redundant Iran-side remote UDP-port question, and fails clearly on conflicts.
# - v11.0.2 restores GitHub process-substitution installs by fetching the canonical GRETUN.sh filename.
# - v12.0.0 removes WSS and adds fully independent GRE Plus tunnels with greplusN interfaces,
#   10.30.N.x addressing, separate configs/services/keys, adaptive MTU, fq scheduling,
#   strict peer firewall rules and larger queues.
# - v12.0.1 stops GRE Plus supervisors from rewriting UFW every 10 seconds.
# - HAProxy fix: preserve an existing global maxconn, use the known-working defaults,
#   and stop changing system limits or restarting HAProxy simply by opening its menu.

APP_VERSION="12.0.1"

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
MAINTENANCE_FLAG="/run/gretun-manager.maintenance"
DIAG_LOG_DIR="/var/log/gretun-manager"
DIAG_EVENT_LOG="$DIAG_LOG_DIR/events.log"
DIAG_DETAIL_LOG="$DIAG_LOG_DIR/diagnostics.log"
DIAG_SERVICE_LOG="$DIAG_LOG_DIR/services.log"
DIAG_EVENT_MAX_BYTES=5242880
DIAG_DETAIL_MAX_BYTES=20971520
SELF_RAW_URL="https://raw.githubusercontent.com/0fariid0/GRE-TUN/refs/heads/main/GRETUN.sh"

WG_META_DIR="/etc/wgtun-tunnels"
WG_KEY_DIR="$WG_META_DIR/keys"
WG_CONFIG_DIR="/etc/wireguard"
WG_IFACE_PREFIX="wgtun"

# Legacy WSS paths are retained only for upgrade cleanup; v12 cannot create WSS.
WSS_CONFIG_DIR="/etc/gretun-wss"
WSS_BINARY="/usr/local/bin/wstunnel"
WSS_SERVICE_TEMPLATE="/etc/systemd/system/gretun-wss@.service"

GREPLUS_CONFIG_DIR="/etc/greplus-tunnels"
GREPLUS_SERVICE_TEMPLATE="/etc/systemd/system/greplus-tunnel@.service"
GREPLUS_IFACE_PREFIX="greplus"
GREPLUS_KEY_BASE=100000
GREPLUS_FALLBACK_MTU=1440
GREPLUS_DEFAULT_TXQUEUELEN=10000

VIRA7_CONFIG_DIR="/etc/vira7-tunnels"
VIRA7_BINARY="/usr/local/bin/vira7-engine"
VIRA7_SERVICE_TEMPLATE="/etc/systemd/system/vira7-tunnel@.service"
VIRATCP_CONFIG_DIR="/etc/viratcp-tunnels"
VIRATCP_BINARY="/usr/local/bin/viratcp-engine"
VIRATCP_SERVICE_TEMPLATE="/etc/systemd/system/viratcp-tunnel@.service"

HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"
HAPROXY_BACKUP_DIR="/etc/haproxy/gretun-backups"
HAPROXY_MAXCONN=500000
PERFORMANCE_SYSCTL_FILE="/etc/sysctl.d/99-gretun-performance.conf"
HAPROXY_UDP_SERVICE_NAME="gretun-haproxy-udp.service"
HAPROXY_UDP_SERVICE_UNIT="/etc/systemd/system/${HAPROXY_UDP_SERVICE_NAME}"
HAPROXY_UDP_REPAIR_SERVICE_NAME="gretun-haproxy-udp-repair.service"
HAPROXY_UDP_REPAIR_SERVICE_UNIT="/etc/systemd/system/${HAPROXY_UDP_REPAIR_SERVICE_NAME}"
HAPROXY_UDP_REPAIR_TIMER_NAME="gretun-haproxy-udp-repair.timer"
HAPROXY_UDP_REPAIR_TIMER_UNIT="/etc/systemd/system/${HAPROXY_UDP_REPAIR_TIMER_NAME}"

AGG_CONFIG_DIR="/etc/gretun-aggregate"
AGG_SERVICE_TEMPLATE="/etc/systemd/system/gretun-aggregate@.service"
AGG_IFACE_PREFIX="gtagg"
AGG_PATH_IFACE_PREFIX="ga"
AGG_FAIL_LIMIT=3
WG_RECENT_HANDSHAKE_SECONDS=180
DEPENDENCY_STATE_DIR="/var/lib/gretun-manager/dependencies"

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

diagnostic_prepare_logs() {
  mkdir -p "$DIAG_LOG_DIR" 2>/dev/null || return 1
  touch "$DIAG_EVENT_LOG" "$DIAG_DETAIL_LOG" "$DIAG_SERVICE_LOG" 2>/dev/null || return 1
  chmod 700 "$DIAG_LOG_DIR" 2>/dev/null || true
  chmod 600 "$DIAG_EVENT_LOG" "$DIAG_DETAIL_LOG" "$DIAG_SERVICE_LOG" 2>/dev/null || true
}

diagnostic_install_logrotate() {
  diagnostic_prepare_logs || return 0
  [ -d /etc/logrotate.d ] || return 0
  cat > /etc/logrotate.d/gretun-manager <<'EOF_LOGROTATE'
/var/log/gretun-manager/*.log {
    daily
    size 10M
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    su root root
}
EOF_LOGROTATE
}

diagnostic_rotate_file() {
  local file="$1" max_bytes="$2" size=0
  [ -f "$file" ] || return 0
  size="$(stat -c '%s' "$file" 2>/dev/null || echo 0)"
  [[ "$size" =~ ^[0-9]+$ ]] || size=0
  if [ "$size" -ge "$max_bytes" ]; then
    mv -f "$file" "${file}.1" 2>/dev/null || true
    : > "$file" 2>/dev/null || true
    chmod 600 "$file" 2>/dev/null || true
  fi
}

diagnostic_event() {
  local level="${1:-INFO}" component="${2:-manager}" message="${3:-}"
  message="${message//$'\n'/ }"
  diagnostic_prepare_logs || return 0
  diagnostic_rotate_file "$DIAG_EVENT_LOG" "$DIAG_EVENT_MAX_BYTES"
  if command -v flock >/dev/null 2>&1; then
    (
      flock -x 9
      printf '%s [%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$level" "$component" "$message" >&9
    ) 9>>"$DIAG_EVENT_LOG" || true
  else
    printf '%s [%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$level" "$component" "$message" >> "$DIAG_EVENT_LOG" 2>/dev/null || true
  fi
}

# Save evidence immediately before a repair/restart. This is intentionally
# independent from journald so the reason survives journal rotation/reboots.
diagnostic_capture() {
  local kind="${1:-unknown}" id="${2:-?}" ifc="${3:-}" svc="${4:-}" target="${5:-}" reason="${6:-unspecified}"
  diagnostic_prepare_logs || return 0
  diagnostic_rotate_file "$DIAG_DETAIL_LOG" "$DIAG_DETAIL_MAX_BYTES"
  {
    echo
    echo "======================================================================"
    printf 'Captured : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"
    printf 'Tunnel   : %s %s\n' "$kind" "$id"
    printf 'Reason   : %s\n' "$reason"
    printf 'Service  : %s\n' "${svc:-N/A}"
    printf 'Interface: %s\n' "${ifc:-N/A}"
    printf 'Target   : %s\n' "${target:-N/A}"
    echo "----------------------------------------------------------------------"
    if [ -n "$svc" ] && command -v systemctl >/dev/null 2>&1; then
      echo "[systemd state]"
      systemctl show "$svc" --no-pager \
        -p ActiveState -p SubState -p Result -p NRestarts -p ExecMainStatus \
        -p ExecMainCode -p ActiveEnterTimestamp -p InactiveEnterTimestamp 2>&1 || true
    fi
    if [ -n "$ifc" ]; then
      echo "[interface]"
      ip -details link show dev "$ifc" 2>&1 || true
      ip -4 addr show dev "$ifc" 2>&1 || true
      ip -s link show dev "$ifc" 2>&1 || true
    fi
    if [ -n "$target" ]; then
      target="${target%%/*}"
      echo "[route to target]"
      ip -4 route get "$target" 2>&1 || true
    fi
    echo "[default route]"
    ip -4 route show default 2>&1 || true
    if [ -n "$svc" ] && command -v journalctl >/dev/null 2>&1; then
      echo "[recent service journal: last 5 minutes / 80 lines]"
      journalctl -u "$svc" --since '-5 minutes' -n 80 --no-pager -o short-iso 2>&1 || true
    fi
    echo "[recent kernel network messages]"
    journalctl -k --since '-5 minutes' -n 40 --no-pager -o short-iso 2>&1 || true
    echo "======================================================================"
  } >> "$DIAG_DETAIL_LOG" 2>&1 || true
}

restart_service_with_diagnostics() {
  local kind="$1" id="$2" ifc="$3" svc="$4" target="${5:-}" reason="${6:-health failure}"
  diagnostic_event "ERROR" "$kind-$id" "$reason; automatic restart requested (service=$svc interface=$ifc target=${target:-N/A})"
  diagnostic_capture "$kind" "$id" "$ifc" "$svc" "$target" "$reason"
  if systemctl restart "$svc" >/dev/null 2>&1; then
    diagnostic_event "RESTART" "$kind-$id" "service restart succeeded: $svc"
    return 0
  fi
  diagnostic_event "ERROR" "$kind-$id" "service restart FAILED: $svc"
  return 1
}

diagnostic_service_line() {
  local component="${1:-service}" line="${2:-}"
  diagnostic_prepare_logs || return 0
  if command -v flock >/dev/null 2>&1; then
    (
      flock -x 9
      printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$component" "$line" >&9
    ) 9>>"$DIAG_SERVICE_LOG" || true
  else
    printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$component" "$line" >> "$DIAG_SERVICE_LOG" 2>/dev/null || true
  fi
}

# Run reconnecting tunnel engines through a timestamping wrapper so even a
# two-second disconnect emitted by the engine is retained with an exact time.
run_logged_tunnel_engine() {
  local kind="$1" id="$2" binary="$3" config="$4" line rc
  [ -x "$binary" ] || { diagnostic_event "ERROR" "$kind-$id" "engine is missing or not executable: $binary"; return 1; }
  [ -f "$config" ] || { diagnostic_event "ERROR" "$kind-$id" "engine config is missing: $config"; return 1; }
  diagnostic_event "START" "$kind-$id" "engine process started"
  set +e
  "$binary" "$config" 2>&1 | while IFS= read -r line || [ -n "$line" ]; do
    diagnostic_service_line "$kind-$id" "$line"
  done
  rc="${PIPESTATUS[0]}"
  set -e
  if [ "$rc" -eq 0 ]; then
    diagnostic_event "STOP" "$kind-$id" "engine process exited normally"
  else
    diagnostic_event "ERROR" "$kind-$id" "engine process exited with code $rc; systemd will restart it"
  fi
  return "$rc"
}

is_main_menu_token() { [ "${1:-}" = "00" ]; }
return_main_msg() { echo -e "${C_CYAN}Returning to main menu...${C_RESET}"; }

maintenance_begin() {
  printf '%s %s\n' "$$" "$(date +%s)" > "$MAINTENANCE_FLAG" 2>/dev/null || true
}

maintenance_end() {
  rm -f "$MAINTENANCE_FLAG" 2>/dev/null || true
}

maintenance_is_active() {
  local started now
  [ -f "$MAINTENANCE_FLAG" ] || return 1
  started="$(awk 'NR==1{print $2}' "$MAINTENANCE_FLAG" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  [[ "$started" =~ ^[0-9]+$ ]] || started=0
  if [ "$started" -gt 0 ] && [ $((now - started)) -lt 900 ]; then
    return 0
  fi
  rm -f "$MAINTENANCE_FLAG" 2>/dev/null || true
  return 1
}

run_maintenance_action() {
  local rc
  maintenance_begin
  set +e
  "$@"
  rc=$?
  set -e
  maintenance_end
  return "$rc"
}

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
  printf "${C_CYAN}${C_BOLD}║${C_RESET} %-52s ${C_CYAN}${C_BOLD}║${C_RESET}\n" "$title"
  printf "${C_CYAN}${C_BOLD}║${C_RESET} Local public IP: %-35s ${C_CYAN}${C_BOLD}║${C_RESET}\n" "${ip_addr:-UNKNOWN}"
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
  echo "2) WireGuard tunnel (direct UDP or automatically over same-number GRE)"
  echo "3) GRE Plus (separate high-capacity GRE, no encryption)"
  echo
  read -rp "Choose [1-3] (00=menu): " TUNNEL_TYPE_CHOICE
  if is_main_menu_token "$TUNNEL_TYPE_CHOICE"; then return_main_msg; return 99; fi
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE="gre" ;;
    2) SELECTED_TUNNEL_TYPE="wireguard" ;;
    3) SELECTED_TUNNEL_TYPE="greplus" ;;
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

# Check first, install only what is missing, and never run a package-index refresh
# on later invocations when all required commands are already available.
ensure_feature_dependencies() {
  local feature="$1"; shift
  local spec cmd pkg missing=0
  local -a packages=()

  for spec in "$@"; do
    cmd="${spec%%:*}"
    pkg="${spec#*:}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing=1
      packages+=("$pkg")
    fi
  done
  [ "$missing" -eq 1 ] || return 0

  # De-duplicate package names before calling the package manager.
  local -A seen_pkg=()
  local -a unique_packages=()
  for pkg in "${packages[@]}"; do
    if [ -z "${seen_pkg[$pkg]+x}" ]; then
      unique_packages+=("$pkg")
      seen_pkg[$pkg]=1
    fi
  done

  info_msg "$feature prerequisites are missing; installing: ${unique_packages[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    # apt-get update is intentionally reached only when a required command is missing.
    DEBIAN_FRONTEND=noninteractive apt-get update || return 1
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${unique_packages[@]}" || return 1
  elif command -v dnf >/dev/null 2>&1; then
    packages=()
    for pkg in "${unique_packages[@]}"; do
      case "$pkg" in iproute2) packages+=(iproute) ;; iputils-ping) packages+=(iputils) ;; *) packages+=("$pkg") ;; esac
    done
    dnf install -y "${packages[@]}" || return 1
  elif command -v yum >/dev/null 2>&1; then
    packages=()
    for pkg in "${unique_packages[@]}"; do
      case "$pkg" in iproute2) packages+=(iproute) ;; iputils-ping) packages+=(iputils) ;; *) packages+=("$pkg") ;; esac
    done
    yum install -y "${packages[@]}" || return 1
  else
    err_msg "No supported package manager found for $feature prerequisites."
    return 1
  fi

  for spec in "$@"; do
    cmd="${spec%%:*}"
    command -v "$cmd" >/dev/null 2>&1 || {
      err_msg "$feature prerequisite is still unavailable after installation: $cmd"
      return 1
    }
  done
  mkdir -p "$DEPENDENCY_STATE_DIR" 2>/dev/null || true
  printf '%s\n' "checked=$(date -u +%FT%TZ)" > "$DEPENDENCY_STATE_DIR/$feature.ok" 2>/dev/null || true
}

# Install a persistent copy safely. When this script is launched with
#   bash <(curl ...)
# $0 points to a live pipe (/dev/fd/N). Copying that pipe consumes the unread
# tail of the running script and makes the menu disappear. In that case fetch
# a complete regular-file copy instead; for normal file execution copy locally.
install_manager_binary() {
  local source_path="${BASH_SOURCE[0]:-$0}"
  local target_dir tmp
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

firewall_allow_tcp_port_and_ip() {
  local label="$1"
  local port="$2"
  local peer_ip="${3:-}"
  local ifc="${4:-}"
  local listen_mode="${5:-0}"

  if command -v iptables >/dev/null 2>&1; then
    if [ "$listen_mode" = "1" ]; then
      iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -p tcp --dport "$port" -j ACCEPT || true
    fi
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      iptables -C OUTPUT -d "$peer_ip" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -d "$peer_ip" -p tcp --dport "$port" -j ACCEPT || true
      if [ "$listen_mode" = "1" ]; then
        iptables -C INPUT -s "$peer_ip" -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -s "$peer_ip" -p tcp --dport "$port" -j ACCEPT || true
      fi
    fi
    if [ -n "$ifc" ]; then
      iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -j ACCEPT || true
      iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -j ACCEPT || true
      iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ifc" -j ACCEPT || true
      iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$ifc" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    if [ "$listen_mode" = "1" ]; then ufw allow "$port/tcp" >/dev/null 2>&1 || true; fi
    if [ -n "$peer_ip" ] && validate_ipv4 "$peer_ip"; then
      ufw allow out to "$peer_ip" port "$port" proto tcp >/dev/null 2>&1 || true
      if [ "$listen_mode" = "1" ]; then ufw allow from "$peer_ip" to any port "$port" proto tcp >/dev/null 2>&1 || true; fi
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
# gretun-self-heal: stable settings for GRE/WireGuard encapsulation
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.fib_multipath_hash_policy=1
EOF_SYSCTL
  fi

  if ! grep -q '^net.ipv4.fib_multipath_hash_policy=' "$sysctl_file" 2>/dev/null; then
    echo 'net.ipv4.fib_multipath_hash_policy=1' >> "$sysctl_file"
  fi

  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.fib_multipath_hash_policy=1 >/dev/null 2>&1 || true

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
    gre*|wgtun*|ga*|gtagg*|"")
      route="$(ip -4 route get 1.1.1.1 from "$local_ip" 2>/dev/null | head -n 1 || true)"
      dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
      gateway="$(awk '{for(i=1;i<=NF;i++) if($i=="via") {print $(i+1); exit}}' <<< "$route")"
      ;;
  esac

  [ -n "$dev" ] || return 0
  case "$dev" in gre*|wgtun*|ga*|gtagg*) return 0 ;; esac
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

# A recent authenticated handshake is stronger evidence of a working
# WireGuard transport than an ICMP probe, especially while the path is full.
wg_iface_has_recent_handshake() {
  local ifc="${1:-}" max_age="${2:-$WG_RECENT_HANDSHAKE_SECONDS}"
  local latest now
  [ -n "$ifc" ] && command -v wg >/dev/null 2>&1 || return 1
  latest="$(wg show "$ifc" latest-handshakes 2>/dev/null | awk '$2 > m {m=$2} END {print m+0}')"
  [[ "$latest" =~ ^[0-9]+$ ]] && [ "$latest" -gt 0 ] || return 1
  now="$(date +%s)"
  [ $((now - latest)) -le "$max_age" ]
}

transport_has_recent_wg_handshake() {
  local transport_type="$1" transport_id="$2" ids wg_id
  ids="$(wg_collect_ids 2>/dev/null || true)"
  while IFS= read -r wg_id; do
    [ -n "$wg_id" ] || continue
    if wg_uses_transport_tunnel "$wg_id" "$transport_type" "$transport_id" && \
       wg_iface_has_recent_handshake "$(wg_iface_name "$wg_id")"; then
      return 0
    fi
  done <<< "$ids"
  return 1
}

health_counter_reset() {
  local kind="$1" id="$2" file previous=""
  file="$HEALTH_STATE_DIR/${kind}-${id}.fail"
  if [ -f "$file" ]; then
    previous="$(cat "$file" 2>/dev/null || true)"
    diagnostic_event "RECOVERED" "$kind-$id" "health check recovered after ${previous:-unknown} consecutive failure(s)"
  fi
  rm -f "$file" 2>/dev/null || true
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
        diagnostic_event "RESTART" "wireguard-$wg_id" "restart triggered because transport $transport_type-$transport_id was repaired"
        if systemctl restart "$svc" >/dev/null 2>&1; then
          diagnostic_event "RESTART" "wireguard-$wg_id" "dependent service restart succeeded: $svc"
        else
          diagnostic_event "ERROR" "wireguard-$wg_id" "dependent service restart FAILED: $svc"
        fi
      fi
    fi
  done <<< "$ids"
}

install_health_monitor() {
  command -v systemctl >/dev/null 2>&1 || return 0
  mkdir -p "$(dirname "$INSTALL_BIN")" "$HEALTH_STATE_DIR" 2>/dev/null || true
  diagnostic_install_logrotate || true
  if [ ! -s "$INSTALL_BIN" ]; then
    install_manager_binary >/dev/null 2>&1 || return 1
  fi

  cat > "$HEALTH_SERVICE_UNIT" <<EOF_HEALTH_SERVICE
[Unit]
Description=GRE/GRE Plus/WireGuard dependency-aware health check
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service health-check-all
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG
EOF_HEALTH_SERVICE

  cat > "$HEALTH_TIMER_UNIT" <<'EOF_HEALTH_TIMER'
[Unit]
Description=Run GRE/GRE Plus/WireGuard health check periodically

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
      diagnostic_event "ERROR" "gre-$id" "supervisor stopped: saved configuration is missing or invalid"
      return 1
    fi
    ifc="$(gre_iface "$id")"
    target="${REMOTE_GRE_IP:-$(gre_remote_inner_ip_for_role "$id" "${ROLE:-2}")}"
    apply_tunnel_sysctls
    ensure_public_endpoint_route "${REMOTE_PUBLIC_IP:-}" "${LOCAL_PUBLIC_IP:-}"

    if ! tunnel_iface_is_up "$ifc"; then
      echo "GRE supervisor: $ifc is missing/down; recreating tunnel $id" >&2
      diagnostic_event "ERROR" "gre-$id" "interface $ifc is missing/down; recreating tunnel"
      diagnostic_capture "gre" "$id" "$ifc" "$(gre_service_name "$id")" "$target" "interface missing or down"
      if gre_create_tunnel 0; then
        diagnostic_event "RESTART" "gre-$id" "tunnel recreation succeeded after interface disappeared"
        failures=0
        restart_wg_dependents_for_transport gre "$id"
      else
        diagnostic_event "ERROR" "gre-$id" "tunnel recreation FAILED after interface disappeared"
        sleep "$GRE_SUPERVISOR_INTERVAL"
        continue
      fi
    elif transport_has_recent_wg_handshake gre "$id" || quick_tunnel_ping "$ifc" "$target"; then
      failures=0
    else
      failures=$((failures + 1))
      diagnostic_event "WARN" "gre-$id" "inner reachability check failed ($failures/$GRE_SUPERVISOR_FAIL_LIMIT), interface=$ifc target=$target"
      if [ "$failures" -ge "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        echo "GRE supervisor: tunnel $id failed $failures health checks; recreating" >&2
        diagnostic_capture "gre" "$id" "$ifc" "$(gre_service_name "$id")" "$target" "$failures consecutive inner reachability failures"
        if gre_create_tunnel 0; then
          diagnostic_event "RESTART" "gre-$id" "tunnel recreation succeeded after $failures failed checks"
          restart_wg_dependents_for_transport gre "$id"
        else
          diagnostic_event "ERROR" "gre-$id" "tunnel recreation FAILED after $failures failed checks"
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
LimitNOFILE=262144
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

tunnel_health_check_all() {
  # Do not fight a manual create/remove/reset operation. The flag self-expires
  # after 15 minutes so an interrupted SSH session cannot disable healing forever.
  maintenance_is_active && return 0
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
        restart_service_with_diagnostics "gre" "$id" "$ifc" "$svc" "" "service inactive or interface missing during periodic health check" || true
      fi
    fi
  done <<< "$ids"

  # GRE Plus is independent of normal GRE and has its own interface/service.
  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(greplus_service_name "$id")"
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      ifc="$(greplus_iface "$id")"
      if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
        restart_service_with_diagnostics "greplus" "$id" "$ifc" "$svc" "" "service inactive or interface missing during periodic health check" || true
      fi
    fi
  done <<< "$ids"

  # WireGuard is checked last so its optional normal-GRE transport is repaired first.
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
      gre)
        if ! tunnel_iface_is_up "${WG_TRANSPORT_IFACE:-}"; then transport_ok=0; fi
        ;;
    esac
    if [ "$transport_ok" -ne 1 ]; then
      diagnostic_event "WARN" "wireguard-$id" "health check skipped because transport interface ${WG_TRANSPORT_IFACE:-unknown} is down"
      health_counter_reset wireguard "$id"
      continue
    fi
    wg_apply_firewall_rules "$id" >/dev/null 2>&1 || true

    if ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
      restart_service_with_diagnostics "wireguard" "$id" "$ifc" "$svc" "$target" "service inactive or interface missing" || true
      health_counter_reset wireguard "$id"
    elif wg_iface_has_recent_handshake "$ifc" || quick_tunnel_ping "$ifc" "$target"; then
      health_counter_reset wireguard "$id"
    else
      count="$(health_counter_fail wireguard "$id")"
      diagnostic_event "WARN" "wireguard-$id" "handshake is stale and inner ping failed ($count/$HEALTH_FAIL_LIMIT), interface=$ifc target=$target"
      if [ "$count" -ge "$HEALTH_FAIL_LIMIT" ]; then
        restart_service_with_diagnostics "wireguard" "$id" "$ifc" "$svc" "$target" "$count stale-handshake/inner-ping failures" || true
        health_counter_reset wireguard "$id"
      fi
    fi
  done <<< "$ids"

  # HAProxy UDP companions are checked last. This is intentionally lightweight:
  # when all four managed rules exist for every TCP row, nothing is changed.
  # If firewall/NAT rules disappear, run the same rebuild+verify logic as menu option 8.
  haproxy_udp_self_heal_check || true
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
  [ -d "$GREPLUS_CONFIG_DIR" ] && greplus_write_service_template >/dev/null 2>&1 || true
  install_health_monitor
  apply_tunnel_sysctls
  systemctl daemon-reload >/dev/null 2>&1 || true

  # v11 does not run removed tunnel engines. Stop legacy instances during
  # migration; menu 8 offers explicit deletion of their files after confirmation.
  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl disable --now "$(vira7_service_name "$id")" >/dev/null 2>&1 || true
    ip link delete "$(vira7_iface_name "$id")" >/dev/null 2>&1 || true
  done <<< "$ids"
  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl disable --now "$(viratcp_service_name "$id")" >/dev/null 2>&1 || true
    ip link delete "$(viratcp_iface_name "$id")" >/dev/null 2>&1 || true
  done <<< "$ids"
  ids="$(aggregate_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl disable --now "$(aggregate_service_name "$id")" >/dev/null 2>&1 || true
    ip link delete "$(aggregate_iface_name "$id")" >/dev/null 2>&1 || true
  done <<< "$ids"
  for ifc in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(vira7|viratcp|ga|gtagg)[0-9]+(@|$)/ {sub(/@.*/, "", $2); print $2}'); do
    ip link delete "$ifc" >/dev/null 2>&1 || true
  done

  ids="$(gre_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(gre_service_name "$id")"
    ifc="$(gre_iface "$id")"
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if [ "$migrate" -eq 1 ] || ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
        restart_service_with_diagnostics "gre" "$id" "$ifc" "$svc" "" "startup repair: service migration, inactive service, or missing interface" || true
      fi
    fi
  done <<< "$ids"

  # Existing HAProxy users upgrading to v8.8.3 get the UDP repair timer
  # automatically on the next manager launch; no need to enter the HAProxy menu.
  if [ -f "$HAPROXY_CONFIG" ] && command -v haproxy >/dev/null 2>&1; then
    haproxy_install_udp_service >/dev/null 2>&1 || true
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
  # v12 no longer runs WSS. Stop legacy instances; menu 8 can delete their files.
  ids="$(wss_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl disable --now "$(wss_service_name "$id")" >/dev/null 2>&1 || true
  done <<< "$ids"

  # Convert old WireGuard-over-WSS metadata to v12 direct UDP or same-number
  # normal GRE. This prevents an enabled wg-quick service from pointing at a
  # stopped localhost WSS relay after the upgrade.
  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    wg_migrate_legacy_wss_meta "$id" >/dev/null 2>&1 || true
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
# GRE Plus helpers (independent high-capacity GRE)
# -----------------------------
greplus_iface() { echo "${GREPLUS_IFACE_PREFIX}$1"; }
greplus_config_file() { echo "$GREPLUS_CONFIG_DIR/tunnel-$1.conf"; }
greplus_service_name() { echo "greplus-tunnel@$1.service"; }
greplus_key() { echo $((GREPLUS_KEY_BASE + $1)); }

greplus_inner_ip_for_role() {
  local id="$1" role="$2"
  [ "$role" = "1" ] && echo "10.30.$id.1" || echo "10.30.$id.2"
}

greplus_remote_inner_ip_for_role() {
  local id="$1" role="$2"
  [ "$role" = "1" ] && echo "10.30.$id.2" || echo "10.30.$id.1"
}

greplus_collect_ids() {
  local f id
  [ -d "$GREPLUS_CONFIG_DIR" ] || return 0
  for f in "$GREPLUS_CONFIG_DIR"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}

greplus_detect_mtu() {
  local remote_ip="$1" route parent_dev parent_mtu max_inner candidate
  route="$(ip -4 route get "$remote_ip" 2>/dev/null | head -n1 || true)"
  parent_dev="$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<< "$route")"
  parent_mtu="$(ip -o link show dev "$parent_dev" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  [[ "$parent_mtu" =~ ^[0-9]+$ ]] || parent_mtu=1500
  max_inner=$((parent_mtu - 28))
  [ "$max_inner" -gt 1472 ] && max_inner=1472
  [ "$max_inner" -lt 1280 ] && max_inner=1280

  if command -v ping >/dev/null 2>&1; then
    for candidate in "$max_inner" "$GREPLUS_FALLBACK_MTU" 1400; do
      [ "$candidate" -le "$max_inner" ] || continue
      if ping -4 -n -M do -c 1 -W 1 -s "$candidate" "$remote_ip" >/dev/null 2>&1; then
        echo "$candidate"
        return 0
      fi
    done
  fi
  [ "$max_inner" -lt "$GREPLUS_FALLBACK_MTU" ] && echo "$max_inner" || echo "$GREPLUS_FALLBACK_MTU"
}

greplus_save_config() {
  local file
  mkdir -p "$GREPLUS_CONFIG_DIR"
  file="$(greplus_config_file "$TUNNEL_ID")"
  {
    write_var TUNNEL_TYPE "greplus"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var ROLE "$ROLE"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_GREPLUS_IP "$LOCAL_GREPLUS_IP"
    write_var REMOTE_GREPLUS_IP "$REMOTE_GREPLUS_IP"
    write_var GREPLUS_MTU "$GREPLUS_MTU"
    write_var GREPLUS_TUN_KEY "$GREPLUS_TUN_KEY"
    write_var GREPLUS_TXQUEUELEN "$GREPLUS_TXQUEUELEN"
  } > "$file"
  chmod 600 "$file"
  echo "Saved GRE Plus tunnel $TUNNEL_ID configuration to $file"
}

greplus_load_config() {
  local id="$1" file
  validate_tunnel_id "$id" || return 1
  file="$(greplus_config_file "$id")"
  [ -f "$file" ] || return 1
  unset TUNNEL_TYPE TUNNEL_ID ROLE LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP LOCAL_GREPLUS_IP REMOTE_GREPLUS_IP GREPLUS_MTU GREPLUS_TUN_KEY GREPLUS_TXQUEUELEN
  # shellcheck disable=SC1090
  source "$file"
  [ "${TUNNEL_TYPE:-}" = "greplus" ] || return 1
  TUNNEL_ID="$id"
  GREPLUS_TUN_KEY="$(greplus_key "$id")"
  GREPLUS_MTU="${GREPLUS_MTU:-$GREPLUS_FALLBACK_MTU}"
  GREPLUS_TXQUEUELEN="${GREPLUS_TXQUEUELEN:-$GREPLUS_DEFAULT_TXQUEUELEN}"
}

greplus_apply_firewall() {
  local id="$1" ifc
  greplus_load_config "$id" || return 1
  ifc="$(greplus_iface "$id")"
  enable_ip_forward
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT
    iptables -C OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT
    iptables -C INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT
    iptables -C OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT
    iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$ifc" -j ACCEPT
    iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$ifc" -j ACCEPT
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
    (
      # Serialize changes with auto-firewall and other GRE Plus instances.
      if command -v flock >/dev/null 2>&1; then
        exec 8>/run/gretun-ufw.lock
        flock -w 30 8 || exit 1
      fi
      ufw allow proto gre from "$REMOTE_PUBLIC_IP" to "$LOCAL_PUBLIC_IP" >/dev/null 2>&1 || true
      ufw allow in on "$ifc" from "$REMOTE_GREPLUS_IP" >/dev/null 2>&1 || true
      ufw route allow in on "$ifc" >/dev/null 2>&1 || true
      ufw route allow out on "$ifc" >/dev/null 2>&1 || true
    ) || true
  fi
}

greplus_remove_firewall() {
  local id="$1" ifc
  greplus_load_config "$id" || return 0
  ifc="$(greplus_iface "$id")"
  if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT || break; done
    while iptables -C OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT || break; done
    while iptables -C INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT || break; done
    while iptables -C OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT || break; done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
  fi
  command -v ufw >/dev/null 2>&1 && ufw delete allow proto gre from "$REMOTE_PUBLIC_IP" to "$LOCAL_PUBLIC_IP" >/dev/null 2>&1 || true
}

greplus_create_tunnel() {
  local interactive="${1:-0}" ifc
  validate_tunnel_id "${TUNNEL_ID:-}" || { err_msg "Invalid GRE Plus tunnel number."; return 1; }
  ifc="$(greplus_iface "$TUNNEL_ID")"
  GREPLUS_TUN_KEY="$(greplus_key "$TUNNEL_ID")"
  if [ "$ROLE" = "1" ]; then
    LOCAL_GREPLUS_IP="10.30.$TUNNEL_ID.1/30"
    REMOTE_GREPLUS_IP="10.30.$TUNNEL_ID.2"
  else
    LOCAL_GREPLUS_IP="10.30.$TUNNEL_ID.2/30"
    REMOTE_GREPLUS_IP="10.30.$TUNNEL_ID.1"
  fi
  local_ipv4_is_assigned "$LOCAL_PUBLIC_IP" || { err_msg "Selected local IP is not assigned: $LOCAL_PUBLIC_IP"; return 1; }
  GREPLUS_MTU="$(greplus_detect_mtu "$REMOTE_PUBLIC_IP")"
  GREPLUS_TXQUEUELEN="${GREPLUS_TXQUEUELEN:-$GREPLUS_DEFAULT_TXQUEUELEN}"
  apply_tunnel_sysctls
  ensure_public_endpoint_route "$REMOTE_PUBLIC_IP" "$LOCAL_PUBLIC_IP"
  modprobe gre >/dev/null 2>&1 || true
  modprobe ip_gre >/dev/null 2>&1 || true
  ip link set "$ifc" down 2>/dev/null || true
  ip tunnel del "$ifc" 2>/dev/null || true

  if ! ip tunnel add "$ifc" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$GREPLUS_TUN_KEY" ttl 64 tos inherit; then
    err_msg "Failed to create $ifc. Check whether protocol 47/GRE is supported and the tuple is unique."
    return 1
  fi
  ip addr replace "$LOCAL_GREPLUS_IP" dev "$ifc" || { ip tunnel del "$ifc" 2>/dev/null || true; return 1; }
  ip link set "$ifc" mtu "$GREPLUS_MTU" txqueuelen "$GREPLUS_TXQUEUELEN" up || { ip tunnel del "$ifc" 2>/dev/null || true; return 1; }
  command -v tc >/dev/null 2>&1 && tc qdisc replace dev "$ifc" root fq >/dev/null 2>&1 || true
  greplus_save_config
  greplus_apply_firewall "$TUNNEL_ID" || true
  if [ "$interactive" -eq 1 ]; then greplus_install_service "$TUNNEL_ID"; fi
  ok_msg "GRE Plus tunnel created: $ifc"
  echo "Local/remote inner IP: $LOCAL_GREPLUS_IP -> $REMOTE_GREPLUS_IP"
  echo "MTU / TX queue / qdisc: $GREPLUS_MTU / $GREPLUS_TXQUEUELEN / fq"
  echo "GRE key: $GREPLUS_TUN_KEY (separate namespace; this is not encryption)"
}

greplus_write_service_template() {
  cat > "$GREPLUS_SERVICE_TEMPLATE" <<EOF_GREPLUS_SERVICE
[Unit]
Description=GRE Plus Tunnel %i High-Capacity Self-Healing Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/bin/bash $INSTALL_BIN --service supervise-greplus %i
Restart=always
RestartSec=2
TimeoutStopSec=10
LimitNOFILE=262144
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG

[Install]
WantedBy=multi-user.target
EOF_GREPLUS_SERVICE
}

greplus_install_service() {
  local id="$1"
  install_manager_binary || return 1
  diagnostic_prepare_logs || true
  greplus_write_service_template
  install_health_monitor
  systemctl daemon-reload
  systemctl enable "$(greplus_service_name "$id")" >/dev/null
  systemctl restart "$(greplus_service_name "$id")"
}

greplus_supervisor() {
  local id="$1" ifc target failures=0
  validate_tunnel_id "$id" || return 1
  trap 'exit 0' TERM INT HUP
  while true; do
    greplus_load_config "$id" || return 1
    ifc="$(greplus_iface "$id")"; target="$REMOTE_GREPLUS_IP"
    apply_tunnel_sysctls
    ensure_public_endpoint_route "$REMOTE_PUBLIC_IP" "$LOCAL_PUBLIC_IP"
    # UFW rules are persistent. Repair the runtime rules only if they went
    # missing (for example after a firewall reload), not on every poll.
    if ! command -v iptables >/dev/null 2>&1 ||
       ! iptables -C INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT 2>/dev/null ||
       ! iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; then
      greplus_apply_firewall "$id" >/dev/null 2>&1 || true
    fi
    if ! tunnel_iface_is_up "$ifc"; then
      diagnostic_capture "greplus" "$id" "$ifc" "$(greplus_service_name "$id")" "$target" "interface missing or down"
      greplus_create_tunnel 0 || true
      failures=0
    elif quick_tunnel_ping "$ifc" "$target"; then
      failures=0
    else
      failures=$((failures + 1))
      diagnostic_event "WARN" "greplus-$id" "inner ping failed ($failures/$GRE_SUPERVISOR_FAIL_LIMIT), target=$target"
      if [ "$failures" -ge "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        diagnostic_capture "greplus" "$id" "$ifc" "$(greplus_service_name "$id")" "$target" "$failures consecutive failures"
        greplus_create_tunnel 0 || true
        failures=0
      fi
    fi
    sleep "$GRE_SUPERVISOR_INTERVAL" & wait $! || true
  done
}

greplus_menu_config_tunnel() {
  show_header "Configure GRE Plus Tunnel"
  prompt_role || return
  local selected_role="$ROLE" existing_local="" existing_remote=""
  prompt_tunnel_id "Enter GRE Plus tunnel number [1-254]: " || return
  if greplus_load_config "$TUNNEL_ID"; then
    existing_local="${LOCAL_PUBLIC_IP:-}"; existing_remote="${REMOTE_PUBLIC_IP:-}"
  fi
  ROLE="$selected_role"
  echo "Interface: $(greplus_iface "$TUNNEL_ID")"
  echo "Iran/Kharej IPs: 10.30.$TUNNEL_ID.1/30 <-> 10.30.$TUNNEL_ID.2/30"
  echo "Service: $(greplus_service_name "$TUNNEL_ID")"
  echo "No encryption; use only when lightweight kernel GRE is desired."
  prompt_local_tunnel_ip "${existing_local:-$(detect_local_public_ip || true)}" "Enter LOCAL public IPv4 for GRE Plus" || return
  prompt_remote_public_ip "$existing_remote" || return
  greplus_create_tunnel 1
}

greplus_list_tunnels() {
  echo "GRE Plus tunnels:"
  local ids id state
  ids="$(greplus_collect_ids || true)"; [ -n "$ids" ] || { echo "  none"; return 0; }
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    greplus_load_config "$id" || continue
    tunnel_iface_is_up "$(greplus_iface "$id")" && state=active || state=inactive
    echo "  - tunnel $id | $(greplus_iface "$id") | $state | MTU $GREPLUS_MTU | peer $REMOTE_PUBLIC_IP | service $(greplus_service_name "$id")"
  done <<< "$ids"
}

greplus_remove_one_tunnel() {
  local id="$1" ifc
  ifc="$(greplus_iface "$id")"
  systemctl disable --now "$(greplus_service_name "$id")" >/dev/null 2>&1 || true
  greplus_remove_firewall "$id" || true
  ip link set "$ifc" down 2>/dev/null || true
  ip tunnel del "$ifc" 2>/dev/null || ip link delete "$ifc" 2>/dev/null || true
  rm -f "$(greplus_config_file "$id")"
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok_msg "GRE Plus tunnel $id removed."
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
    gre) printf '%s' "${WG_ENDPOINT_IP:-}" ;;
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
  echo
  echo "Normal GRE uses 10.10.N.x, WireGuard uses 10.20.N.x, and GRE Plus uses 10.30.N.x."
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
  local private_file conf allowed_ips private_key endpoint_ip endpoint_mode_note mtu_value endpoint_line=""
  private_file="$(wg_private_key_file "$id")"
  conf="$(wg_config_file "$id")"
  private_key="$(cat "$private_file")"
  allowed_ips="${REMOTE_WG_IP%%/*}/32"
  endpoint_ip="$(wg_auto_endpoint_ip)"
  endpoint_mode_note="${WG_ENDPOINT_MODE:-public}"
  mtu_value="${WG_MTU:-1420}"
  case "$endpoint_mode_note" in
    gre) mtu_value="${WG_MTU:-1280}" ;;
  esac
  if [ -z "$endpoint_ip" ]; then
    echo "WireGuard endpoint IP is empty. Cannot write config." >&2
    return 1
  fi
  endpoint_line="Endpoint = $endpoint_ip:$REMOTE_WG_PORT"
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
$endpoint_line
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
      gre) WG_MTU="$(wg_mtu_for_gre "$TUNNEL_ID")" ;;
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

  gre_ifc="$(wg_transport_iface "$id")"
  gre_remote_ip="$(gre_remote_inner_ip_for_role "$id" "$role")"

  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="${REMOTE_PUBLIC_IP:-}"
  WG_TRANSPORT_IFACE=""

  gre_ok=0
  if ip link show "$gre_ifc" >/dev/null 2>&1; then
    gre_ok=1
  fi

  if [ "$gre_ok" -eq 1 ]; then
    WG_ENDPOINT_MODE="gre"
    WG_ENDPOINT_IP="$gre_remote_ip"
    WG_TRANSPORT_IFACE="$gre_ifc"
    return 0
  fi
}

wg_migrate_legacy_wss_meta() {
  local id="$1" old_mode
  wg_load_meta "$id" || return 0
  old_mode="${WG_ENDPOINT_MODE:-public}"
  [[ "$old_mode" == wss-* ]] || return 0

  LOCAL_WG_PORT="$(wg_default_port "$id")"
  REMOTE_WG_PORT="$LOCAL_WG_PORT"
  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="${REMOTE_PUBLIC_IP:-}"
  WG_TRANSPORT_IFACE=""
  WG_MTU="1420"
  wg_choose_auto_endpoint "$id" "${ROLE:-1}" || true
  if [ "$WG_ENDPOINT_MODE" = "gre" ]; then
    WG_MTU="$(wg_mtu_for_gre "$id")"
  fi

  if [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ] && [ -s "$(wg_private_key_file "$id")" ]; then
    wg_write_config "$id" >/dev/null 2>&1 || return 1
  fi
  wg_save_meta >/dev/null 2>&1 || return 1
  wss_remove_one "$id" || true
  diagnostic_event "MIGRATE" "wireguard-$id" "legacy $old_mode metadata converted to $WG_ENDPOINT_MODE transport"
  if systemctl is-enabled --quiet "$(wg_service_name "$id")" 2>/dev/null && [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
    systemctl restart "$(wg_service_name "$id")" >/dev/null 2>&1 || true
  fi
}

wg_mtu_for_gre() {
  local id="$1" parent_mtu="" calculated
  parent_mtu="$(ip -o link show dev "$(gre_iface "$id")" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  [[ "$parent_mtu" =~ ^[0-9]+$ ]] || parent_mtu=1390
  calculated=$((parent_mtu - 60))
  [ "$calculated" -lt 1280 ] && calculated=1280
  [ "$calculated" -gt 1420 ] && calculated=1420
  echo "$calculated"
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
  local gre_saved_remote
  gre_saved_remote=""
  local existing_wg_port
  existing_wg_port=""
  if wg_load_meta "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_peer_key="${REMOTE_WG_PUBLIC_KEY:-}"
    existing_wg_port="${LOCAL_WG_PORT:-}"
  fi
  ROLE="$selected_role"
  REMOTE_WG_PUBLIC_KEY="$existing_peer_key"

  # Reuse the remote public IP saved by a same-number GRE tunnel when available.
  # Run these in subshells so tunnel variables do not overwrite the selected WireGuard role.
  gre_saved_remote="$(bash -c 'set -e; f="'"$GRE_CONFIG_DIR""'/tunnel-'"$TUNNEL_ID""'.conf"; [ -f "$f" ] && . "$f" && printf "%s" "${REMOTE_PUBLIC_IP:-}"' 2>/dev/null || true)"
  if [ -z "$existing_remote_ip" ] && [ -n "$gre_saved_remote" ]; then
    existing_remote_ip="$gre_saved_remote"
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

  LOCAL_WG_PORT="$(auto_select_udp_port "$(wg_default_port "$TUNNEL_ID")" "$existing_wg_port" "wireguard" "$TUNNEL_ID")" || return
  REMOTE_WG_PORT="$LOCAL_WG_PORT"
  EXTRA_ALLOWED_IPS=""

  REMOTE_PUBLIC_IP="$existing_remote_ip"
  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP=""
  WG_TRANSPORT_IFACE=""

  # Remove a legacy WSS companion for this number before configuring v12.
  if [ -f "$(wss_config_file "$TUNNEL_ID")" ]; then
    wss_remove_one "$TUNNEL_ID" || true
  fi
  wg_choose_auto_endpoint "$TUNNEL_ID" "$ROLE" || return
  if [ "${WG_ENDPOINT_MODE:-public}" = "public" ]; then
    prompt_remote_public_ip "$existing_remote_ip" || return
    WG_ENDPOINT_MODE="public"
    WG_ENDPOINT_IP="$REMOTE_PUBLIC_IP"
    WG_TRANSPORT_IFACE=""
  else
    echo "Same-number normal GRE tunnel exists."
    echo "WireGuard will use normal GRE as its transport. GRE Plus remains independent."
    REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-$existing_remote_ip}"
  fi

  case "${WG_ENDPOINT_MODE:-public}" in
    gre) WG_MTU="$(wg_mtu_for_gre "$TUNNEL_ID")" ;;
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
      gre) echo "Transport interface : ${WG_TRANSPORT_IFACE:-}" ;;
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
          if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
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
    esac
  fi
  if [ -n "$transport_after" ]; then
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target $transport_after
Wants=$transport_after

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-wg $id
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG
EOF_WG_FW
  else
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service firewall-wg $id
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG
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
    if [ "$endpoint_mode" = "gre" ] && [ -n "$transport_ifc" ]; then
      iptables -C INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT || true
      if [ -n "$endpoint_ip" ]; then
        iptables -C OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || true
      fi
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port/udp" comment "wgtun$id" >/dev/null 2>&1 || true
    ufw allow in on "$ifc" >/dev/null 2>&1 || true
    if [ "$endpoint_mode" = "gre" ] && [ -n "$transport_ifc" ]; then
      ufw allow in on "$transport_ifc" to any port "$port" proto udp >/dev/null 2>&1 || true
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-interface="$ifc" >/dev/null 2>&1 || true
    if [ "$endpoint_mode" = "gre" ] && [ -n "$transport_ifc" ]; then
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
  local ifc conf meta private public endpoint_mode=""
  ifc="$(wg_iface_name "$id")"
  conf="$(wg_config_file "$id")"
  meta="$(wg_meta_file "$id")"
  private="$(wg_private_key_file "$id")"
  public="$(wg_public_key_file "$id")"
  if wg_load_meta "$id"; then endpoint_mode="${WG_ENDPOINT_MODE:-}"; fi

  echo "Removing WireGuard tunnel $id ($ifc)..."

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$(wg_service_name "$id")" 2>/dev/null || true
  fi

  # Safe cleanup only for this WireGuard tunnel. Do not touch the main route table.
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true
  wg_remove_firewall_rules "$id"
  if [ -f "$(wss_config_file "$id")" ]; then
    wss_remove_one "$id"
  fi

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
# -----------------------------
# Legacy WSS cleanup helpers (creation/runtime removed in v12)
# -----------------------------
wss_config_file() { echo "$WSS_CONFIG_DIR/tunnel-$1.conf"; }
wss_service_name() { echo "gretun-wss@$1.service"; }

wss_collect_ids() {
  local f id
  [ -d "$WSS_CONFIG_DIR" ] || return 0
  for f in "$WSS_CONFIG_DIR"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}

wss_remove_one() {
  local id="$1" file port=""
  validate_tunnel_id "$id" || return 1
  file="$(wss_config_file "$id")"
  if [ -f "$file" ]; then
    port="$(sed -n "s/^WSS_BIND_PORT=['\"]\{0,1\}\([0-9][0-9]*\)['\"]\{0,1\}$/\1/p" "$file" | head -n1)"
  fi
  systemctl disable --now "$(wss_service_name "$id")" >/dev/null 2>&1 || true
  rm -f "$file"
  if validate_port "$port" && command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport "$port" -j ACCEPT || break; done
  fi
  validate_port "$port" && command -v ufw >/dev/null 2>&1 && ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
}

# Legacy v10 Vira cleanup helpers. v11 cannot create or start Vira tunnels.
vira7_iface_name() { echo "vira7$1"; }
vira7_config_file() { echo "$VIRA7_CONFIG_DIR/tunnel-$1.conf"; }
vira7_service_name() { echo "vira7-tunnel@$1.service"; }
vira7_collect_ids() {
  local f id
  [ -d "$VIRA7_CONFIG_DIR" ] || return 0
  for f in "$VIRA7_CONFIG_DIR"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}
vira7_remove_one_tunnel() {
  local id="$1" ifc file port=""
  ifc="$(vira7_iface_name "$id")"; file="$(vira7_config_file "$id")"
  [ -f "$file" ] && port="$(awk -F= '$1=="VIRA7_PORT" || $1=="port" {gsub(/[\047\042[:space:]]/, "", $2); print $2; exit}' "$file" 2>/dev/null || true)"
  systemctl disable --now "$(vira7_service_name "$id")" >/dev/null 2>&1 || true
  ip link delete "$ifc" >/dev/null 2>&1 || true
  if validate_port "$port" && command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport "$port" -j ACCEPT || break; done
  fi
  rm -f "$file"
  echo "[OK] Legacy Vira7 tunnel $id removed."
}

# Legacy v10 ViraTCP cleanup helpers. v11 cannot create or start Vira tunnels.
viratcp_iface_name() { echo "viratcp$1"; }
viratcp_config_file() { echo "$VIRATCP_CONFIG_DIR/tunnel-$1.conf"; }
viratcp_service_name() { echo "viratcp-tunnel@$1.service"; }
viratcp_collect_ids() {
  local f id
  [ -d "$VIRATCP_CONFIG_DIR" ] || return 0
  for f in "$VIRATCP_CONFIG_DIR"/tunnel-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/tunnel-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}
viratcp_remove_one_tunnel() {
  local id="$1" ifc file port=""
  ifc="$(viratcp_iface_name "$id")"; file="$(viratcp_config_file "$id")"
  [ -f "$file" ] && port="$(awk -F= '$1=="VIRATCP_PORT" || $1=="port" {gsub(/[\047\042[:space:]]/, "", $2); print $2; exit}' "$file" 2>/dev/null || true)"
  systemctl disable --now "$(viratcp_service_name "$id")" >/dev/null 2>&1 || true
  ip link delete "$ifc" >/dev/null 2>&1 || true
  if validate_port "$port" && command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport "$port" -j ACCEPT || break; done
  fi
  rm -f "$file"
  echo "[OK] Legacy ViraTCP tunnel $id removed."
}

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

  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(greplus_iface "$id")"
    local_ip=""; target=""; local_pub=""; remote_pub=""; desc="GRE Plus"
    if greplus_load_config "$id"; then
      local_ip="${LOCAL_GREPLUS_IP:-}"
      target="${REMOTE_GREPLUS_IP:-}"
      local_pub="${LOCAL_PUBLIC_IP:-}"
      remote_pub="${REMOTE_PUBLIC_IP:-}"
    fi
    if tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
    INV_TYPE+=("greplus"); INV_ID+=("$id"); INV_IFACE+=("$ifc"); INV_LOCAL+=("$local_ip"); INV_TARGET+=("$target"); INV_LOCAL_PUBLIC+=("$local_pub"); INV_REMOTE_PUBLIC+=("$remote_pub"); INV_STATE+=("$state"); INV_DESC+=("$desc")
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
    greplus) greplus_remove_one_tunnel "$id" ;;
    wireguard) wg_remove_one_tunnel "$id" ;;
  esac
}

ping_inventory_item() {
  local index="$1"
  local i=$((index - 1))
  local type="${INV_TYPE[$i]}"
  local id="${INV_ID[$i]}"
  case "$type" in
    gre) test_gre_tunnel_ping "$id" ;;
    greplus) test_greplus_tunnel_ping "$id" ;;
    wireguard) test_wg_tunnel_ping "$id" ;;
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

# Prevent accidental removal of a GRE transport that still has WireGuard on top.
# This avoids the common "I removed one tunnel and the others stopped" case.
remove_selection_dependency_guard() {
  local -a selected=("$@")
  local idx i type id wg_ids wg_id blocked=0

  for idx in "${selected[@]}"; do
    i=$((idx - 1))
    type="${INV_TYPE[$i]:-}"
    id="${INV_ID[$i]:-}"

    case "$type" in
      gre)
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

  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if greplus_load_config "$id"; then
      ifc="$(greplus_iface "$id")"
      greplus_apply_firewall "$id" || true
      svc="$(greplus_service_name "$id")"
      if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet "$svc" 2>/dev/null && ! ip link show "$ifc" >/dev/null 2>&1; then
        warn_msg "Remaining GRE Plus tunnel $id is enabled but inactive; restarting only this tunnel."
        systemctl restart "$svc" 2>/dev/null || greplus_create_tunnel 0 || true
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
    wireguard)
      wg_menu_config_tunnel
      ;;
    greplus) greplus_menu_config_tunnel ;;
  esac
}

status_check() {
  show_header "Tunnel Status"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_status_check ;;
    greplus) greplus_list_tunnels ;;
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
    echo -e "${C_RED}${C_BOLD}WARNING:${C_RESET} this will remove ALL managed GRE, GRE Plus, and WireGuard tunnels."
    if ! confirm_yes "Are you sure?"; then
      echo "Cancelled."
      return
    fi

    local ids id
    # Remove WireGuard first because it may depend on normal GRE. GRE Plus is independent.
    ids="$(wg_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && wg_remove_one_tunnel "$id"; done <<< "$ids"
    ids="$(greplus_collect_ids || true)"
    while IFS= read -r id; do [ -n "$id" ] && greplus_remove_one_tunnel "$id"; done <<< "$ids"
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

  # Remove in dependency-safe order: WireGuard before its GRE transport.
  for phase in wireguard greplus gre; do
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
  greplus_list_tunnels
  echo
  wg_list_tunnels
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

test_greplus_tunnel_ping() {
  local id="$1" ifc svc target
  if ! greplus_load_config "$id"; then
    echo "[SKIP] GRE Plus tunnel $id: no saved config"
    return 1
  fi
  target="${REMOTE_GREPLUS_IP:-}"
  ifc="$(greplus_iface "$id")"
  svc="$(greplus_service_name "$id")"
  if ! tunnel_iface_is_up "$ifc"; then
    echo "[REPAIR] $ifc is inactive; restarting its independent service..."
    systemctl restart "$svc" >/dev/null 2>&1 || greplus_create_tunnel 0 || true
    sleep 2
  fi
  ping4_target "GRE Plus tunnel $id ($ifc) remote inner IP" "$target" "$ifc"
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

test_one_tunnel_ping_menu() {
  show_header "Test One Tunnel"
  ask_tunnel_type || return
  echo
  prompt_tunnel_id "Enter tunnel number to test [1-254]: " || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) test_gre_tunnel_ping "$TUNNEL_ID" ;;
    greplus) test_greplus_tunnel_ping "$TUNNEL_ID" ;;
    wireguard) test_wg_tunnel_ping "$TUNNEL_ID" ;;
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
  echo "Testing all saved GRE Plus tunnels..."
  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    total=$((total + 1))
    if test_greplus_tunnel_ping "$id"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
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
  echo "============================================================"
  echo "Ping test summary: total=$total ok=$ok failed_or_skipped=$fail"
  echo "============================================================"
}

tunnel_speed_test_menu() {
  show_header "Tunnel Throughput Speed Test"
  ensure_feature_dependencies "speed-test" "iperf3:iperf3" || return 1
  build_tunnel_inventory
  print_tunnel_inventory || return
  read -rp "Select tunnel number for speed test (00=menu): " selected
  if is_main_menu_token "$selected"; then return 99; fi
  [[ "$selected" =~ ^[0-9]+$ ]] && [ "$selected" -ge 1 ] && [ "$selected" -le "${#INV_TYPE[@]}" ] || { err_msg "Invalid tunnel selection."; return 1; }
  local idx local_ip target role duration answer rc=0 type
  idx=$((selected - 1))
  local_ip="${INV_LOCAL[$idx]:-}"
  local_ip="${local_ip%%/*}"
  type="${INV_TYPE[$idx]:-}"
  echo "Select this server's location:"
  echo "1) Iran (client)"
  echo "2) Kharej/outside (iperf3 server)"
  read -rp "Choose [1-2] (00=menu): " role
  if is_main_menu_token "$role"; then return 99; fi
  if [ "$role" = "1" ]; then
    target="${INV_TARGET[$idx]:-}"
    read -rp "Remote tunnel IPv4 (inner IP) [${target:-required}]: " answer
    target="${answer:-$target}"
    target="${target%%/*}"
    validate_ipv4 "$target" || { err_msg "Invalid remote IPv4."; return 1; }
  elif [ "$role" != "2" ]; then
    err_msg "Invalid role."; return 1
  fi
  read -rp "Test duration seconds [10]: " duration
  duration="${duration:-10}"
  [[ "$duration" =~ ^[1-9][0-9]*$ ]] || duration=10
  echo
  if [ "$role" = "2" ]; then
    iperf3_prepare_firewall "${INV_IFACE[$idx]:-}"
    echo "Starting a one-shot iperf3 server on this (Kharej) side."
    echo "Now start the client test on Iran; this server will stop automatically after that one test."
    if [ -n "$local_ip" ]; then
      echo "Command: iperf3 -s -1 -B $local_ip"
      if iperf3 -s -1 -B "$local_ip"; then :; else rc=$?; fi
    else
      echo "Command: iperf3 -s -1"
      if iperf3 -s -1; then :; else rc=$?; fi
    fi
  elif [ "$role" = "1" ]; then
    echo "Make sure iperf3 -s is running on the Kharej server, then testing through the selected tunnel..."
    if [ -n "$local_ip" ]; then
      echo "Command: iperf3 -c $target -B $local_ip -t $duration -P 4"
      if iperf3 -c "$target" -B "$local_ip" -t "$duration" -P 4; then :; else rc=$?; fi
    else
      echo "Command: iperf3 -c $target -t $duration -P 4"
      if iperf3 -c "$target" -t "$duration" -P 4; then :; else rc=$?; fi
    fi
  else
    err_msg "Invalid role."; return 1
  fi

  if [ "$rc" -ne 0 ]; then
    warn_msg "iperf3 ended or was interrupted (status $rc). Returning safely to the menu."
  else
    ok_msg "Speed test finished. Returning to the menu."
  fi
  return 0
}

# Legacy aggregate cleanup helpers. v11 cannot create or apply ECMP profiles.
aggregate_config_file() { echo "$AGG_CONFIG_DIR/profile-$1.conf"; }
aggregate_iface_name() { echo "${AGG_IFACE_PREFIX}$1"; }
aggregate_service_name() { echo "gretun-aggregate@$1.service"; }
aggregate_collect_ids() {
  local f id
  [ -d "$AGG_CONFIG_DIR" ] || return 0
  for f in "$AGG_CONFIG_DIR"/profile-*.conf; do
    [ -e "$f" ] || continue
    id="${f##*/profile-}"; id="${id%.conf}"
    validate_tunnel_id "$id" && echo "$id"
  done | sort -n -u
}
aggregate_remove_profile() {
  local id="$1"
  systemctl disable --now "$(aggregate_service_name "$id")" >/dev/null 2>&1 || true
  ip link delete "$(aggregate_iface_name "$id")" >/dev/null 2>&1 || true
  rm -f "$(aggregate_config_file "$id")"
  echo "[OK] Legacy aggregate profile $id removed."
}

iperf3_prepare_firewall() {
  local ifc="${1:-}" port=5201
  [ -n "$ifc" ] || return 0
  if command -v iptables >/dev/null 2>&1; then
    if ! iptables -C INPUT -i "$ifc" -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1; then
      iptables -I INPUT -i "$ifc" -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1 || true
    fi
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow in on "$ifc" to any port "$port" proto tcp >/dev/null 2>&1 || true
  fi
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
  echo "This will restart/recreate all saved normal GRE, GRE Plus, and WireGuard tunnels from their saved configs."
  echo "It will also re-enable their systemd services for boot."
  echo
  if ! confirm_yes "Continue with reset all tunnels?"; then
    echo "Cancelled."
    return
  fi

  diagnostic_event "MANUAL" "manager" "manual reset-all started by operator"

  echo
  echo "Stopping WireGuard first..."
  local ids id

  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl stop "$(wg_service_name "$id")" 2>/dev/null || true
    wg-quick down "$(wg_iface_name "$id")" >/dev/null 2>&1 || true
    ip link delete "$(wg_iface_name "$id")" 2>/dev/null || true
  done <<< "$ids"

  echo "Stopping GRE Plus and normal GRE tunnels..."
  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    systemctl stop "$(greplus_service_name "$id")" 2>/dev/null || true
    ip link set dev "$(greplus_iface "$id")" down 2>/dev/null || true
    ip tunnel del "$(greplus_iface "$id")" 2>/dev/null || true
  done <<< "$ids"

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
  echo "Starting GRE Plus tunnels..."
  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if greplus_load_config "$id"; then
      if greplus_create_tunnel 0 && greplus_install_service "$id"; then
        echo "[OK] GRE Plus tunnel $id reset"
      else
        echo "[WARN] GRE Plus tunnel $id reset failed"
      fi
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
  diagnostic_event "MANUAL" "manager" "manual reset-all finished"
}

# -----------------------------
# Persistent disconnect / restart diagnostics
# -----------------------------
diagnostics_collect_current() {
  local i kind id ifc svc target
  build_tunnel_inventory 0
  if [ "${#INV_TYPE[@]}" -eq 0 ]; then
    warn_msg "No managed tunnel was found."
    return 1
  fi

  info_msg "Saving a current diagnostic snapshot for every tunnel..."
  for i in "${!INV_TYPE[@]}"; do
    kind="${INV_TYPE[$i]}"; id="${INV_ID[$i]}"; ifc="${INV_IFACE[$i]}"; target="${INV_TARGET[$i]:-}"
    case "$kind" in
      gre) svc="$(gre_service_name "$id")" ;;
      greplus) svc="$(greplus_service_name "$id")" ;;
      wireguard) svc="$(wg_service_name "$id")" ;;
      *) svc="" ;;
    esac
    diagnostic_capture "$kind" "$id" "$ifc" "$svc" "$target" "manual diagnostic snapshot"
  done
  diagnostic_event "MANUAL" "manager" "current snapshot saved for ${#INV_TYPE[@]} tunnel(s)"
  ok_msg "Snapshot saved to $DIAG_DETAIL_LOG"
}

diagnostics_show_events() {
  diagnostic_prepare_logs || { err_msg "Cannot create/read $DIAG_LOG_DIR"; return 1; }
  show_header "Recent Tunnel Errors / Restarts"
  if [ ! -s "$DIAG_EVENT_LOG" ]; then
    warn_msg "No health error or restart has been recorded yet."
    return 0
  fi
  echo "Log file: $DIAG_EVENT_LOG"
  echo "Showing the latest 200 events:"
  echo
  tail -n 200 "$DIAG_EVENT_LOG"
}

diagnostics_show_details() {
  diagnostic_prepare_logs || { err_msg "Cannot create/read $DIAG_LOG_DIR"; return 1; }
  show_header "Detailed Failure Evidence"
  if [ ! -s "$DIAG_DETAIL_LOG" ]; then
    warn_msg "No detailed failure snapshot has been recorded yet."
    return 0
  fi
  echo "Log file: $DIAG_DETAIL_LOG"
  echo "Showing the latest 350 lines:"
  echo
  tail -n 350 "$DIAG_DETAIL_LOG"
}

diagnostics_show_services() {
  diagnostic_prepare_logs || { err_msg "Cannot create/read $DIAG_LOG_DIR"; return 1; }
  show_header "Raw Tunnel Service Messages"
  if [ ! -s "$DIAG_SERVICE_LOG" ]; then
    warn_msg "No tunnel service message has been recorded yet."
    echo "Services will write here after their next start/restart."
    return 0
  fi
  echo "Log file: $DIAG_SERVICE_LOG"
  echo "Showing the latest 300 service messages:"
  echo
  tail -n 300 "$DIAG_SERVICE_LOG"
}

diagnostics_export_report() {
  local report="/root/gretun-diagnostic-$(date '+%Y%m%d-%H%M%S').log"
  diagnostics_collect_current || true
  {
    echo "GRE-TUN diagnostic report"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S %z')"
    echo "Version: $APP_VERSION"
    echo
    echo "===== health timer ====="
    systemctl status gretun-health.timer gretun-health.service --no-pager 2>&1 || true
    echo
    echo "===== recorded events ====="
    cat "$DIAG_EVENT_LOG" 2>/dev/null || true
    echo
    echo "===== raw tunnel service output ====="
    cat "$DIAG_SERVICE_LOG" 2>/dev/null || true
    echo
    echo "===== detailed snapshots ====="
    cat "$DIAG_DETAIL_LOG" 2>/dev/null || true
  } > "$report" 2>&1
  chmod 600 "$report" 2>/dev/null || true
  ok_msg "Complete report created: $report"
  echo "Send this file for analysis after the next interruption."
}

diagnostics_clear_logs() {
  if ! confirm_yes "Delete the saved diagnostic logs?"; then
    echo "Cancelled."
    return 0
  fi
  diagnostic_prepare_logs || return 1
  : > "$DIAG_EVENT_LOG"
  : > "$DIAG_DETAIL_LOG"
  : > "$DIAG_SERVICE_LOG"
  rm -f "${DIAG_EVENT_LOG}.1" "${DIAG_DETAIL_LOG}.1" "${DIAG_SERVICE_LOG}.1" 2>/dev/null || true
  ok_msg "Saved diagnostic logs cleared."
}

diagnostics_menu() {
  diagnostic_prepare_logs || { err_msg "Cannot initialize diagnostic log storage."; return 1; }
  while true; do
    show_header "Tunnel Disconnect / Restart Logs"
    echo -e "${C_BOLD}${C_WHITE}Diagnostics Menu${C_RESET}"
    echo -e "  ${C_YELLOW}1)${C_RESET} view recent errors and restarts"
    echo -e "  ${C_BLUE}2)${C_RESET} view raw tunnel service messages"
    echo -e "  ${C_CYAN}3)${C_RESET} view detailed failure evidence"
    echo -e "  ${C_GREEN}4)${C_RESET} capture current tunnel state now"
    echo -e "  ${C_MAGENTA}5)${C_RESET} export complete report to /root"
    echo -e "  ${C_RED}6)${C_RESET} clear saved logs"
    echo -e "  ${C_DIM}00) Back to main menu${C_RESET}"
    echo
    echo "Automatic event log : $DIAG_EVENT_LOG"
    echo "Raw service output  : $DIAG_SERVICE_LOG"
    echo "Detailed snapshots  : $DIAG_DETAIL_LOG"
    echo
    read -rp "Choose diagnostics option [1-6/00]: " DIAG_CHOICE
    case "$DIAG_CHOICE" in
      1) diagnostics_show_events; pause ;;
      2) diagnostics_show_services; pause ;;
      3) diagnostics_show_details; pause ;;
      4) diagnostics_collect_current; pause ;;
      5) diagnostics_export_report; pause ;;
      6) diagnostics_clear_logs; pause ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
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
haproxy_configured_maxconn() {
  # Only the global setting applies here; frontend/defaults maxconn must not be rewritten.
  [ -f "$HAPROXY_CONFIG" ] || return 0
  awk '
    /^[[:space:]]*global([[:space:]]|$)/ { in_global=1; next }
    in_global && /^[^[:space:]#]/ { exit }
    in_global && /^[[:space:]]*maxconn[[:space:]]+[0-9]+([[:space:]#]|$)/ {
      print $2; exit
    }
  ' "$HAPROXY_CONFIG"
}

haproxy_base_header() {
  # Silent WebSocket-safe profile:
  # - no access logging by default, so HAProxy does not spam journald/syslog for every WS request
  # - keep HTTP mode for WebSocket forwarding
  # - longer tunnel timeout + TCP keepalive to avoid random long-lived WS drops
  local maxconn_line="" existing_maxconn=""
  if [ -f "$HAPROXY_CONFIG" ]; then
    existing_maxconn="$(haproxy_configured_maxconn)"
  else
    existing_maxconn="$HAPROXY_MAXCONN"
  fi
  [ -z "$existing_maxconn" ] || maxconn_line="    maxconn $existing_maxconn"
  cat <<EOF_HEADER
global
${maxconn_line}
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

haproxy_cleanup_legacy_limits() {
  # Remove only the exact systemd override created by older GRETUN versions.
  # A custom administrator override is left alone.
  local override="/etc/systemd/system/haproxy.service.d/99-gretun-limits.conf"
  if [ -f "$override" ] && printf '[Service]\nLimitNOFILE=2097152\nTasksMax=infinity\n' | cmp -s - "$override"; then
    rm -f "$override"
    systemctl daemon-reload
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
  build_tunnel_inventory 0
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

  build_tunnel_inventory 0
  count="${#INV_TYPE[@]}"
  if [ "$count" -gt 0 ]; then
    haproxy_target_inventory || true
    echo "Choose a tunnel row or type a custom IPv4."
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
  HAP_UDP_AGGREGATE=0

  build_tunnel_inventory 0
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

  if [ "${HAP_UDP_AGGREGATE:-0}" = "1" ]; then
    # Remove both the old v9 MASQUERADE form and the v10 deterministic SNAT.
    haproxy_udp_delete_exact_rule nat POSTROUTING \
      -p udp -d "$target" --dport "$tport" -j MASQUERADE
    haproxy_udp_delete_exact_rule nat POSTROUTING \
      -p udp -d "$target" --dport "$tport" -j SNAT --to-source "$local_ip"
    haproxy_udp_delete_exact_rule filter FORWARD \
      -p udp -d "$target" --dport "$tport" -j ACCEPT
    haproxy_udp_delete_exact_rule filter FORWARD \
      -p udp -s "$target" --sport "$tport" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    return 0
  fi

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

  if [ "${HAP_UDP_AGGREGATE:-0}" = "1" ]; then
    # Every aggregate path terminates at the same virtual address. Deterministic
    # SNAT keeps replies inside the aggregate instead of exposing a member IP.
    iptables -w 5 -t nat -I POSTROUTING 1 \
      -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-post-$port" -j SNAT --to-source "$local_ip"
    iptables -w 5 -I FORWARD 1 \
      -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-out-$port" -j ACCEPT
    iptables -w 5 -I FORWARD 1 \
      -p udp -s "$target" --sport "$tport" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "gretun-hap-udp-back-$port" -j ACCEPT
    return 0
  fi

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

haproxy_udp_rule_set_present() {
  local port="$1" target="$2" tport="$3"
  iptables -w 5 -t nat -C PREROUTING \
    -p udp --dport "$port" -m comment --comment "gretun-hap-udp-pre-$port" \
    -j DNAT --to-destination "$target:$tport" 2>/dev/null || return 1

  if [ "${HAP_UDP_AGGREGATE:-0}" = "1" ]; then
    iptables -w 5 -t nat -C POSTROUTING \
      -p udp -d "$target" --dport "$tport" -m comment --comment "gretun-hap-udp-post-$port" -j SNAT --to-source "$HAP_UDP_LOCAL_IP" 2>/dev/null || return 1
    iptables -w 5 -C FORWARD \
      -p udp -d "$target" --dport "$tport" -m comment --comment "gretun-hap-udp-out-$port" -j ACCEPT 2>/dev/null || return 1
    iptables -w 5 -C FORWARD \
      -p udp -s "$target" --sport "$tport" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "gretun-hap-udp-back-$port" -j ACCEPT 2>/dev/null || return 1
  else
    iptables -w 5 -t nat -C POSTROUTING \
      -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-post-$port" -j SNAT --to-source "$HAP_UDP_LOCAL_IP" 2>/dev/null || return 1
    iptables -w 5 -C FORWARD \
      -o "$HAP_UDP_IFACE" -p udp -d "$target" --dport "$tport" \
      -m comment --comment "gretun-hap-udp-out-$port" -j ACCEPT 2>/dev/null || return 1
    iptables -w 5 -C FORWARD \
      -i "$HAP_UDP_IFACE" -p udp -s "$target" --sport "$tport" \
      -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "gretun-hap-udp-back-$port" -j ACCEPT 2>/dev/null || return 1
  fi
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
  local tmp="$1" backup=""
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
    backup="$(mktemp "$HAPROXY_BACKUP_DIR/haproxy.cfg.XXXXXXXX.bak")"
    if ! cp -p "$HAPROXY_CONFIG" "$backup"; then
      rm -f "$backup" "$tmp"
      err_msg "Could not back up the existing HAProxy config. Nothing changed."
      return 1
    fi
  fi
  mv -f "$tmp" "$HAPROXY_CONFIG"
  haproxy_cleanup_legacy_limits
  systemctl enable haproxy >/dev/null 2>&1 || true
  if systemctl restart haproxy; then
    ok_msg "HAProxy restarted successfully."
    return 0
  fi
  err_msg "HAProxy restart failed. Check: journalctl -u haproxy -n 50 --no-pager"
  if [ -n "$backup" ]; then
    cp -p "$backup" "$HAPROXY_CONFIG"
    if systemctl restart haproxy; then
      warn_msg "Previous HAProxy config restored and service started."
    else
      err_msg "Previous config restored, but HAProxy still did not start. Check the journal."
    fi
  fi
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
    http-reuse safe
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
  haproxy_cleanup_legacy_limits
  mkdir -p /etc/haproxy "$HAPROXY_BACKUP_DIR"
  if [ ! -f "$HAPROXY_CONFIG" ]; then
    local new_config
    new_config="$(mktemp)"
    haproxy_base_header > "$new_config"
    if ! haproxy -c -f "$new_config"; then
      rm -f "$new_config"
      err_msg "HAProxy configuration validation failed. No config was installed."
      return 1
    fi
    mv -f "$new_config" "$HAPROXY_CONFIG"
  fi
  if ! systemctl is-active --quiet haproxy; then
    if ! haproxy -c -f "$HAPROXY_CONFIG" || ! systemctl start haproxy; then
      err_msg "HAProxy did not start. Check: journalctl -u haproxy -n 50 --no-pager"
      return 1
    fi
  fi
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

    haproxy_udp_rule_set_present "$port" "$target" "$tport" || return 1
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

    if haproxy_udp_rule_set_present "$port" "$target" "$tport"; then
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
    echo -e "  ${C_DIM}00) Back to main menu${C_RESET}"
    echo
    read -rp "Choose HAProxy option [1-8/00]: " HAP_CHOICE
    case "$HAP_CHOICE" in
      1) haproxy_run_action haproxy_list_forwards || return 0 ;;
      2) haproxy_run_action haproxy_add_port || return 0 ;;
      3) haproxy_run_action haproxy_change_all_ips || return 0 ;;
      4) haproxy_run_action haproxy_delete_port || return 0 ;;
      5) haproxy_run_action haproxy_change_one_ip || return 0 ;;
      6) haproxy_run_action haproxy_change_protocol || return 0 ;;
      7) haproxy_run_action haproxy_optimize_websocket_nolog || return 0 ;;
      8) haproxy_run_action haproxy_repair_udp || return 0 ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

# -----------------------------
# Performance, capacity, and v11 migration tools
# -----------------------------
performance_status() {
  local mem_kb cpu_count nofile configured_maxconn conntrack_now="N/A" conntrack_max="N/A" congestion="N/A" qdisc="N/A"
  mem_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  cpu_count="$(nproc 2>/dev/null || echo 1)"
  nofile="$(ulimit -n 2>/dev/null || echo unknown)"
  configured_maxconn="$(haproxy_configured_maxconn)"
  configured_maxconn="${configured_maxconn:-automatic / not set}"
  [ -r /proc/sys/net/netfilter/nf_conntrack_count ] && conntrack_now="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
  [ -r /proc/sys/net/netfilter/nf_conntrack_max ] && conntrack_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
  [ -r /proc/sys/net/ipv4/tcp_congestion_control ] && congestion="$(cat /proc/sys/net/ipv4/tcp_congestion_control)"
  [ -r /proc/sys/net/core/default_qdisc ] && qdisc="$(cat /proc/sys/net/core/default_qdisc)"
  show_header "Performance / Capacity Status"
  printf "CPU cores                 : %s\n" "$cpu_count"
  printf "RAM                       : %s MiB\n" "$((mem_kb / 1024))"
  printf "Current shell open files  : %s\n" "$nofile"
  printf "HAProxy configured maxconn: %s\n" "$configured_maxconn"
  printf "Conntrack usage           : %s / %s\n" "$conntrack_now" "$conntrack_max"
  printf "TCP congestion / qdisc    : %s / %s\n" "$congestion" "$qdisc"
  echo
  echo "Note: HAProxy maxconn is a ceiling, not guaranteed capacity; RAM, CPU, file descriptors,"
  echo "conntrack, backend capacity, RTT, and packet loss determine the real limit."
  echo "A single backend IP:port can also hit the local ephemeral-port ceiling; use multiple"
  echo "backend IPs or source IPs when you truly need more than about 60k concurrent backend sockets."
}

apply_capacity_profile() {
  mkdir -p /etc/sysctl.d /etc/systemd/system/haproxy.service.d 2>/dev/null || true
  cat > "$PERFORMANCE_SYSCTL_FILE" <<'EOF_PERFORMANCE'
# GRETUN v12 balanced high-capacity profile. Buffer values are maxima, not pre-allocation.
fs.file-max = 8388608
net.core.somaxconn = 131072
net.core.netdev_max_backlog = 131072
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 131072 33554432
net.ipv4.tcp_max_syn_backlog = 131072
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_tw_reuse = 1
EOF_PERFORMANCE
  if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
    echo 'net.netfilter.nf_conntrack_max = 2097152' >> "$PERFORMANCE_SYSCTL_FILE"
  fi
  sysctl -p "$PERFORMANCE_SYSCTL_FILE" >/dev/null 2>&1 || true
  apply_tunnel_sysctls
  systemctl daemon-reload >/dev/null 2>&1 || true
  if systemctl is-active --quiet haproxy 2>/dev/null; then
    systemctl reload haproxy >/dev/null 2>&1 || systemctl restart haproxy >/dev/null 2>&1 || true
  fi
  ok_msg "Balanced capacity profile applied. Existing tunnel addresses/routes were not changed."
}

enable_bbr_profile() {
  if ! modprobe tcp_bbr >/dev/null 2>&1 || [ ! -d /sys/module/tcp_bbr ]; then
    err_msg "This kernel does not provide tcp_bbr. No congestion-control setting was changed."
    return 1
  fi
  cat > /etc/sysctl.d/99-gretun-bbr.conf <<'EOF_BBR'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF_BBR
  if ! sysctl -p /etc/sysctl.d/99-gretun-bbr.conf >/dev/null 2>&1; then
    err_msg "Kernel rejected BBR settings; inspect /etc/sysctl.d/99-gretun-bbr.conf."
    return 1
  fi
  ok_msg "BBR + fq enabled for TCP traffic (including HAProxy). GRE and WireGuard encapsulation do not use TCP congestion control."
}

cleanup_removed_v11_features() {
  echo "This removes legacy WSS, Vira7, ViraTCP, and aggregate services/configs from this server."
  echo "Normal GRE, GRE Plus, WireGuard, HAProxy, and their logs are not removed."
  if ! confirm_yes "Continue with legacy cleanup?"; then
    echo "Cancelled."
    return 0
  fi

  local ids id unit ifc
  ids="$(vira7_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && vira7_remove_one_tunnel "$id"; done <<< "$ids"
  ids="$(viratcp_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && viratcp_remove_one_tunnel "$id"; done <<< "$ids"
  ids="$(aggregate_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && aggregate_remove_profile "$id"; done <<< "$ids"
  ids="$(wss_collect_ids || true)"
  while IFS= read -r id; do [ -n "$id" ] && wss_remove_one "$id"; done <<< "$ids"

  while read -r unit _; do
    [[ "$unit" == vira7-tunnel@*.service || "$unit" == viratcp-tunnel@*.service || "$unit" == gretun-aggregate@*.service || "$unit" == gretun-wss@*.service ]] || continue
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done < <(systemctl list-units --all --plain --no-legend 'vira7-tunnel@*.service' 'viratcp-tunnel@*.service' 'gretun-aggregate@*.service' 'gretun-wss@*.service' 2>/dev/null || true)

  for ifc in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^(vira7|viratcp|ga|gtagg)[0-9]+(@|$)/ {sub(/@.*/, "", $2); print $2}'); do
    ip link delete "$ifc" >/dev/null 2>&1 || true
  done
  rm -f "$VIRA7_SERVICE_TEMPLATE" "$VIRATCP_SERVICE_TEMPLATE" "$AGG_SERVICE_TEMPLATE" "$VIRA7_BINARY" "$VIRATCP_BINARY" "$WSS_SERVICE_TEMPLATE" "$WSS_BINARY"
  rm -rf "$VIRA7_CONFIG_DIR" "$VIRATCP_CONFIG_DIR" "$AGG_CONFIG_DIR" "$WSS_CONFIG_DIR"
  systemctl daemon-reload >/dev/null 2>&1 || true
  ok_msg "Legacy WSS, Vira, and aggregate installation files were removed."
}

performance_menu() {
  while true; do
    show_header "Performance / Capacity / Migration"
    echo "1) show current capacity status"
    echo "2) apply balanced high-capacity profile"
    echo "3) enable BBR + fq for TCP (when kernel supports it)"
    echo "4) remove legacy WSS / Vira / aggregate installation"
    echo "00) back to main menu"
    echo
    local choice
    read -rp "Choose [1-4/00]: " choice
    case "$choice" in
      1) performance_status; pause ;;
      2) if confirm_yes "Apply the balanced capacity profile?"; then apply_capacity_profile; fi; pause ;;
      3) if confirm_yes "Enable BBR + fq?"; then enable_bbr_profile || true; fi; pause ;;
      4) run_maintenance_action cleanup_removed_v11_features; pause ;;
      00) return_main_msg; return 0 ;;
      *) err_msg "Invalid option"; sleep 1 ;;
    esac
  done
}

show_menu() {
  show_header "GRE + GRE Plus + WireGuard Management v${APP_VERSION}"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel"
  echo -e "  ${C_RED}2)${C_RESET} remove tunnel"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} throughput speed test ${C_DIM}(iperf3)${C_RESET}"
  echo -e "  ${C_MAGENTA}6)${C_RESET} haproxy port manager"
  echo -e "  ${C_YELLOW}7)${C_RESET} disconnect / error / restart logs"
  echo -e "  ${C_CYAN}8)${C_RESET} performance / capacity / migration tools"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  read -rp "Choose an option [0-8]: " CHOICE
  case "$CHOICE" in
    1) if run_maintenance_action menu_config_tunnel; then pause; fi ;;
    2) if run_maintenance_action remove_tun; then pause; fi ;;
    3) if run_maintenance_action reset_all_tunnels; then pause; fi ;;
    4) if test_tunnels_menu; then pause; fi ;;
    5) if tunnel_speed_test_menu; then pause; fi ;;
    6) haproxy_menu || true ;;
    7) diagnostics_menu || true ;;
    8) performance_menu || true ;;
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
    supervise-greplus)
      ensure_root
      greplus_supervisor "${3:-}"
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
    *)
      echo "Unknown service command. Use --service supervise-gre <id>, supervise-greplus <id>, health-check-all, haproxy-udp-sync, or haproxy-udp-repair." >&2
      exit 1
      ;;
  esac
fi

ensure_root
bootstrap_runtime_repairs >/dev/null 2>&1 || true
while true; do
  show_menu
done
