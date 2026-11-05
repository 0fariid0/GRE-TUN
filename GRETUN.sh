#!/bin/bash
set -euo pipefail

# GRE + GRE Plus + WireGuard + HAProxy tunnel manager v12.0.6
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - WireGuard can use public UDP or ride over an existing GRE / GRE Plus tunnel as transport
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
# - v12.0.2 stops destructive tunnel recreation/restarts caused only by transient ping/ICMP loss,
#   avoids health-timer/supervisor repair races, and normalizes diagnostic timestamps to Asia/Tehran.
# - v12.0.3 lets WireGuard use same-number GRE or GRE Plus, prompts when both are up,
#   and preserves the selected transport across firewall, MTU, boot, health and removal checks.
# - v12.0.4 fixes UDP socket detection, propagates startup errors, isolates dependency
#   metadata, waits for the selected GRE transport at startup, and keeps cancelled edits safe.
# - v12.0.5 initializes peer ports for each selected WG ID, re-confirms legacy
#   peer ports, and provides a persistent port-only repair without regenerating keys.
# - v12.0.6 keeps the outside iperf3 server running for all tunnel addresses,
#   and adds validated multi-row client selection, sequential tests, timeouts and a summary.
# - HAProxy fix: preserve an existing global maxconn, use the known-working defaults,
#   and stop changing system limits or restarting HAProxy simply by opening its menu.

APP_VERSION="12.6.0"

GRE_CONFIG_DIR="/etc/gre-tunnels"
GRE_LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gretun-manager.sh"
GRE_SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
GRE_LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
GRE_SUPERVISOR_INTERVAL=10
GRE_SUPERVISOR_FAIL_LIMIT=3
# Probe failures are useful for diagnostics, but ICMP loss alone must not tear down a live tunnel.
AUTO_REPAIR_ON_PROBE_FAILURE=0
# Real service/interface failures are still repaired automatically.
AUTO_REPAIR_MISSING_INTERFACE=1
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
# Keep all diagnostic logs in one timezone on both Iran and foreign servers.
# Override when needed: GRETUN_LOG_TIMEZONE=Europe/Berlin /path/to/GRETUN.sh
DIAG_TIMEZONE="${GRETUN_LOG_TIMEZONE:-Asia/Tehran}"
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

diag_now() {
  TZ="$DIAG_TIMEZONE" date '+%Y-%m-%d %H:%M:%S %z'
}

diag_filename_stamp() {
  TZ="$DIAG_TIMEZONE" date '+%Y%m%d-%H%M%S'
}

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
      printf '%s [%s] [%s] %s\n' "$(diag_now)" "$level" "$component" "$message" >&9
    ) 9>>"$DIAG_EVENT_LOG" || true
  else
    printf '%s [%s] [%s] %s\n' "$(diag_now)" "$level" "$component" "$message" >> "$DIAG_EVENT_LOG" 2>/dev/null || true
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
    printf 'Captured : %s\n' "$(diag_now)"
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
      TZ="$DIAG_TIMEZONE" journalctl -u "$svc" --since '-5 minutes' -n 80 --no-pager -o short-iso 2>&1 || true
    fi
    echo "[recent kernel network messages]"
    TZ="$DIAG_TIMEZONE" journalctl -k --since '-5 minutes' -n 40 --no-pager -o short-iso 2>&1 || true
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
      printf '%s [%s] %s\n' "$(diag_now)" "$component" "$line" >&9
    ) 9>>"$DIAG_SERVICE_LOG" || true
  else
    printf '%s [%s] %s\n' "$(diag_now)" "$component" "$line" >> "$DIAG_SERVICE_LOG" 2>/dev/null || true
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
  TUNNEL_ID="$((10#$TUNNEL_ID))"
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
  echo "2) WireGuard tunnel (direct UDP or over same-number GRE / GRE Plus)"
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
  local target_dir tmp candidate_version
  if [ "${MANAGER_INSTALLED_THIS_SESSION:-0}" = 1 ] && [ -s "$INSTALL_BIN" ]; then return 0; fi
  target_dir="$(dirname "$INSTALL_BIN")"
  tmp="${INSTALL_BIN}.tmp.$$"

  mkdir -p "$target_dir" || return 1
  rm -f "$tmp"

  case "$source_path" in
    /dev/fd/*|/proc/*/fd/*)
      if command -v curl >/dev/null 2>&1; then
        curl -fLsS --ipv4 --connect-timeout 10 --max-time 45 "$SELF_RAW_URL" -o "$tmp" || { rm -f "$tmp"; return 1; }
      elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=15 --tries=2 -O "$tmp" "$SELF_RAW_URL" || { rm -f "$tmp"; return 1; }
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
  candidate_version="$(sed -n 's/^APP_VERSION="\([^"]*\)"/\1/p' "$tmp" | head -n1)"
  if [ "$candidate_version" != "$APP_VERSION" ]; then
    rm -f "$tmp"
    err_msg "Manager version mismatch: running $APP_VERSION, downloaded ${candidate_version:-unknown}. Upload the matching GRETUN.sh, or run this downloaded file directly." >&2
    return 1
  fi
  if [ -f "$INSTALL_BIN" ] && cmp -s "$tmp" "$INSTALL_BIN"; then rm -f "$tmp"; MANAGER_INSTALLED_THIS_SESSION=1; return 0; fi
  bash -n "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; return 1; }
  chmod 755 "$tmp" || { rm -f "$tmp"; return 1; }
  mv -f "$tmp" "$INSTALL_BIN" || return 1
  MANAGER_INSTALLED_THIS_SESSION=1
}

# -----------------------------
# Shared UDP port + firewall helpers
# -----------------------------
udp_port_is_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -lun 2>/dev/null | awk -v port="$port" '
      {for(i=1;i<=NF;i++) if($i ~ ("[:.]" port "$")) found=1}
      END {exit found ? 0 : 1}'
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

transport_has_recent_wg_handshake() (
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
)

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

restart_wg_dependents_for_transport() (
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
)

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
    if maintenance_is_active; then
      sleep "$GRE_SUPERVISOR_INTERVAL" & wait $! || true
      continue
    fi
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
      if [ "$AUTO_REPAIR_MISSING_INTERFACE" -eq 1 ]; then
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
      else
        diagnostic_event "ERROR" "gre-$id" "interface $ifc is missing/down; automatic repair is disabled"
      fi
    elif transport_has_recent_wg_handshake gre "$id" || quick_tunnel_ping "$ifc" "$target"; then
      if [ "$failures" -gt 0 ]; then
        diagnostic_event "RECOVERED" "gre-$id" "inner reachability recovered after $failures failed probe(s); tunnel was not recreated"
      fi
      failures=0
    else
      failures=$((failures + 1))
      # Log the first few failures, then only once every ~5 minutes to avoid log spam.
      if [ "$failures" -le "$GRE_SUPERVISOR_FAIL_LIMIT" ] || [ $((failures % 30)) -eq 0 ]; then
        diagnostic_event "WARN" "gre-$id" "inner reachability probe failed ($failures), interface=$ifc target=$target; live tunnel left untouched"
      fi
      if [ "$AUTO_REPAIR_ON_PROBE_FAILURE" -eq 1 ] && [ "$failures" -ge "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        diagnostic_capture "gre" "$id" "$ifc" "$(gre_service_name "$id")" "$target" "$failures consecutive inner reachability failures"
        if gre_create_tunnel 0; then
          diagnostic_event "RESTART" "gre-$id" "tunnel recreation succeeded after $failures failed probes"
          restart_wg_dependents_for_transport gre "$id"
        else
          diagnostic_event "ERROR" "gre-$id" "tunnel recreation FAILED after $failures failed probes"
        fi
        failures=0
      elif [ "$failures" -eq "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        diagnostic_event "INFO" "gre-$id" "probe threshold reached, but auto-recreate-on-probe-failure is disabled"
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
Restart=on-failure
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
      if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        restart_service_with_diagnostics "gre" "$id" "$ifc" "$svc" "" "supervisor service inactive during periodic health check" || true
      elif ! tunnel_iface_is_up "$ifc"; then
        # The active supervisor owns interface recovery. Do not restart it here and race its repair.
        diagnostic_event "WARN" "gre-$id" "interface $ifc is missing/down; active supervisor will handle recovery"
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
      if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
        restart_service_with_diagnostics "greplus" "$id" "$ifc" "$svc" "" "supervisor service inactive during periodic health check" || true
      elif ! tunnel_iface_is_up "$ifc"; then
        # The active supervisor owns interface recovery. Do not restart it here and race its repair.
        diagnostic_event "WARN" "greplus-$id" "interface $ifc is missing/down; active supervisor will handle recovery"
      fi
    fi
  done <<< "$ids"

  # WireGuard is checked last so its GRE/GRE Plus transport is repaired first.
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
      gre|greplus)
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
      if [ "$count" -le "$HEALTH_FAIL_LIMIT" ] || [ $((count % 15)) -eq 0 ]; then
        diagnostic_event "WARN" "wireguard-$id" "handshake is stale and inner ping failed ($count), interface=$ifc target=$target; interface left untouched"
      fi
      if [ "$AUTO_REPAIR_ON_PROBE_FAILURE" -eq 1 ] && [ "$count" -ge "$HEALTH_FAIL_LIMIT" ]; then
        restart_service_with_diagnostics "wireguard" "$id" "$ifc" "$svc" "$target" "$count stale-handshake/inner-ping failures" || true
        health_counter_reset wireguard "$id"
      elif [ "$count" -eq "$HEALTH_FAIL_LIMIT" ]; then
        diagnostic_event "INFO" "wireguard-$id" "probe threshold reached, but auto-restart-on-probe-failure is disabled"
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
  # Detect an older supervisor template before overwriting it. This makes the
  # v12.0.2 behavior take effect immediately with one controlled service restart,
  # but avoids restarting healthy tunnels every time the manager menu is opened.
  if [ ! -f "$GRE_SERVICE_TEMPLATE" ] ||
     ! grep -q 'supervise-gre' "$GRE_SERVICE_TEMPLATE" 2>/dev/null ||
     ! grep -q '^Restart=on-failure$' "$GRE_SERVICE_TEMPLATE" 2>/dev/null; then
    migrate=1
  fi
  if [ -d "$GREPLUS_CONFIG_DIR" ] && {
       [ ! -f "$GREPLUS_SERVICE_TEMPLATE" ] ||
       ! grep -q 'supervise-greplus' "$GREPLUS_SERVICE_TEMPLATE" 2>/dev/null ||
       ! grep -q '^Restart=on-failure$' "$GREPLUS_SERVICE_TEMPLATE" 2>/dev/null;
     }; then
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
        restart_service_with_diagnostics "gre" "$id" "$ifc" "$svc" "" "startup repair: supervisor template migration, inactive service, or missing interface" || true
      fi
    fi
  done <<< "$ids"

  ids="$(greplus_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    svc="$(greplus_service_name "$id")"
    ifc="$(greplus_iface "$id")"
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if [ "$migrate" -eq 1 ] || ! systemctl is-active --quiet "$svc" 2>/dev/null || ! tunnel_iface_is_up "$ifc"; then
        restart_service_with_diagnostics "greplus" "$id" "$ifc" "$svc" "" "startup repair: supervisor template migration, inactive service, or missing interface" || true
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

  mkdir -p "$GRE_CONFIG_DIR" || return 1
  local file temporary
  file="$(gre_config_file "$TUNNEL_ID")"
  temporary="$(mktemp "$GRE_CONFIG_DIR/.config.XXXXXX")" || return 1

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
  } > "$temporary" || { rm -f "$temporary"; return 1; }
  chmod 600 "$temporary" || { rm -f "$temporary"; return 1; }
  mv -f "$temporary" "$file" || return 1
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
    gre_save_config || return 1
    if [ -f "$(gre_config_file "$TUNNEL_ID")" ] && command -v systemctl >/dev/null 2>&1; then
      if gre_install_service "$TUNNEL_ID"; then
        echo "GRE persistence enabled for $(gre_service_name "$TUNNEL_ID")."
      else
        echo "Failed to enable GRE persistence. Tunnel is currently created, but it may not survive reboot." >&2
      fi
    fi
  fi
  transparent_repair_routes "$TUN_IFACE" || return 1

}

gre_menu_config_tunnel() {
  show_header "Configure Normal GRE Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter GRE tunnel number before IP [1-254]: " || return
  transparent_guard "$(gre_iface "$TUNNEL_ID")" || return 1

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
  gre_create_tunnel 1 || { err_msg "GRE tunnel creation failed"; return 1; }
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
  remove_transport_dependency_check gre "$id" || return 1
  transparent_remove_interface "$(gre_iface "$id")" || return 1
  local ifc file
  ifc="$(gre_iface "$id")"
  file="$(gre_config_file "$id")"

  echo "Removing GRE tunnel $id ($ifc)..."

  stop_tunnel_for_remove "$(gre_service_name "$id")" || return 1

  ip link set dev "$ifc" down 2>/dev/null || true
  if ip tunnel del "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip tunnel del'"
  elif ip link delete "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip link delete'"
  else
    echo "- $ifc was not found or could not be removed automatically."
  fi

  verify_interface_removed "$ifc" || return 1
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
greplus_key() { echo $((GREPLUS_KEY_BASE + 10#$1)); }

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
  local file temporary
  mkdir -p "$GREPLUS_CONFIG_DIR" || return 1
  file="$(greplus_config_file "$TUNNEL_ID")"
  temporary="$(mktemp "$GREPLUS_CONFIG_DIR/.config.XXXXXX")" || return 1
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
  } > "$temporary" || { rm -f "$temporary"; return 1; }
  chmod 600 "$temporary" || { rm -f "$temporary"; return 1; }
  mv -f "$temporary" "$file" || return 1
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

greplus_apply_firewall() (
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
)

greplus_peer_is_shared() (
  local removed_id="$1" local_peer="$2" remote_peer="$3" f other_id
  for f in "$GREPLUS_CONFIG_DIR"/tunnel-*.conf; do
    [ -f "$f" ] || continue
    other_id="${f##*/tunnel-}"; other_id="${other_id%.conf}"
    [ "$other_id" = "$removed_id" ] && continue
    unset LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP
    source "$f" || continue
    if [ "${LOCAL_PUBLIC_IP:-}" = "$local_peer" ] && [ "${REMOTE_PUBLIC_IP:-}" = "$remote_peer" ]; then
      return 0
    fi
  done
  return 1
)

greplus_remove_firewall() {
  local id="$1" ifc shared=0
  greplus_load_config "$id" || return 0
  ifc="$(greplus_iface "$id")"
  greplus_peer_is_shared "$id" "$LOCAL_PUBLIC_IP" "$REMOTE_PUBLIC_IP" && shared=1
  if command -v iptables >/dev/null 2>&1; then
    if [ "$shared" -eq 0 ]; then
    while iptables -C INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p gre -s "$REMOTE_PUBLIC_IP" -d "$LOCAL_PUBLIC_IP" -j ACCEPT || break; done
    while iptables -C OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -p gre -s "$LOCAL_PUBLIC_IP" -d "$REMOTE_PUBLIC_IP" -j ACCEPT || break; done
    fi
    while iptables -C INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$ifc" -s "$REMOTE_GREPLUS_IP" -j ACCEPT || break; done
    while iptables -C OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -o "$ifc" -d "$REMOTE_GREPLUS_IP" -j ACCEPT || break; done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
  fi
  [ "$shared" -eq 0 ] && command -v ufw >/dev/null 2>&1 && ufw delete allow proto gre from "$REMOTE_PUBLIC_IP" to "$LOCAL_PUBLIC_IP" >/dev/null 2>&1 || true
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
  greplus_save_config || return 1
  greplus_apply_firewall "$TUNNEL_ID" || return 1
  if [ "$interactive" -eq 1 ]; then greplus_install_service "$TUNNEL_ID" || return 1; fi
  ok_msg "GRE Plus tunnel created: $ifc"
  echo "Local/remote inner IP: $LOCAL_GREPLUS_IP -> $REMOTE_GREPLUS_IP"
  echo "MTU / TX queue / qdisc: $GREPLUS_MTU / $GREPLUS_TXQUEUELEN / fq"
  echo "GRE key: $GREPLUS_TUN_KEY (separate namespace; this is not encryption)"
  transparent_repair_routes "$ifc" || return 1

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
Restart=on-failure
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
  greplus_write_service_template || return 1
  install_health_monitor || return 1
  systemctl daemon-reload || return 1
  systemctl enable "$(greplus_service_name "$id")" >/dev/null || return 1
  systemctl restart "$(greplus_service_name "$id")"
}

greplus_supervisor() {
  local id="$1" ifc target failures=0
  validate_tunnel_id "$id" || return 1
  trap 'exit 0' TERM INT HUP
  while true; do
    if maintenance_is_active; then
      sleep "$GRE_SUPERVISOR_INTERVAL" & wait $! || true
      continue
    fi
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
      if [ "$AUTO_REPAIR_MISSING_INTERFACE" -eq 1 ]; then
        diagnostic_event "ERROR" "greplus-$id" "interface $ifc is missing/down; recreating tunnel"
        diagnostic_capture "greplus" "$id" "$ifc" "$(greplus_service_name "$id")" "$target" "interface missing or down"
        if greplus_create_tunnel 0; then
          diagnostic_event "RESTART" "greplus-$id" "tunnel recreation succeeded after interface disappeared"
          failures=0
          restart_wg_dependents_for_transport greplus "$id"
        else
          diagnostic_event "ERROR" "greplus-$id" "tunnel recreation FAILED after interface disappeared"
        fi
      else
        diagnostic_event "ERROR" "greplus-$id" "interface $ifc is missing/down; automatic repair is disabled"
      fi
    elif transport_has_recent_wg_handshake greplus "$id" || quick_tunnel_ping "$ifc" "$target"; then
      if [ "$failures" -gt 0 ]; then
        diagnostic_event "RECOVERED" "greplus-$id" "inner ping recovered after $failures failed probe(s); tunnel was not recreated"
      fi
      failures=0
    else
      failures=$((failures + 1))
      # ICMP can be dropped/throttled while GRE traffic itself is still healthy.
      # Never destroy a live GRE Plus interface only because ping missed a few times.
      if [ "$failures" -le "$GRE_SUPERVISOR_FAIL_LIMIT" ] || [ $((failures % 30)) -eq 0 ]; then
        diagnostic_event "WARN" "greplus-$id" "inner ping failed ($failures), target=$target; live tunnel left untouched"
      fi
      if [ "$AUTO_REPAIR_ON_PROBE_FAILURE" -eq 1 ] && [ "$failures" -ge "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        diagnostic_capture "greplus" "$id" "$ifc" "$(greplus_service_name "$id")" "$target" "$failures consecutive ping failures"
        if greplus_create_tunnel 0; then
          diagnostic_event "RESTART" "greplus-$id" "tunnel recreation succeeded after $failures failed probes"
          restart_wg_dependents_for_transport greplus "$id"
        else
          diagnostic_event "ERROR" "greplus-$id" "tunnel recreation FAILED after $failures failed probes"
        fi
        failures=0
      elif [ "$failures" -eq "$GRE_SUPERVISOR_FAIL_LIMIT" ]; then
        diagnostic_event "INFO" "greplus-$id" "probe threshold reached, but auto-recreate-on-probe-failure is disabled"
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
  transparent_guard "$(greplus_iface "$TUNNEL_ID")" || return 1
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
  remove_transport_dependency_check greplus "$id" || return 1
  transparent_remove_interface "$(greplus_iface "$id")" || return 1
  ifc="$(greplus_iface "$id")"
  stop_tunnel_for_remove "$(greplus_service_name "$id")" || return 1
  greplus_remove_firewall "$id" || true
  ip link set "$ifc" down 2>/dev/null || true
  ip tunnel del "$ifc" 2>/dev/null || ip link delete "$ifc" 2>/dev/null || true
  verify_interface_removed "$ifc" || return 1
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
  echo $((51800 + 10#$id))
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
    gre|greplus) printf '%s' "${WG_ENDPOINT_IP:-}" ;;
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
    journalctl -u "$svc" -n 25 --no-pager -o cat 2>/dev/null || true
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
  echo "  Transport       : active gre$id (10.10.$id.x) or greplus$id (10.30.$id.x)"
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
  local id="$1" private public tmp_private derived tmp_public
  mkdir -p "$WG_KEY_DIR" || return 1
  chmod 700 "$WG_META_DIR" "$WG_KEY_DIR" 2>/dev/null || true
  private="$(wg_private_key_file "$id")"; public="$(wg_public_key_file "$id")"
  if [ ! -s "$private" ]; then
    tmp_private="$(mktemp "$WG_KEY_DIR/.private.XXXXXX")" || return 1
    if ! wg genkey > "$tmp_private"; then rm -f "$tmp_private"; return 1; fi
    if ! derived="$(wg pubkey < "$tmp_private")" || ! validate_wg_public_key "$derived"; then
      rm -f "$tmp_private"; err_msg "WireGuard key generation failed."; return 1
    fi
    chmod 600 "$tmp_private" || { rm -f "$tmp_private"; return 1; }
    mv -f "$tmp_private" "$private" || return 1
    echo "Generated new WireGuard private key for tunnel $id."
  else
    if ! derived="$(wg pubkey < "$private")" || ! validate_wg_public_key "$derived"; then
      err_msg "Saved WireGuard private key is invalid. It was preserved; repair the key file first."
      return 1
    fi
  fi
  # Always derive the public key from the private key; stale public files break handshakes.
  tmp_public="$(mktemp "$WG_KEY_DIR/.public.XXXXXX")" || return 1
  printf '%s\n' "$derived" > "$tmp_public" || { rm -f "$tmp_public"; return 1; }
  chmod 644 "$tmp_public" || { rm -f "$tmp_public"; return 1; }
  mv -f "$tmp_public" "$public" || return 1
  chmod 600 "$private" || return 1
}

wg_save_meta() {
  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Cannot save WireGuard meta: invalid tunnel number" >&2
    return 1
  fi

  mkdir -p "$WG_META_DIR" || return 1
  chmod 700 "$WG_META_DIR" 2>/dev/null || true
  local file temporary
  file="$(wg_meta_file "$TUNNEL_ID")"
  temporary="$(mktemp "$WG_META_DIR/.meta.XXXXXX")" || return 1

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
    write_var WG_REMOTE_PORT_CONFIRMED "${WG_REMOTE_PORT_CONFIRMED:-0}"
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
  } > "$temporary" || { rm -f "$temporary"; return 1; }
  chmod 600 "$temporary" || { rm -f "$temporary"; return 1; }
  mv -f "$temporary" "$file" || return 1
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
    # Optional transport fields in older files must not inherit another tunnel's state.
    unset TUNNEL_TYPE TUNNEL_ID WG_IFACE ROLE SERVER_ROLE LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP
    unset LOCAL_WG_IP REMOTE_WG_IP LOCAL_WG_PORT REMOTE_WG_PORT WG_REMOTE_PORT_CONFIRMED WG_ENDPOINT_MODE WG_ENDPOINT_IP
    unset WG_TRANSPORT_IFACE WG_MTU REMOTE_WG_PUBLIC_KEY WG_PENDING EXTRA_ALLOWED_IPS
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    WG_IFACE="$(wg_iface_name "$id")"
    LOCAL_WG_PORT="${LOCAL_WG_PORT:-$(wg_default_port "$id")}"
    REMOTE_WG_PORT="${REMOTE_WG_PORT:-$(wg_default_port "$id")}"
    WG_REMOTE_PORT_CONFIRMED="${WG_REMOTE_PORT_CONFIRMED:-0}"
    REMOTE_WG_PUBLIC_KEY="${REMOTE_WG_PUBLIC_KEY:-}"
    EXTRA_ALLOWED_IPS="${EXTRA_ALLOWED_IPS:-}"
    WG_ENDPOINT_MODE="${WG_ENDPOINT_MODE:-public}"
    WG_ENDPOINT_IP="${WG_ENDPOINT_IP:-${REMOTE_PUBLIC_IP:-}}"
    case "$WG_ENDPOINT_MODE" in
      gre) WG_TRANSPORT_IFACE="${WG_TRANSPORT_IFACE:-$(gre_iface "$id")}" ;;
      greplus) WG_TRANSPORT_IFACE="${WG_TRANSPORT_IFACE:-$(greplus_iface "$id")}" ;;
      *) WG_TRANSPORT_IFACE="" ;;
    esac
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
  transparent_guard "$(wg_iface_name "$1")" || return 1
  local id="$1" temporary
  local private_file conf allowed_ips private_key endpoint_ip endpoint_mode_note mtu_value endpoint_line=""
  private_file="$(wg_private_key_file "$id")"
  conf="$(wg_config_file "$id")"
  private_key="$(cat "$private_file")" || return 1
  allowed_ips="${REMOTE_WG_IP%%/*}/32"
  endpoint_ip="$(wg_auto_endpoint_ip)"
  endpoint_mode_note="${WG_ENDPOINT_MODE:-public}"
  mtu_value="${WG_MTU:-1420}"
  case "$endpoint_mode_note" in
    gre|greplus) mtu_value="${WG_MTU:-1280}" ;;
  esac
  if [ -z "$endpoint_ip" ]; then
    echo "WireGuard endpoint IP is empty. Cannot write config." >&2
    return 1
  fi
  endpoint_line="Endpoint = $endpoint_ip:$REMOTE_WG_PORT"
  if [ -n "${EXTRA_ALLOWED_IPS:-}" ]; then
    allowed_ips="$allowed_ips, $EXTRA_ALLOWED_IPS"
  fi

  mkdir -p "$WG_CONFIG_DIR" || return 1
  chmod 700 "$WG_CONFIG_DIR" 2>/dev/null || true

  temporary="$(mktemp "$WG_CONFIG_DIR/.wg.XXXXXX")" || return 1
  if ! cat > "$temporary" <<EOF_CONF
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
  then rm -f "$temporary"; return 1; fi
  chmod 600 "$temporary" || { rm -f "$temporary"; return 1; }
  mv -f "$temporary" "$conf" || return 1
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
      gre|greplus) WG_MTU="$(wg_mtu_for_gre "$TUNNEL_ID")" ;;
      *) WG_MTU="1420" ;;
    esac
  fi
  EXTRA_ALLOWED_IPS="${EXTRA_ALLOWED_IPS:-}"
  REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "${REMOTE_WG_PUBLIC_KEY:-}")"
  WG_PENDING=0

  wg_generate_keys "$TUNNEL_ID" || return 1
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
  if [[ "${WG_ENDPOINT_MODE:-public}" == gre || "${WG_ENDPOINT_MODE:-public}" == greplus ]]; then
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
    wg_safe_cleanup_runtime "$TUNNEL_ID" || return 1
    command -v systemctl >/dev/null 2>&1 && systemctl disable "$(wg_service_name "$TUNNEL_ID")" >/dev/null 2>&1 || true
    echo "Remote public key is empty."
    echo "Saved as PENDING. Nothing will be started yet, so ping will not work until you add the peer key."
    wg_save_meta || return 1
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
    wg_save_meta || return 1
    return 0
  fi

  if [ "$REMOTE_WG_PUBLIC_KEY" = "$local_pub" ]; then
    WG_PENDING=1
    echo "You pasted this server's own public key, not the OTHER server public key." >&2
    echo "Saved as PENDING. Run the script on the other server and paste its public key here." >&2
    REMOTE_WG_PUBLIC_KEY=""
    wg_save_meta || return 1
    return 0
  fi

  wg_commit_and_start "$TUNNEL_ID" || return 1
  echo "[OK] WireGuard tunnel created and started as $WG_IFACE"

  echo "Local WG IP : $LOCAL_WG_IP"
  echo "Remote WG IP: $REMOTE_WG_IP"
  echo
  echo "After both sides are started, test:"
  echo "  ping $REMOTE_WG_IP"
}

wg_start_runtime() {
  local id="$1" ifc
  ifc="$(wg_iface_name "$id")"
  if command -v systemctl >/dev/null 2>&1; then
    wg_install_service "$id" || { wg_print_service_failure "$id"; return 1; }
  else
    wg_safe_cleanup_runtime "$id" || return 1
    wg-quick up "$ifc" || return 1
    tunnel_iface_is_up "$ifc" || return 1
  fi
}

wg_commit_and_start() {
  local id="$1" backup had_config=0 had_meta=0 was_up=0 conf meta
  conf="$(wg_config_file "$id")"; meta="$(wg_meta_file "$id")"
  mkdir -p "$WG_META_DIR" || return 1
  backup="$(mktemp -d "$WG_META_DIR/.update.XXXXXX")" || return 1
  if [ -f "$conf" ]; then cp -p "$conf" "$backup/config" || { rm -rf "$backup"; return 1; }; had_config=1; fi
  if [ -f "$meta" ]; then cp -p "$meta" "$backup/meta" || { rm -rf "$backup"; return 1; }; had_meta=1; fi
  tunnel_iface_is_up "$(wg_iface_name "$id")" && was_up=1

  if wg_write_config "$id" && wg_save_meta && wg_apply_firewall_rules "$id" && wg_start_runtime "$id"; then
    enable_ip_forward
    rm -rf "$backup"
    return 0
  fi
  err_msg "WireGuard $id configuration/startup failed."
  if [ "$had_config" -eq 1 ] && [ "$had_meta" -eq 1 ]; then
    cp -p "$backup/config" "$conf" && cp -p "$backup/meta" "$meta" || {
      err_msg "Could not restore previous files; backup retained at $backup."; return 1;
    }
    warn_msg "Previous WireGuard config and metadata restored."
    if [ "$was_up" -eq 1 ]; then
      if wg_load_meta "$id" && wg_start_runtime "$id"; then
        warn_msg "Previous WireGuard tunnel restarted successfully."
      else
        err_msg "Previous settings restored, but the previous tunnel could not restart; check its service log."
      fi
    fi
  else
    # Keep a new failed tunnel's generated config/metadata for repair and diagnostics.
    warn_msg "Saved files, if generated, were retained for repair; no successful connection was reported."
  fi
  rm -rf "$backup"
  return 1
}

# interactive=1 only from the menu; background migrations must never wait for input.
wg_choose_auto_endpoint() {
  local id="$1" role="$2" interactive="${3:-0}"
  local gre_up=0 plus_up=0 selected="" choice
  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="${REMOTE_PUBLIC_IP:-}"
  WG_TRANSPORT_IFACE=""
  tunnel_iface_is_up "$(gre_iface "$id")" && gre_up=1
  tunnel_iface_is_up "$(greplus_iface "$id")" && plus_up=1

  if [ "$gre_up" -eq 1 ] && [ "$plus_up" -eq 1 ]; then
    if [ "$interactive" -eq 1 ]; then
      echo "Both GRE and GRE Plus tunnel $id are active."
      echo "1) Normal GRE ($(gre_iface "$id"))"
      echo "2) GRE Plus ($(greplus_iface "$id"))"
      echo "Choose the SAME transport on the other server."
      while true; do
        read -rp "WireGuard transport [1-2] (00=menu): " choice || return 99
        if is_main_menu_token "$choice"; then return_main_msg; return 99; fi
        case "$choice" in
          1) selected="gre"; break ;;
          2) selected="greplus"; break ;;
          *) echo "Invalid choice. Enter 1 or 2." ;;
        esac
      done
    else
      selected="gre"
    fi
  elif [ "$gre_up" -eq 1 ]; then
    selected="gre"
  elif [ "$plus_up" -eq 1 ]; then
    selected="greplus"
  else
    return 0
  fi

  local config remote_inner transport_role remote_public
  case "$selected" in
    gre)
      WG_TRANSPORT_IFACE="$(gre_iface "$id")"
      remote_inner="$(gre_remote_inner_ip_for_role "$id" "$role")"
      config="$(gre_config_file "$id")"
      ;;
    greplus)
      WG_TRANSPORT_IFACE="$(greplus_iface "$id")"
      remote_inner="$(greplus_remote_inner_ip_for_role "$id" "$role")"
      config="$(greplus_config_file "$id")"
      ;;
  esac
  # Read saved transport data in a subshell: sourcing it directly would overwrite WG state.
  if [ -f "$config" ]; then
    transport_role="$(source "$config"; printf '%s' "${ROLE:-}")"
    if [ -n "$transport_role" ] && [ "$transport_role" != "$role" ]; then
      echo "Selected transport role differs from WireGuard role. Choose the matching server role." >&2
      return 1
    fi
    remote_public="$(source "$config"; printf '%s' "${REMOTE_PUBLIC_IP:-}")"
    if [ -n "$remote_public" ]; then REMOTE_PUBLIC_IP="$remote_public"; fi
  fi
  WG_ENDPOINT_MODE="$selected"
  WG_ENDPOINT_IP="$remote_inner"
  echo "WireGuard transport: $selected ($WG_TRANSPORT_IFACE), endpoint $WG_ENDPOINT_IP"
  return 0
}

wg_select_local_port() {
  local id="$1" saved="${2:-}" actual=""
  if [ -n "$saved" ] && tunnel_iface_is_up "$(wg_iface_name "$id")"; then
    actual="$(wg show "$(wg_iface_name "$id")" listen-port 2>/dev/null || true)"
    if [ "$actual" = "$saved" ] && ! udp_port_in_saved_configs "$saved" wireguard "$id"; then
      printf '%s\n' "$saved"
      return 0
    fi
  fi
  auto_select_udp_port "$(wg_default_port "$id")" "$saved" wireguard "$id"
}

wg_prompt_remote_port() {
  local default_port="${1:-$(wg_default_port "$TUNNEL_ID")}" input
  echo "Use the ListenPort shown on the OTHER server (it may differ from this server)."
  read -rp "REMOTE WireGuard UDP port [$default_port] (00=menu): " input || return 99
  if is_main_menu_token "$input"; then return_main_msg; return 99; fi
  input="${input:-$default_port}"
  validate_port "$input" || { err_msg "Invalid remote UDP port."; return 1; }
  REMOTE_WG_PORT="$((10#$input))"
  WG_REMOTE_PORT_CONFIRMED=1
}

wg_ensure_transport_ready() {
  local id="$1" ifc="${WG_TRANSPORT_IFACE:-}" service config expected_ip attempt
  case "${WG_ENDPOINT_MODE:-public}" in
    gre) service="$(gre_service_name "$id")"; config="$(gre_config_file "$id")" ;;
    greplus) service="$(greplus_service_name "$id")"; config="$(greplus_config_file "$id")" ;;
    public) return 0 ;;
    *) err_msg "Unsupported WireGuard transport: ${WG_ENDPOINT_MODE:-empty}"; return 1 ;;
  esac
  [ -n "$ifc" ] || { err_msg "Transport interface is missing from metadata."; return 1; }
  # Type=simple only means the supervisor has started, not that its interface is ready.
  if ! tunnel_iface_is_up "$ifc" && [ -f "$config" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl start "$service" || return 1
  fi
  for attempt in 1 2 3 4 5; do
    if tunnel_iface_is_up "$ifc"; then
      expected_ip="$(ip -o -4 addr show dev "$ifc" | awk '$3=="inet" {split($4,a,"/"); print a[1]; exit}')"
      validate_ipv4 "$expected_ip" || { err_msg "$ifc has no IPv4 address."; return 1; }
      validate_ipv4 "${WG_ENDPOINT_IP:-}" || { err_msg "Invalid transport endpoint."; return 1; }
      # Pin only the GRE inner peer, so overlay AllowedIPs cannot cause recursive routing.
      ip -4 route replace "$WG_ENDPOINT_IP/32" dev "$ifc" src "$expected_ip" || return 1
      return 0
    fi
    sleep 1
  done
  err_msg "Selected transport $ifc is not UP; WireGuard startup was stopped."
  return 1
}

wg_fix_peer_port() {
  local id="${1:-}" port="${2:-}" conf meta backup old_port was_up=0
  validate_tunnel_id "$id" && validate_port "$port" || { err_msg "Usage: --fix-wg-port <tunnel ID> <REMOTE ListenPort>"; return 1; }
  id="$((10#$id))"; port="$((10#$port))"
  wg_ensure_tools || return 1
  install_manager_binary || return 1
  wg_load_meta "$id" || { err_msg "Missing metadata for WireGuard $id."; return 1; }
  validate_wg_public_key "$REMOTE_WG_PUBLIC_KEY" || { err_msg "The remote public key is missing/invalid."; return 1; }
  [ -s "$(wg_private_key_file "$id")" ] || { err_msg "Private key is missing; it was not regenerated."; return 1; }
  validate_ipv4 "$(wg_auto_endpoint_ip)" || { err_msg "Invalid saved endpoint IP."; return 1; }
  conf="$(wg_config_file "$id")"; meta="$(wg_meta_file "$id")"
  [ -f "$conf" ] || { err_msg "Saved WireGuard config is missing."; return 1; }
  backup="$(mktemp -d "$WG_META_DIR/.port-fix.XXXXXX")" || return 1
  cp -p "$conf" "$backup/config" && cp -p "$meta" "$backup/meta" || { rm -rf "$backup"; return 1; }
  tunnel_iface_is_up "$(wg_iface_name "$id")" && was_up=1
  old_port="$REMOTE_WG_PORT"
  REMOTE_WG_PORT="$port"; WG_REMOTE_PORT_CONFIRMED=1
  if wg_write_config "$id" && wg_save_meta && wg_apply_firewall_rules "$id"; then
    if [ "$was_up" -eq 1 ]; then
      if wg set "$(wg_iface_name "$id")" peer "$REMOTE_WG_PUBLIC_KEY" endpoint "$(wg_auto_endpoint_ip):$port"; then
        rm -rf "$backup"
        ok_msg "WireGuard $id peer port updated: $old_port -> $port (runtime, config, metadata)."
        echo "Endpoint: $(wg_auto_endpoint_ip):$port; LOCAL ListenPort: $LOCAL_WG_PORT"
        return 0
      fi
    elif wg_start_runtime "$id"; then
      rm -rf "$backup"
      ok_msg "WireGuard $id started with remote port $port."
      return 0
    fi
  fi
  if ! cp -p "$backup/config" "$conf" || ! cp -p "$backup/meta" "$meta"; then
    err_msg "Repair failed; could not restore files. Backup retained at $backup."; return 1
  fi
  rm -rf "$backup"
  err_msg "Port repair failed; previous config and metadata restored."
  return 1
}

wg_service_preflight() (
  local id="$1"
  wg_load_meta "$id" || { err_msg "Missing WireGuard metadata for $id."; return 1; }
  [ -n "$REMOTE_WG_PUBLIC_KEY" ] || { err_msg "WireGuard $id is pending the remote public key."; return 1; }
  wg_ensure_transport_ready "$id" || return 1
  wg_apply_firewall_rules "$id"
)

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
  if [[ "$WG_ENDPOINT_MODE" == gre || "$WG_ENDPOINT_MODE" == greplus ]]; then
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
  local id="$1" parent_mtu="" calculated parent_ifc
  parent_ifc="${WG_TRANSPORT_IFACE:-$(gre_iface "$id")}"
  parent_mtu="$(ip -o link show dev "$parent_ifc" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="mtu") {print $(i+1); exit}}')"
  [[ "$parent_mtu" =~ ^[0-9]+$ ]] || parent_mtu=1390
  calculated=$((parent_mtu - 60))
  [ "$calculated" -lt 1280 ] && calculated=1280
  [ "$calculated" -gt 1420 ] && calculated=1420
  echo "$calculated"
}

wg_menu_config_tunnel() {
  wg_ensure_tools || return 1
  show_header "Configure WireGuard Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_peer_key
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter WireGuard tunnel number before IP [1-254]: " || return
  transparent_guard "$(wg_iface_name "$TUNNEL_ID")" || return 1

  existing_local_ip=""
  existing_remote_ip=""
  existing_peer_key=""
  local existing_wg_port existing_remote_port existing_remote_port_confirmed
  existing_wg_port=""; existing_remote_port=""; existing_remote_port_confirmed=0
  if wg_load_meta "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_peer_key="${REMOTE_WG_PUBLIC_KEY:-}"
    existing_wg_port="${LOCAL_WG_PORT:-}"
    existing_remote_port="${REMOTE_WG_PORT:-}"
    existing_remote_port_confirmed="${WG_REMOTE_PORT_CONFIRMED:-0}"
  fi
  ROLE="$selected_role"
  REMOTE_WG_PUBLIC_KEY="$existing_peer_key"

  REMOTE_PUBLIC_IP="$existing_remote_ip"
  wg_choose_auto_endpoint "$TUNNEL_ID" "$ROLE" 1 || return $?
  if [ "${WG_ENDPOINT_MODE:-public}" = "public" ]; then
    prompt_remote_public_ip "$existing_remote_ip" || return
    WG_ENDPOINT_IP="$REMOTE_PUBLIC_IP"
  fi

  echo
  wg_print_ip_plan "$TUNNEL_ID"
  echo
  echo "For servers with multiple IP addresses, choose the exact LOCAL IPv4 that the other side should use as this server endpoint."
  echo "WireGuard listens on the generated UDP port; this value is saved and shown so the peer can use the correct IP."
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for WireGuard endpoint" || return
  echo "Use this IP as the REMOTE server Public IPv4 on the other server: $LOCAL_PUBLIC_IP"
  echo

  LOCAL_WG_PORT="${existing_wg_port:-$(wg_default_port "$TUNNEL_ID")}"
  REMOTE_WG_PORT="$(wg_default_port "$TUNNEL_ID")"
  WG_REMOTE_PORT_CONFIRMED=0
  if [ "$existing_remote_port_confirmed" = 1 ] && validate_port "$existing_remote_port"; then
    REMOTE_WG_PORT="$existing_remote_port"
    WG_REMOTE_PORT_CONFIRMED=1
  elif [ -n "$existing_remote_port" ] && [ "$existing_remote_port" != "$REMOTE_WG_PORT" ]; then
    warn_msg "Old saved peer port $existing_remote_port needs confirmation. The default is now $REMOTE_WG_PORT for tunnel $TUNNEL_ID."
    echo "If the OTHER server really uses $existing_remote_port, enter it explicitly at the remote-port prompt."
  fi
  EXTRA_ALLOWED_IPS=""

  # Remove only a legacy WSS companion for this number.
  if [ -f "$(wss_config_file "$TUNNEL_ID")" ]; then
    wss_remove_one "$TUNNEL_ID" || true
  fi

  case "${WG_ENDPOINT_MODE:-public}" in
    gre|greplus) WG_MTU="$(wg_mtu_for_gre "$TUNNEL_ID")" ;;
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
  if [[ "${WG_ENDPOINT_MODE:-public}" == gre || "${WG_ENDPOINT_MODE:-public}" == greplus ]]; then
    echo "  Transport interface    : ${WG_TRANSPORT_IFACE:-gre$TUNNEL_ID}"
  fi
  echo "  AllowedIPs             : peer /32 only"
  if [ -n "$REMOTE_WG_PUBLIC_KEY" ]; then
    echo "  Remote public key      : already saved"
    echo
    echo "Saved remote peer key found."
    echo "Press Enter to keep it, paste a new peer public key to replace it, or type CLEAR to reset this tunnel to pending."
    local peer_key_input
    read -rp "REMOTE WireGuard public key [keep/CLEAR/new] (00=menu): " peer_key_input || return 99
    if is_main_menu_token "$peer_key_input"; then return_main_msg; return 99; fi
    if [ "${peer_key_input^^}" = "CLEAR" ]; then
      REMOTE_WG_PUBLIC_KEY=""
    elif [ -n "$peer_key_input" ]; then
      REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "$peer_key_input")"
    fi
  fi
  echo

  # Peer key input is completed before deleting the existing runtime interface.
  if [ -z "$REMOTE_WG_PUBLIC_KEY" ]; then
    wg_generate_keys "$TUNNEL_ID" || return 1
    echo "Local WireGuard public key: $(cat "$(wg_public_key_file "$TUNNEL_ID")")"
    read -rp "REMOTE WireGuard public key (Enter=pending, 00=menu): " REMOTE_WG_PUBLIC_KEY || return 99
    if is_main_menu_token "$REMOTE_WG_PUBLIC_KEY"; then return_main_msg; return 99; fi
    REMOTE_WG_PUBLIC_KEY="$(normalize_wg_public_key "$REMOTE_WG_PUBLIC_KEY")"
  fi
  if [ -n "$REMOTE_WG_PUBLIC_KEY" ]; then
    validate_wg_public_key "$REMOTE_WG_PUBLIC_KEY" || { err_msg "Invalid remote public key; current tunnel was left running."; return 1; }
    wg_generate_keys "$TUNNEL_ID" || return 1
    if [ "$REMOTE_WG_PUBLIC_KEY" = "$(cat "$(wg_public_key_file "$TUNNEL_ID")")" ]; then
      err_msg "Use the OTHER server's public key; current tunnel was left running."
      return 1
    fi
  fi
  wg_prompt_remote_port "$REMOTE_WG_PORT" || return $?
  if [ -n "$REMOTE_WG_PUBLIC_KEY" ]; then wg_ensure_transport_ready "$TUNNEL_ID" || return 1; fi
  LOCAL_WG_PORT="$(wg_select_local_port "$TUNNEL_ID" "$existing_wg_port")" || return 1
  echo "Final UDP ports: LOCAL ListenPort=$LOCAL_WG_PORT / REMOTE Endpoint port=$REMOTE_WG_PORT"
  wg_create_tunnel 0 || { local rc=$?; [ "$rc" -eq 99 ] || err_msg "WireGuard tunnel creation failed"; return "$rc"; }
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
      gre|greplus) echo "Transport interface : ${WG_TRANSPORT_IFACE:-}" ;;
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
      if ping -n -I "$ifc" -c 4 "$REMOTE_WG_IP" >/tmp/wg_ping_$$.log 2>&1; then
        cat /tmp/wg_ping_$$.log
        echo "[OK] WireGuard inner tunnel is UP"
      else
        cat /tmp/wg_ping_$$.log
        echo "[WARN] WireGuard inner ping failed"
        last="$(wg show "$ifc" latest-handshakes 2>/dev/null | awk 'NR==1{print $2}' || true)"
        if [ -z "$last" ] || [ "$last" = "0" ]; then
          if [[ "${WG_ENDPOINT_MODE:-public}" == gre || "${WG_ENDPOINT_MODE:-public}" == greplus ]]; then
            echo "Diagnosis: no WireGuard handshake yet. WireGuard is using ${WG_ENDPOINT_MODE} transport. Check that transport tunnel $id still pings, the peer public key is correct, and UDP ${LOCAL_WG_PORT:-$(wg_default_port "$id")} is allowed over ${WG_TRANSPORT_IFACE:-transport interface} on both servers."
          else
            echo "Diagnosis: no WireGuard handshake yet. Check the peer public key, remote public IP, UDP port ${REMOTE_WG_PORT:-$(wg_default_port "$id")}, and firewall/NAT on both servers. If public UDP/WireGuard is blocked but GRE works, re-run create/update after GRE is up; v6 will auto-use GRE as WireGuard transport."
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
  install_health_monitor || return 1
  diagnostic_prepare_logs || return 1
  mkdir -p "/etc/systemd/system/wg-quick@$ifc.service.d"
  local transport_after=""
  if wg_load_meta "$id"; then
    case "${WG_ENDPOINT_MODE:-public}" in
      gre) transport_after="gre-tunnel@$id.service" ;;
      greplus) transport_after="$(greplus_service_name "$id")" ;;
    esac
  fi
  if [ -n "$transport_after" ]; then
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target $transport_after
Wants=$transport_after

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service prepare-wg $id
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG
EOF_WG_FW
  else
    cat > "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf" <<EOF_WG_FW
[Unit]
After=network-online.target

[Service]
ExecStartPre=/bin/bash $INSTALL_BIN --service prepare-wg $id
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG
EOF_WG_FW
  fi

  systemctl daemon-reload

  wg_service_preflight "$id" || return 1

  # Avoid stale interface/socket/route bugs, but only touch this WireGuard tunnel.
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true

  if wg_load_meta "$id" && [ -n "${LOCAL_WG_PORT:-}" ] && udp_port_is_listening "$LOCAL_WG_PORT"; then
    err_msg "UDP port $LOCAL_WG_PORT is still busy after cleaning $ifc."
    echo "Check what owns it with: ss -lunp | grep ':$LOCAL_WG_PORT'" >&2
    echo "Then re-run create/update; the script can choose another free port if the saved one is cleared or changed." >&2
    return 1
  fi

  systemctl enable "$svc" || return 1
  if systemctl restart "$svc" && tunnel_iface_is_up "$ifc"; then
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
  wg_ensure_tools || return 1
  wg_generate_keys "$id" || return 1
  wg_ensure_transport_ready "$id" || return 1
  wg_write_config "$id" || return 1
  enable_ip_forward
  wg_apply_firewall_rules "$id" || return 1

  echo "Restarting WireGuard tunnel $id ($ifc)..."
  if command -v systemctl >/dev/null 2>&1; then
    wg_install_service "$id" || { wg_print_service_failure "$id"; return 1; }
  else
    wg_safe_cleanup_runtime "$id" || return 1
    wg-quick up "$ifc" || return 1
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

wg_apply_firewall_rules() (
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
    if [[ "$endpoint_mode" == gre || "$endpoint_mode" == greplus ]] && [ -n "$transport_ifc" ]; then
      iptables -C INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT 2>/dev/null || iptables -A INPUT -i "$transport_ifc" -p udp --dport "$port" -j ACCEPT || true
      if [ -n "$endpoint_ip" ]; then
        iptables -C OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -A OUTPUT -o "$transport_ifc" -p udp -d "$endpoint_ip" --dport "$remote_port" -j ACCEPT || true
      fi
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$port/udp" comment "wgtun$id" >/dev/null 2>&1 || true
    ufw allow in on "$ifc" >/dev/null 2>&1 || true
    if [[ "$endpoint_mode" == gre || "$endpoint_mode" == greplus ]] && [ -n "$transport_ifc" ]; then
      ufw allow in on "$transport_ifc" to any port "$port" proto udp >/dev/null 2>&1 || true
    fi
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$port/udp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-interface="$ifc" >/dev/null 2>&1 || true
    if [[ "$endpoint_mode" == gre || "$endpoint_mode" == greplus ]] && [ -n "$transport_ifc" ]; then
      firewall-cmd --permanent --add-interface="$transport_ifc" >/dev/null 2>&1 || true
    fi
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
)

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
  transparent_remove_interface "$(wg_iface_name "$id")" || return 1
  local ifc conf meta private public endpoint_mode=""
  ifc="$(wg_iface_name "$id")"
  conf="$(wg_config_file "$id")"
  meta="$(wg_meta_file "$id")"
  private="$(wg_private_key_file "$id")"
  public="$(wg_public_key_file "$id")"
  if wg_load_meta "$id"; then endpoint_mode="${WG_ENDPOINT_MODE:-}"; fi

  echo "Removing WireGuard tunnel $id ($ifc)..."

  stop_tunnel_for_remove "$(wg_service_name "$id")" || return 1

  # Safe cleanup only for this WireGuard tunnel. Do not touch the main route table.
  wg_safe_cleanup_runtime "$id" >/dev/null 2>&1 || true
  verify_interface_removed "$ifc" || return 1
  wg_remove_firewall_rules "$id"
  if [ -f "$(wss_config_file "$id")" ]; then
    wss_remove_one "$id"
  fi

  rm -f "/etc/systemd/system/wg-quick@$ifc.service.d/10-gretun-firewall.conf"
  rmdir "/etc/systemd/system/wg-quick@$ifc.service.d" 2>/dev/null || true
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
  local TUNNEL_TYPE TUNNEL_ID TUN_IFACE TUN_KEY ROLE SERVER_ROLE LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP
  local LOCAL_GRE_IP REMOTE_GRE_IP LOCAL_GREPLUS_IP REMOTE_GREPLUS_IP GREPLUS_MTU GREPLUS_TUN_KEY GREPLUS_TXQUEUELEN
  local WG_IFACE LOCAL_WG_IP REMOTE_WG_IP LOCAL_WG_PORT REMOTE_WG_PORT WG_REMOTE_PORT_CONFIRMED WG_ENDPOINT_MODE WG_ENDPOINT_IP
  local WG_TRANSPORT_IFACE WG_MTU REMOTE_WG_PUBLIC_KEY WG_PENDING EXTRA_ALLOWED_IPS
  local WG_CONFIG_FILE WG_PRIVATE_KEY_FILE WG_PUBLIC_KEY_FILE
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
    if [ "$desc" = "WireGuard/PENDING" ]; then state="pending-key"
    elif tunnel_iface_is_up "$ifc"; then state="active"; else state="inactive"; fi
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
wg_uses_transport_tunnel() (
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
    greplus)
      expected_ifc="$(greplus_iface "$transport_id")"
      [ "${WG_ENDPOINT_MODE:-}" = "greplus" ] || return 1
      ;;
    *)
      return 1
      ;;
  esac

  # Normal case: transport interface is saved explicitly.
  if [ -n "${WG_TRANSPORT_IFACE:-}" ] && [ "${WG_TRANSPORT_IFACE}" = "$expected_ifc" ]; then
    return 0
  fi
  [ -z "${WG_TRANSPORT_IFACE:-}" ] || return 1

  # Backward compatibility: older metadata may only use same-number transport.
  [ "$wg_id" = "$transport_id" ]
)

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
      gre|greplus)
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

gre_apply_firewall_rules() (
  local id="$1"
  local ifc
  validate_tunnel_id "$id" || return 1
  gre_load_config "$id" || return 1
  ifc="$(gre_iface "$id")"
  enable_ip_forward
  firewall_allow_ip_peer "GRE tunnel $id remote public" "${REMOTE_PUBLIC_IP:-}" "$ifc" >/dev/null 2>&1 || true
  firewall_allow_ip_peer "GRE tunnel $id remote inner" "${REMOTE_GRE_IP:-}" "$ifc" >/dev/null 2>&1 || true
)

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
    selected=""
    for ((idx=1; idx<=${#INV_TYPE[@]}; idx++)); do selected+="$idx "; done
    echo "All managed tunnels selected."
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
    token="$((10#$token))"
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
  local remove_failed=0
  for phase in wireguard greplus gre; do
    for idx in "${SELECTED_INDEXES[@]}"; do
      i=$((idx - 1))
      if [ "${INV_TYPE[$i]}" = "$phase" ]; then
        echo
        echo -e "${C_CYAN}Removing row $idx: ${INV_TYPE[$i]} ${INV_ID[$i]} (${INV_IFACE[$i]})${C_RESET}"
        if ! remove_inventory_item "$idx"; then
          remove_failed=$((remove_failed + 1))
          warn_msg "Could not fully remove row $idx (${INV_TYPE[$i]} ${INV_ID[$i]}). Continue with the next selected tunnel."
        fi
      fi
    done
  done

  if [ "$remove_failed" -gt 0 ]; then
    err_msg "Removal incomplete: $remove_failed tunnel(s) failed. Saved configs were retained where possible."; return 1
  fi
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
  if ! tunnel_iface_is_up "$(wg_iface_name "$id")"; then
    echo "[REPAIR] WireGuard $id is inactive; repairing its saved transport/config/service..."
    wg_restart_one_tunnel "$id" || return 1
    wg_load_meta "$id" || return 1
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

# Select inventory rows, not tunnel IDs (GRE/GRE Plus/WG may share the same ID).
speed_test_parse_selection() {
  local raw="${1:-}" count="${2:-0}" token number
  local -a tokens=()
  local -A seen=()
  SPEED_TEST_SELECTION=()
  raw="${raw//,/ }"
  read -r -a tokens <<< "$raw"
  [ "${#tokens[@]}" -gt 0 ] && [ "$count" -gt 0 ] || { err_msg "No tunnel rows selected."; return 1; }
  if [ "${#tokens[@]}" -eq 1 ] && [ "${tokens[0]}" = 0 ]; then
    for ((number=1;number<=count;number++)); do SPEED_TEST_SELECTION+=("$number"); done
    return 0
  fi
  for token in "${tokens[@]}"; do
    [[ "$token" =~ ^[0-9]{1,9}$ ]] || { SPEED_TEST_SELECTION=(); err_msg "Invalid row: $token"; return 1; }
    number="$((10#$token))"
    [ "$number" -ge 1 ] && [ "$number" -le "$count" ] || {
      SPEED_TEST_SELECTION=(); err_msg "Row $token is outside the list. Use 0 alone for ALL."; return 1;
    }
    if [ -z "${seen[$number]+x}" ]; then
      SPEED_TEST_SELECTION+=("$number"); seen[$number]=1
    fi
  done
}

speed_test_restore_int_trap() {
  local saved="${1:-}"
  trap - INT
  if [ -n "$saved" ]; then eval "$saved"; fi
}

speed_test_outside_server() {
  local rc=0 saved_int interrupted=0
  # One listener accepts every GRE/GRE Plus/WG inner address; do not bind to a single tunnel.
  iperf3_prepare_firewall || return 1
  echo "Outside speed-test server: listening on all IPv4 addresses, TCP port 5201."
  echo "It remains running after each Iran test. Other Iran servers can test in turn."
  echo "Close it yourself with Ctrl+C when all tests are finished. Keep this SSH window open."
  echo "Command: iperf3 -s -4 -p 5201"
  saved_int="$(trap -p INT)"
  trap 'interrupted=1' INT
  if iperf3 -s -4 -p 5201; then :; else rc=$?; fi
  speed_test_restore_int_trap "$saved_int"
  if [ "$interrupted" -eq 1 ] || [ "$rc" -eq 130 ]; then
    info_msg "Outside speed-test server closed manually. Returning to the menu."
    return 0
  elif [ "$rc" -ne 0 ]; then
    err_msg "iperf3 server stopped with status $rc. Check whether port 5201 is already in use."
    return "$rc"
  fi
  info_msg "Outside speed-test server stopped."
}

tunnel_speed_test_menu() {
  show_header "Tunnel Throughput Speed Test"
  local role selected duration row idx ifc local_ip target rc saved_int interrupted=0
  local ok=0 failed=0 skipped=0 completed=0
  local -a results=() connect_options=() command=()
  echo "Select this server's location:"
  echo "1) Iran (test selected tunnels)"
  echo "2) Kharej/outside (keep speed-test server running)"
  read -rp "Choose [1-2] (00=menu): " role || return 99
  if is_main_menu_token "$role"; then return_main_msg; return 99; fi
  case "$role" in
    2)
      ensure_feature_dependencies "speed-test" "iperf3:iperf3" || return 1
      speed_test_outside_server
      return $?
      ;;
    1) ;;
    *) err_msg "Invalid role."; return 1 ;;
  esac

  build_tunnel_inventory
  print_tunnel_inventory || return 1
  echo "Select ONE or MORE row numbers: 1 2 3  /  1,2,3,  /  2"
  echo "0) Test ALL listed tunnels"
  echo "Selected rows are tested in your order, once each."
  read -rp "Tunnel rows (00=menu): " selected || return 99
  if is_main_menu_token "$selected"; then return_main_msg; return 99; fi
  speed_test_parse_selection "$selected" "${#INV_TYPE[@]}" || return 1
  read -rp "Duration per tunnel in seconds [10] (00=menu): " duration || return 99
  if is_main_menu_token "$duration"; then return_main_msg; return 99; fi
  duration="${duration:-10}"
  [[ "$duration" =~ ^[0-9]{1,4}$ ]] && [ "$((10#$duration))" -ge 1 ] && [ "$((10#$duration))" -le 3600 ] || {
    err_msg "Duration must be from 1 to 3600 seconds."; return 1;
  }
  duration="$((10#$duration))"
  ensure_feature_dependencies "speed-test" "iperf3:iperf3" "timeout:coreutils" || return 1
  if iperf3 --help 2>&1 | grep -q -- '--connect-timeout'; then connect_options=(--connect-timeout 5000); fi
  echo "Keep the outside speed-test server running. These client tests stop automatically."
  echo "TCP upload from Iran, 4 parallel streams, $duration seconds per tunnel."
  saved_int="$(trap -p INT)"
  trap 'interrupted=1' INT
  for row in "${SPEED_TEST_SELECTION[@]}"; do
    [ "$interrupted" -eq 0 ] || break
    idx=$((row - 1)); ifc="${INV_IFACE[$idx]:-}"
    local_ip="${INV_LOCAL[$idx]:-}"; local_ip="${local_ip%%/*}"
    target="${INV_TARGET[$idx]:-}"; target="${target%%/*}"
    echo
    echo "============================================================"
    echo "[$((completed + 1))/${#SPEED_TEST_SELECTION[@]}] row $row | ${INV_TYPE[$idx]} ID ${INV_ID[$idx]} | $ifc"
    echo "Local: ${local_ip:-missing} -> Remote: ${target:-missing}"
    if [ "${INV_STATE[$idx]:-}" = pending-key ] || ! validate_ipv4 "$local_ip" || ! validate_ipv4 "$target" || ! tunnel_iface_is_up "$ifc"; then
      warn_msg "Skipped: interface is down/pending or a tunnel IP is missing."
      results+=("SKIPPED"); skipped=$((skipped + 1)); completed=$((completed + 1))
      continue
    fi
    command=(iperf3 -4 -c "$target" -B "$local_ip" -p 5201 -t "$duration" -P 4 "${connect_options[@]}")
    printf 'Command: '; printf '%q ' "${command[@]}"; printf '\n'
    rc=0
    if timeout --signal=INT --kill-after=5s "$((duration + 20))s" "${command[@]}"; then :; else rc=$?; fi
    completed=$((completed + 1))
    if [ "$interrupted" -eq 1 ] || [ "$rc" -eq 130 ]; then
      results+=("INTERRUPTED")
      warn_msg "Testing cancelled; remaining rows will not run."
      break
    elif [ "$rc" -eq 0 ]; then
      results+=("OK"); ok=$((ok + 1))
    else
      results+=("FAILED($rc)"); failed=$((failed + 1))
      warn_msg "This test failed (status $rc); continuing with the next selected row."
    fi
  done
  speed_test_restore_int_trap "$saved_int"
  echo
  echo "Speed test summary"
  printf '%4s  %-11s %-4s %-12s %s\n' "Row" "Type" "ID" "Interface" "Result"
  local n
  for n in "${!SPEED_TEST_SELECTION[@]}"; do
    row="${SPEED_TEST_SELECTION[$n]}"; idx=$((row - 1))
    printf '%4s  %-11s %-4s %-12s %s\n' "$row" "${INV_TYPE[$idx]}" "${INV_ID[$idx]}" "${INV_IFACE[$idx]}" "${results[$n]:-NOT-RUN}"
  done
  echo "Selected=${#SPEED_TEST_SELECTION[@]} completed=$completed ok=$ok failed=$failed skipped=$skipped"
  echo "Iran client tests finished. The outside server remains running until you close it."
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
  local ifc="${1:-}" port=5201 source_range
  local -a rule=()
  if [ -n "$ifc" ]; then
    rule=(-i "$ifc" -p tcp --dport "$port")
    if command -v iptables >/dev/null 2>&1; then
      iptables -C INPUT "${rule[@]}" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT "${rule[@]}" -j ACCEPT || return 1
    fi
    command -v ufw >/dev/null 2>&1 && ufw allow in on "$ifc" to any port "$port" proto tcp >/dev/null 2>&1 || true
  else
    # Current and future managed tunnels can reach the shared listener without a tunnel picker.
    for source_range in 10.10.0.0/16 10.20.0.0/16 10.30.0.0/16; do
      rule=(-s "$source_range" -p tcp --dport "$port")
      if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT "${rule[@]}" -j ACCEPT >/dev/null 2>&1 || iptables -I INPUT "${rule[@]}" -j ACCEPT || return 1
      fi
      command -v ufw >/dev/null 2>&1 && ufw allow from "$source_range" to any port "$port" proto tcp >/dev/null 2>&1 || true
    done
  fi
  return 0
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
  transparent_reset_check || return 1
  show_header "Reset All Tunnels"
  echo "This will restart/recreate all saved normal GRE, GRE Plus, and WireGuard tunnels from their saved configs."
  echo "It will also re-enable their systemd services for boot."
  echo
  if ! confirm_yes "Continue with reset all tunnels?"; then
    echo "Cancelled."
    return
  fi

  reset_saved_configs_check || return 1
  install_manager_binary || return 1
  diagnostic_event "MANUAL" "manager" "manual reset-all started by operator"

  echo
  echo "Stopping WireGuard first..."
  local ids id failed=0

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
    systemctl stop "$(gre_service_name "$id")" 2>/dev/null || true
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
        failed=$((failed + 1)); echo "[WARN] GRE tunnel $id reset failed"
      fi
    else
      failed=$((failed + 1)); echo "[WARN] GRE tunnel $id config could not be loaded"
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
        failed=$((failed + 1)); echo "[WARN] GRE Plus tunnel $id reset failed"
      fi
    else
      failed=$((failed + 1)); echo "[WARN] GRE Plus tunnel $id config could not be loaded"
    fi
  done <<< "$ids"

  echo
  echo "Starting WireGuard tunnels..."
  ids="$(wg_collect_ids || true)"
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if ! wg_load_meta "$id"; then
      failed=$((failed + 1)); echo "[WARN] WireGuard tunnel $id metadata could not be loaded"; continue
    fi
    if [ -z "${REMOTE_WG_PUBLIC_KEY:-}" ]; then
      echo "[SKIP] WireGuard tunnel $id is pending peer key"
      continue
    fi
    if wg_reset_saved_tunnel "$id"; then
      echo "[OK] WireGuard tunnel $id reset"
    else
      failed=$((failed + 1)); echo "[WARN] WireGuard tunnel $id reset failed"
    fi
  done <<< "$ids"

  echo
  if ! transparent_reset_restore; then
    failed=$((failed + 1)); err_msg "Transparent route restore failed; inspect the error above."
  fi
  if [ "$failed" -gt 0 ]; then err_msg "Reset completed with $failed tunnel failure(s)."; return 1; fi
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
  local report="/root/gretun-diagnostic-$(diag_filename_stamp).log"
  diagnostics_collect_current || true
  {
    echo "GRE-TUN diagnostic report"
    echo "Generated: $(diag_now)"
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
  transparent_guard haproxy || return 1
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
  transparent_guard haproxy || return 1
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

stop_tunnel_for_remove() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl disable --now "$svc"; then
      if systemctl is-active --quiet "$svc"; then
        err_msg "Service $svc is still active; its tunnel config was retained."; return 1
      fi
    fi
  fi
}

verify_interface_removed() {
  if ip link show dev "$1" >/dev/null 2>&1; then
    err_msg "Interface $1 still exists; its saved config was retained."; return 1
  fi
}

remove_transport_dependency_check() {
  local kind="$1" id="$2" wg_id
  while IFS= read -r wg_id; do
    [ -n "$wg_id" ] || continue
    if wg_uses_transport_tunnel "$wg_id" "$kind" "$id"; then
      err_msg "Cannot remove $kind $id: WireGuard $wg_id still depends on it. Remove its row first or select both rows."; return 1
    fi
  done < <(wg_collect_ids)
}

transparent_remove_interface() {
  local module iface="$1"
  compgen -G '/etc/gretun-transparent/profile-*.json' >/dev/null || return 0
  module="$(transparent_module_path)" || return 1
  python3 "$module" remove-interface "$iface"
}

wg_reset_saved_tunnel() {
  local id="$1" ifc svc conf
  ifc="$(wg_iface_name "$id")"; svc="$(wg_service_name "$id")"; conf="$(wg_config_file "$id")"
  [ -s "$conf" ] || { err_msg "Missing saved WireGuard config: $conf"; return 1; }
  wg_ensure_tools || return 1
  wg_ensure_transport_ready "$id" || return 1
  wg_apply_firewall_rules "$id" || return 1
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable "$svc" || return 1
    systemctl restart "$svc" || { wg_print_service_failure "$id"; return 1; }
  else
    wg-quick up "$ifc" || return 1
  fi
  transparent_repair_routes "$ifc" || return 1
  ip link show dev "$ifc" >/dev/null 2>&1
}

transparent_reset_check() {
  local module
  compgen -G '/etc/gretun-transparent/profile-*.json' >/dev/null || return 0
  module="$(transparent_module_path)" || return 1
  python3 "$module" reset-check
}

transparent_reset_restore() {
  local module
  compgen -G '/etc/gretun-transparent/profile-*.json' >/dev/null || return 0
  module="$(transparent_module_path)" || return 1
  python3 "$module" restore
}

reset_saved_configs_check() (
  local id
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    gre_load_config "$id" || { err_msg "Cannot load GRE config $id; nothing stopped."; return 1; }
  done < <(gre_collect_ids)
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    greplus_load_config "$id" || { err_msg "Cannot load GRE Plus config $id; nothing stopped."; return 1; }
  done < <(greplus_collect_ids)
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    wg_load_meta "$id" || { err_msg "Cannot load WireGuard metadata $id; nothing stopped."; return 1; }
    if [ -n "${REMOTE_WG_PUBLIC_KEY:-}" ] && [ ! -s "$(wg_config_file "$id")" ]; then
      err_msg "Missing saved WireGuard config $id; nothing stopped."; return 1
    fi
  done < <(wg_collect_ids)
)

TRANSPARENT_SHA256="585f575af826c2ccbef335f94f1c9ba72e19175754ab92f1d9942472dd6b0928"
# Embedded fallback keeps one-file curl installs in sync with their helper.
transparent_embedded_to_file() {
  python3 -c "import base64,gzip,pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(gzip.decompress(base64.b64decode('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')))" "$1"
}

transparent_install_module() {
  local target=/usr/local/lib/gretun/transparent_forward.py candidate tmp
  if [ -f "$target" ] && [ "$(sha256sum "$target" | awk '{print $1}')" = "$TRANSPARENT_SHA256" ]; then
    printf '%s' "$target"; return 0
  fi
  mkdir -p /usr/local/lib/gretun || return 1
  tmp="$(mktemp /usr/local/lib/gretun/.transparent.XXXXXXXX)" || return 1
  candidate="$(dirname -- "${BASH_SOURCE[0]}")/transparent_forward.py"
  if [ -f "$candidate" ] && [ "$(sha256sum "$candidate" | awk '{print $1}')" = "$TRANSPARENT_SHA256" ]; then
    cp -- "$candidate" "$tmp" || { rm -f "$tmp"; return 1; }
  elif transparent_embedded_to_file "$tmp"; then
    :
  elif command -v curl >/dev/null 2>&1; then
    curl -fLsS --ipv4 --connect-timeout 10 --max-time 45 "${SELF_RAW_URL%/*}/transparent_forward.py" -o "$tmp" || { rm -f "$tmp"; return 1; }
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=15 --tries=2 -O "$tmp" "${SELF_RAW_URL%/*}/transparent_forward.py" || { rm -f "$tmp"; return 1; }
  else
    rm -f "$tmp"; err_msg "curl or wget is required to install transparent forwarding." >&2; return 1
  fi
  if [ "$(sha256sum "$tmp" | awk '{print $1}')" != "$TRANSPARENT_SHA256" ]; then
    rm -f "$tmp"; err_msg "Helper checksum mismatch. Upload matching GRETUN.sh and transparent_forward.py from the same release." >&2; return 1
  fi
  python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' "$tmp" || { rm -f "$tmp"; return 1; }
  chmod 755 "$tmp" && mv -f -- "$tmp" "$target" || { rm -f "$tmp"; return 1; }
  printf '%s' "$target"
}

transparent_module_path() {
  # Never return an arbitrary old adjacent or installed helper.
  transparent_install_module
}

transparent_guard() {
  local scope="${1:-all}" module
  compgen -G '/etc/gretun-transparent/profile-*.json' >/dev/null || return 0
  module="$(transparent_module_path)" || return 1
  python3 "$module" guard "$scope"
}

transparent_repair_routes() {
  local iface="$1" module
  compgen -G '/etc/gretun-transparent/profile-*.json' >/dev/null || return 0
  module="$(transparent_module_path)" || return 1
  python3 "$module" restore "$iface"
}

transparent_menu() {
  local module
  ensure_feature_dependencies "transparent-forward" "python3:python3" "ip:iproute2" "ss:iproute2" "iptables:iptables" "iptables-save:iptables" "conntrack:conntrack" "sha256sum:coreutils" || return 1
  module="$(transparent_install_module)" || return 1
  install_manager_binary || return 1
  python3 "$module" auto
}


show_menu() {
  show_header "GRE + GRE Plus + WireGuard Management v${APP_VERSION}"
  echo -e "${C_BOLD}${C_WHITE}Main Menu${C_RESET}"
  echo -e "  ${C_GREEN}1)${C_RESET} create/update tunnel"
  echo -e "  ${C_RED}2)${C_RESET} remove tunnel"
  echo -e "  ${C_YELLOW}3)${C_RESET} reset all tunnels"
  echo -e "  ${C_CYAN}4)${C_RESET} ping test tunnels"
  echo -e "  ${C_MAGENTA}5)${C_RESET} throughput speed test ${C_DIM}(multi-select / persistent server)${C_RESET}"
  echo -e "  ${C_MAGENTA}6)${C_RESET} haproxy port manager"
  echo -e "  ${C_YELLOW}7)${C_RESET} disconnect / error / restart logs"
  echo -e "  ${C_CYAN}8)${C_RESET} performance / capacity / migration tools"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
  echo "  9) Transparent client IP: ON / OFF (Iran / Outside)"
  read -rp "Choose an option [0-9]: " CHOICE
  case "$CHOICE" in
    1) if run_maintenance_action menu_config_tunnel; then pause; fi ;;
    2) if run_maintenance_action remove_tun; then pause; fi ;;
    3) if run_maintenance_action reset_all_tunnels; then pause; fi ;;
    4) if test_tunnels_menu; then pause; fi ;;
    5) if tunnel_speed_test_menu; then pause; fi ;;
    6) haproxy_menu || true ;;
    7) diagnostics_menu || true ;;
    8) performance_menu || true ;;
    9) transparent_menu || true ;;
    00) return_main_msg ;;
    0) echo "Bye"; exit 0 ;;
    *) err_msg "Invalid option"; sleep 1 ;;
  esac
}

### Script entry
if [[ "${1:-}" == "--version" ]]; then printf "%s\n" "$APP_VERSION"; exit 0; fi
if [[ "${1:-}" == "--install" ]]; then ensure_root; install_manager_binary; exit $?; fi
if [[ "${1:-}" == "--transparent" ]]; then ensure_root; transparent_menu; exit $?; fi
if [[ "${1:-}" == "--fix-wg-port" ]]; then
  ensure_root
  run_maintenance_action wg_fix_peer_port "${2:-}" "${3:-}"
  exit $?
fi

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
    prepare-wg)
      ensure_root
      wg_service_preflight "${3:-}"
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
      echo "Unknown service command. Use --service prepare-wg <id>, supervise-gre <id>, supervise-greplus <id>, health-check-all, haproxy-udp-sync, or haproxy-udp-repair." >&2
      exit 1
      ;;
  esac
fi

ensure_root
bootstrap_runtime_repairs >/dev/null 2>&1 || true
while true; do
  show_menu
done
