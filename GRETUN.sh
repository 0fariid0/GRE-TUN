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

APP_VERSION="12.6.5"

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
  return 0 # Automatic monitoring and repair removed.
}

# GRE uses a persistent supervisor instead of a oneshot service. A oneshot unit
# can remain "active" after the kernel interface has disappeared, which prevents
# systemd from repairing it. The supervisor verifies both interface presence and
# inner reachability, then recreates only this GRE and restarts dependent WG.
gre_supervisor() {
  gre_service_start "${1:-}"
}

gre_write_service_template() {
  cat > "$GRE_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=Normal GRE Tunnel %i Boot Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $INSTALL_BIN --service supervise-gre %i
Restart=no
TimeoutStopSec=10
LimitNOFILE=262144
StandardOutput=append:$DIAG_SERVICE_LOG
StandardError=append:$DIAG_SERVICE_LOG

[Install]
WantedBy=multi-user.target
EOF_SERVICE
}

tunnel_health_check_all() {
  return 0 # Automatic monitoring and repair removed.
}

bootstrap_runtime_repairs() {
  return 0 # Automatic monitoring and repair removed.
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
Description=GRE Plus Tunnel %i High-Capacity Boot Service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $INSTALL_BIN --service supervise-greplus %i
Restart=no
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
  greplus_load_config "${1:-}" || return 1
  greplus_create_tunnel 0
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
  # Remaining tunnels are not automatically repaired.
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

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable "$HAPROXY_UDP_SERVICE_NAME" >/dev/null 2>&1 || true
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
  return 0 # Automatic monitoring and repair removed.
}

# Non-interactive hourly service wrapper. This intentionally force-runs the
# exact same repair as menu option 8 even if the rules still look present.
haproxy_periodic_udp_repair() {
  return 0 # Automatic monitoring and repair removed.
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

TRANSPARENT_SHA256="925f9e83e3da7be7891e62e1c080db49688e8706aef0580961fcc1bc97529ba4"
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
  echo -e "  ${C_CYAN}9)${C_RESET} transparent client IP ${C_DIM}(ON / OFF)${C_RESET}"
  echo -e "  ${C_DIM}00) Main menu / back${C_RESET}"
  echo -e "  ${C_DIM}0) Exit${C_RESET}"
  echo
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

disable_legacy_automation() {
  command -v systemctl >/dev/null 2>&1 || return 0
  local unit
  for unit in gretun-health.timer gretun-health.service gretun-haproxy-udp-repair.timer gretun-haproxy-udp-repair.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$unit"
  done
  # Stop old polling processes without deleting live interfaces. New boot units
  # create tunnels once; they never poll, repair, or restart them in the background.
  if grep -q '^Type=simple$' "$GRE_SERVICE_TEMPLATE" 2>/dev/null; then
    systemctl stop 'gre-tunnel@*.service' >/dev/null 2>&1 || true
    gre_write_service_template || return 1
  fi
  if grep -q '^Type=simple$' "$GREPLUS_SERVICE_TEMPLATE" 2>/dev/null; then
    systemctl stop 'greplus-tunnel@*.service' >/dev/null 2>&1 || true
    greplus_write_service_template || return 1
  fi
  systemctl daemon-reload || return 1
}

### Script entry
if [[ "${1:-}" == "--version" ]]; then printf "%s\n" "$APP_VERSION"; exit 0; fi
if [[ "${1:-}" == "--install" ]]; then ensure_root; install_manager_binary && disable_legacy_automation; exit $?; fi
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
disable_legacy_automation || { err_msg "Could not disable old automation"; exit 1; }
while true; do
  show_menu
done
