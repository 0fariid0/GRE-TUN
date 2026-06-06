#!/bin/bash
set -euo pipefail

# GRE + WireGuard + FOU-GRE multi-tunnel manager v9
# - Normal GRE tunnels keep the old/current behavior and naming: greN + 10.10.N.x
# - WireGuard tunnels use separate names/ranges/files: wgtunN + 10.20.N.x
# - FOU-GRE tunnels use separate names/ranges/files: fougreN + 10.30.N.x
# - FOU-GRE wraps GRE inside UDP, useful when raw GRE protocol 47 is filtered/throttled/lossy
# - WireGuard can use public UDP or automatically ride over an existing GRE tunnel as transport
# - Local tunnel/bind IPv4 can be selected manually for servers with multiple IPs
# - v9 detects missing ip-fou support early and falls back to WireGuard UDP rescue mode
# - v9 also applies UDP port conflict checks to WireGuard, not only FOU-GRE

GRE_CONFIG_DIR="/etc/gre-tunnels"
GRE_LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gretun-manager.sh"
GRE_SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
GRE_LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"

WG_META_DIR="/etc/wgtun-tunnels"
WG_KEY_DIR="$WG_META_DIR/keys"
WG_CONFIG_DIR="/etc/wireguard"
WG_IFACE_PREFIX="wgtun"

FOUGRE_CONFIG_DIR="/etc/fougre-tunnels"
FOUGRE_SERVICE_TEMPLATE="/etc/systemd/system/fougre-tunnel@.service"
FOUGRE_IFACE_PREFIX="fougre"

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
    read -rp "$prompt_label [$default_ip]: " input
    input="${input:-$default_ip}"
  else
    read -rp "$prompt_label: " input
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
    read -rp "Enter REMOTE server Public IPv4 [$default_ip]: " input
    REMOTE_PUBLIC_IP="${input:-$default_ip}"
  else
    read -rp "Enter REMOTE server Public IPv4: " REMOTE_PUBLIC_IP
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
  echo "=============================================="
  echo " $title"
  echo " Local server public IP: ${ip_addr:-UNKNOWN}"
  echo "=============================================="
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

prompt_tunnel_id() {
  local prompt="${1:-Enter tunnel number [1-254]: }"
  read -rp "$prompt" TUNNEL_ID
  if ! validate_tunnel_id "$TUNNEL_ID"; then
    echo "Invalid tunnel number. Use a number from 1 to 254."
    return 1
  fi
}

prompt_role() {
  echo "1) Iran / local-side role"
  echo "2) Kharej / remote-side role"
  echo
  read -rp "Select server role [1-2]: " ROLE
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "Invalid selection"
    return 1
  fi
}

ask_tunnel_type() {
  echo "Select tunnel type:"
  echo "1) Normal GRE tunnel"
  echo "2) WireGuard tunnel"
  echo "3) FOU-GRE over UDP tunnel"
  echo
  read -rp "Choose [1-3]: " TUNNEL_TYPE_CHOICE
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE="gre" ;;
    2) SELECTED_TUNNEL_TYPE="wireguard" ;;
    3) SELECTED_TUNNEL_TYPE="fougre" ;;
    *) echo "Invalid tunnel type"; return 1 ;;
  esac
}

confirm_yes() {
  local prompt="$1"
  local answer
  read -rp "$prompt [y/N]: " answer
  case "$answer" in
    [Yy]*) return 0 ;;
    *) return 1 ;;
  esac
}

confirm_default_yes() {
  local prompt="$1"
  local answer
  read -rp "$prompt [Y/n]: " answer
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

validate_udp_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

read_simple_config_value() {
  local file="$1"
  local key="$2"
  [ -f "$file" ] || return 1
  awk -F= -v k="$key" '$1 == k {print $2; exit}' "$file" | tr -d "'\""
}

udp_port_socket_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "(^|:|\])$port$" && return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -lun 2>/dev/null | awk 'NR>2{print $4}' | grep -Eq "(^|:|\])$port$" && return 0
  fi
  return 1
}

udp_fou_port_registered() {
  local port="$1"
  command -v ip >/dev/null 2>&1 || return 1
  ip fou show 2>/dev/null | grep -Eq "(^|[[:space:]])port[[:space:]]+$port([[:space:]]|$)"
}

udp_port_reserved_by_tunnel_configs() {
  local port="$1"
  local skip_file="${2:-}"
  local f key value
  for f in "$WG_META_DIR"/tunnel-*.conf "$FOUGRE_CONFIG_DIR"/tunnel-*.conf; do
    [ -f "$f" ] || continue
    [ -n "$skip_file" ] && [ "$f" = "$skip_file" ] && continue
    for key in LOCAL_WG_PORT REMOTE_WG_PORT LOCAL_FOUGRE_PORT REMOTE_FOUGRE_PORT; do
      value="$(read_simple_config_value "$f" "$key" 2>/dev/null || true)"
      [ "$value" = "$port" ] && return 0
    done
  done
  return 1
}

fougre_saved_uses_local_port() {
  local id="$1"
  local port="$2"
  local file value
  file="$FOUGRE_CONFIG_DIR/tunnel-$id.conf"
  value="$(read_simple_config_value "$file" LOCAL_FOUGRE_PORT 2>/dev/null || true)"
  [ "$value" = "$port" ]
}

udp_port_available_for_fougre() {
  local port="$1"
  local id="${2:-}"
  local skip_file=""
  validate_udp_port "$port" || return 1
  [ -n "$id" ] && skip_file="$FOUGRE_CONFIG_DIR/tunnel-$id.conf"

  if udp_port_socket_in_use "$port"; then
    # ss/netstat may also show kernel FOU receive ports. Allow the current
    # same-number FOU-GRE tunnel to reuse its own port during update/repair.
    if ! { [ -n "$id" ] && fougre_saved_uses_local_port "$id" "$port" && udp_fou_port_registered "$port"; }; then
      return 1
    fi
  fi

  if udp_fou_port_registered "$port"; then
    if ! { [ -n "$id" ] && fougre_saved_uses_local_port "$id" "$port"; }; then
      return 1
    fi
  fi

  if udp_port_reserved_by_tunnel_configs "$port" "$skip_file"; then
    return 1
  fi

  return 0
}

find_free_udp_port_for_fougre() {
  local start="$1"
  local id="${2:-}"
  local port
  validate_udp_port "$start" || start=53001
  port="$start"
  while [ "$port" -le 65535 ]; do
    if udp_port_available_for_fougre "$port" "$id"; then
      echo "$port"
      return 0
    fi
    port=$((port + 1))
  done
  return 1
}

prompt_local_udp_port_for_fougre() {
  local default_port="$1"
  local id="$2"
  local input chosen
  read -rp "Enter LOCAL FOU-GRE UDP receive port [$default_port, auto-safe]: " input
  if [ -z "$input" ]; then
    chosen="$(find_free_udp_port_for_fougre "$default_port" "$id")" || {
      echo "Could not find a free UDP port for FOU-GRE." >&2
      return 1
    }
    if [ "$chosen" != "$default_port" ]; then
      echo "Default UDP port $default_port is busy/reserved; selected free port $chosen instead."
    fi
    LOCAL_FOUGRE_PORT="$chosen"
    return 0
  fi

  if ! validate_udp_port "$input"; then
    echo "Invalid UDP port: $input"
    return 1
  fi
  if ! udp_port_available_for_fougre "$input" "$id"; then
    echo "UDP port $input is already in use or reserved by another tunnel/service. Choose another port."
    return 1
  fi
  LOCAL_FOUGRE_PORT="$input"
}

prompt_remote_udp_port() {
  local default_port="$1"
  local label="${2:-REMOTE UDP port}"
  local input
  read -rp "$label [$default_port]: " input
  input="${input:-$default_port}"
  if ! validate_udp_port "$input"; then
    echo "Invalid UDP port: $input"
    return 1
  fi
  REMOTE_FOUGRE_PORT="$input"
}


wg_saved_uses_local_port() {
  local id="$1"
  local port="$2"
  local file value
  file="$WG_META_DIR/tunnel-$id.conf"
  value="$(read_simple_config_value "$file" LOCAL_WG_PORT 2>/dev/null || true)"
  [ "$value" = "$port" ]
}

udp_port_available_for_wireguard() {
  local port="$1"
  local id="${2:-}"
  local skip_file=""
  validate_udp_port "$port" || return 1
  [ -n "$id" ] && skip_file="$WG_META_DIR/tunnel-$id.conf"

  # During update/repair the current wg interface may already be listening on
  # its saved port. Allow that same tunnel to reuse its own port, but do not
  # allow any other socket/config to collide with it.
  if udp_port_socket_in_use "$port"; then
    if ! { [ -n "$id" ] && wg_saved_uses_local_port "$id" "$port"; }; then
      return 1
    fi
  fi

  if udp_port_reserved_by_tunnel_configs "$port" "$skip_file"; then
    return 1
  fi

  return 0
}

find_free_udp_port_for_wireguard() {
  local start="$1"
  local id="${2:-}"
  local port
  validate_udp_port "$start" || start=51801
  port="$start"
  while [ "$port" -le 65535 ]; do
    if udp_port_available_for_wireguard "$port" "$id"; then
      echo "$port"
      return 0
    fi
    port=$((port + 1))
  done
  return 1
}

prompt_local_udp_port_for_wireguard() {
  local default_port="$1"
  local id="$2"
  local input chosen
  read -rp "Enter LOCAL WireGuard UDP ListenPort [$default_port, auto-safe]: " input
  if [ -z "$input" ]; then
    chosen="$(find_free_udp_port_for_wireguard "$default_port" "$id")" || {
      echo "Could not find a free UDP port for WireGuard." >&2
      return 1
    }
    if [ "$chosen" != "$default_port" ]; then
      echo "Default WireGuard UDP port $default_port is busy/reserved; selected free port $chosen instead."
    fi
    LOCAL_WG_PORT="$chosen"
    return 0
  fi

  if ! validate_udp_port "$input"; then
    echo "Invalid UDP port: $input"
    return 1
  fi
  if ! udp_port_available_for_wireguard "$input" "$id"; then
    echo "UDP port $input is already in use or reserved by another tunnel/service. Choose another port."
    return 1
  fi
  LOCAL_WG_PORT="$input"
}

prompt_remote_udp_port_for_wireguard() {
  local default_port="$1"
  local input
  read -rp "Enter REMOTE server WireGuard UDP ListenPort [$default_port]: " input
  input="${input:-$default_port}"
  if ! validate_udp_port "$input"; then
    echo "Invalid UDP port: $input"
    return 1
  fi
  REMOTE_WG_PORT="$input"
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

gre_default_key() {
  # Keep the old behavior by default: tunnel N uses GRE key N.
  # The important v7 fix is that this key is reset per tunnel so a previous
  # tunnel key cannot leak into the next tunnel created in the same session.
  echo "$1"
}

gre_reset_runtime_vars() {
  # Prevent values sourced/entered for one GRE tunnel from leaking into the next one.
  unset TUN_IFACE TUN_KEY SERVER_ROLE LOCAL_GRE_IP REMOTE_GRE_IP
  unset LOCAL_PUBLIC_IP REMOTE_PUBLIC_IP
}

gre_print_ip_plan() {
  local id="$1"
  echo "Normal GRE tunnel $id plan:"
  echo "  Interface       : gre$id"
  echo "  Config file     : $GRE_CONFIG_DIR/tunnel-$id.conf"
  echo "  Service         : gre-tunnel@$id.service"
  echo "  GRE key         : $(gre_default_key "$id")"
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

  local file
  file="$(gre_config_file "$id")"
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    TUN_IFACE="${TUN_IFACE:-$(gre_iface "$id")}"
    TUN_KEY="${TUN_KEY:-$id}"
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

gre_disable_rp_filter() {
  local ifc="${1:-}"
  # Reverse-path filtering often breaks multi-GRE setups on providers that use
  # policy routing, multiple public IPs, or asymmetric return paths.
  for rp in /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/default/rp_filter "/proc/sys/net/ipv4/conf/$ifc/rp_filter"; do
    [ -e "$rp" ] && echo 0 > "$rp" 2>/dev/null || true
  done

  mkdir -p /etc/sysctl.d 2>/dev/null || true
  cat > /etc/sysctl.d/99-gretun-multitunnel.conf <<EOF_SYSCTL
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
  sysctl -q -p /etc/sysctl.d/99-gretun-multitunnel.conf >/dev/null 2>&1 || true
}

gre_apply_firewall_rules() {
  local id="$1"
  local ifc remote local_ip subnet
  ifc="$(gre_iface "$id")"
  remote="${REMOTE_PUBLIC_IP:-}"
  local_ip="${LOCAL_PUBLIC_IP:-}"
  subnet="10.10.$id.0/24"

  gre_disable_rp_filter "$ifc"

  if command -v iptables >/dev/null 2>&1; then
    # Insert at the TOP, not append. This beats broad DROP rules such as
    # '-A FORWARD -s 10.0.0.0/8 -j DROP' and UFW user DROP rules.
    iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$ifc" -j ACCEPT || true
    iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o "$ifc" -j ACCEPT || true
    iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$ifc" -j ACCEPT || true
    iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$ifc" -j ACCEPT || true

    iptables -C INPUT -s "$subnet" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s "$subnet" -j ACCEPT || true
    iptables -C OUTPUT -d "$subnet" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -d "$subnet" -j ACCEPT || true
    iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "$subnet" -j ACCEPT || true
    iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "$subnet" -j ACCEPT || true

    if [ -n "$remote" ]; then
      if [ -n "$local_ip" ]; then
        iptables -C INPUT -p gre -s "$remote" -d "$local_ip" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p gre -s "$remote" -d "$local_ip" -j ACCEPT || true
        iptables -C OUTPUT -p gre -s "$local_ip" -d "$remote" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p gre -s "$local_ip" -d "$remote" -j ACCEPT || true
      fi
      iptables -C INPUT -p gre -s "$remote" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p gre -s "$remote" -j ACCEPT || true
      iptables -C OUTPUT -p gre -d "$remote" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p gre -d "$remote" -j ACCEPT || true
    else
      iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p gre -j ACCEPT || true
      iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p gre -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow in on "$ifc" >/dev/null 2>&1 || true
    ufw allow out on "$ifc" >/dev/null 2>&1 || true
    ufw route allow in on "$ifc" >/dev/null 2>&1 || true
    ufw route allow out on "$ifc" >/dev/null 2>&1 || true
    ufw allow out to "$subnet" >/dev/null 2>&1 || true
    ufw allow in from "$subnet" >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-interface="$ifc" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

gre_remove_firewall_rules() {
  local id="$1"
  local ifc subnet
  ifc="$(gre_iface "$id")"
  subnet="10.10.$id.0/24"

  if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$ifc" -j ACCEPT || break; done
    while iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -o "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
    while iptables -C INPUT -s "$subnet" -j ACCEPT 2>/dev/null; do iptables -D INPUT -s "$subnet" -j ACCEPT || break; done
    while iptables -C OUTPUT -d "$subnet" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -d "$subnet" -j ACCEPT || break; done
    while iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -s "$subnet" -j ACCEPT || break; done
    while iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -d "$subnet" -j ACCEPT || break; done
  fi
}

gre_create_tunnel() {
  local interactive=${1:-0}

  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Invalid tunnel number. Use 1 to 254." >&2
    return 1
  fi

  TUN_IFACE="$(gre_iface "$TUNNEL_ID")"
  TUN_KEY="${TUN_KEY:-$(gre_default_key "$TUNNEL_ID")}"

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

  modprobe ip_gre || true

  # Remove only this GRE interface so other GRE/WireGuard tunnels stay intact.
  ip link set "$TUN_IFACE" down 2>/dev/null || true
  ip tunnel del "$TUN_IFACE" 2>/dev/null || true

  ip tunnel add "$TUN_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$TUN_KEY" ttl 255
  ip addr add "$LOCAL_GRE_IP" dev "$TUN_IFACE"
  ip link set "$TUN_IFACE" mtu 1390
  ip link set "$TUN_IFACE" up

  if ! ip link show "$TUN_IFACE" >/dev/null 2>&1; then
    echo "GRE interface creation failed" >&2
    return 1
  fi

  enable_ip_forward
  gre_apply_firewall_rules "$TUNNEL_ID"

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
  gre_reset_runtime_vars
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_key
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter GRE tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  existing_key=""
  if gre_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_key="${TUN_KEY:-}"
  fi
  ROLE="$selected_role"
  TUN_KEY="${existing_key:-$(gre_default_key "$TUNNEL_ID")}"

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
  read -rp "Enter GRE tunnel number to check, or leave empty to check all listed GRE tunnels: " selected_id

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

  gre_remove_firewall_rules "$id"

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
  read -rp "Enter GRE tunnel number to remove, for example 1: " selected_id
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

gre_restart_one_tunnel() {
  local id="$1"
  local ifc svc
  if ! validate_tunnel_id "$id"; then
    echo "Invalid GRE tunnel number." >&2
    return 1
  fi
  ifc="$(gre_iface "$id")"
  svc="$(gre_service_name "$id")"

  if ! gre_load_config "$id"; then
    echo "No saved GRE configuration found for tunnel $id." >&2
    return 1
  fi

  echo "Restarting GRE tunnel $id ($ifc) without touching other tunnels..."
  enable_ip_forward
  gre_disable_rp_filter "$ifc"

  if command -v systemctl >/dev/null 2>&1 && [ -f "$GRE_SERVICE_TEMPLATE" ]; then
    systemctl daemon-reload || true
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if ! systemctl restart "$svc"; then
        echo "Systemd restart failed; trying direct start from saved config..." >&2
        gre_create_tunnel 0
      fi
    else
      gre_create_tunnel 0
    fi
  else
    gre_create_tunnel 0
  fi

  gre_apply_firewall_rules "$id"
  echo "[OK] Repaired/restarted $ifc"
  gre_check_one_tunnel "$id"
}

gre_repair_menu() {
  show_header "Normal GRE Repair / Restart"
  gre_list_tunnels
  echo
  local ids selected_id
  ids="$(gre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No GRE tunnels found."
    return
  fi
  read -rp "Enter GRE tunnel number to repair/restart, for example 1: " selected_id
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "GRE tunnel $selected_id was not found in the list."
    return
  fi
  gre_restart_one_tunnel "$selected_id"
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
  systemctl enable "$(gre_service_name "$id")"
  echo "GRE service installed and enabled for boot ($(gre_service_name "$id"))"
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
  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
    printf '%s' "${WG_ENDPOINT_IP:-}"
  else
    wg_default_public_endpoint_ip
  fi
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
  echo "  Default UDP port: $port"
  echo "  Iran role IP    : 10.20.$id.1/30"
  echo "  Kharej role IP  : 10.20.$id.2/30"
  echo "  GRE fallback    : if gre$id is already up, WireGuard will auto-use 10.10.$id.x as its endpoint"
  echo
  echo "GRE uses 10.10.N.x and greN. WireGuard uses 10.20.N.x and wgtunN, so they do not conflict."
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
  if [ "$endpoint_mode_note" = "gre" ]; then
    mtu_value="${WG_MTU:-1280}"
  fi
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
    if [ "$WG_ENDPOINT_MODE" = "gre" ]; then
      WG_MTU="1280"
    else
      WG_MTU="1420"
    fi
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
    read -rp "REMOTE WireGuard public key: " REMOTE_WG_PUBLIC_KEY
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
  local gre_ifc gre_remote_ip gre_remote_ok
  gre_ifc="$(wg_transport_iface "$id")"
  gre_remote_ip="$(gre_remote_inner_ip_for_role "$id" "$role")"

  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="${REMOTE_PUBLIC_IP:-}"
  WG_TRANSPORT_IFACE=""

  # If a same-number GRE tunnel is already up and its inner IP replies, use it as WireGuard transport.
  # This is useful when public UDP/WireGuard is blocked but GRE is reachable.
  if ip link show "$gre_ifc" >/dev/null 2>&1; then
    gre_remote_ok=0
    if ping -c 1 -W 1 "$gre_remote_ip" >/dev/null 2>&1; then
      gre_remote_ok=1
    fi
    if [ "$gre_remote_ok" -eq 1 ]; then
      WG_ENDPOINT_MODE="gre"
      WG_ENDPOINT_IP="$gre_remote_ip"
      WG_TRANSPORT_IFACE="$gre_ifc"
      return 0
    fi
  fi

  # If a previous WireGuard config used GRE transport, keep that choice when the GRE interface still exists.
  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ] && ip link show "$gre_ifc" >/dev/null 2>&1; then
    WG_ENDPOINT_IP="$gre_remote_ip"
    WG_TRANSPORT_IFACE="$gre_ifc"
  fi
}

wg_menu_config_tunnel() {
  show_header "Configure WireGuard Tunnel"
  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_peer_key existing_local_port existing_remote_port remote_ip_input
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter WireGuard tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  existing_peer_key=""
  existing_local_port=""
  existing_remote_port=""
  local previous_endpoint_mode previous_endpoint_ip previous_transport_iface gre_saved_remote
  previous_endpoint_mode=""
  previous_endpoint_ip=""
  previous_transport_iface=""
  gre_saved_remote=""
  if wg_load_meta "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_peer_key="${REMOTE_WG_PUBLIC_KEY:-}"
    existing_local_port="${LOCAL_WG_PORT:-}"
    existing_remote_port="${REMOTE_WG_PORT:-}"
    previous_endpoint_mode="${WG_ENDPOINT_MODE:-}"
    previous_endpoint_ip="${WG_ENDPOINT_IP:-}"
    previous_transport_iface="${WG_TRANSPORT_IFACE:-}"
  fi
  ROLE="$selected_role"
  REMOTE_WG_PUBLIC_KEY="$existing_peer_key"

  # Try to reuse the remote public IP saved by the same-number GRE tunnel.
  # Run this in a subshell so GRE variables do not overwrite the selected WireGuard role.
  gre_saved_remote="$(bash -c 'set -e; f="'"$GRE_CONFIG_DIR"'/tunnel-'"$TUNNEL_ID"'.conf"; [ -f "$f" ] && . "$f" && printf "%s" "${REMOTE_PUBLIC_IP:-}"' 2>/dev/null || true)"
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

  # Tunnel N defaults to UDP 51800+N, but v9 checks for conflicts before saving.
  # If the default port is busy, the local ListenPort is moved to the next free UDP port.
  prompt_local_udp_port_for_wireguard "${existing_local_port:-$(wg_default_port "$TUNNEL_ID")}" "$TUNNEL_ID" || return
  prompt_remote_udp_port_for_wireguard "${existing_remote_port:-$LOCAL_WG_PORT}" || return
  EXTRA_ALLOWED_IPS=""

  REMOTE_PUBLIC_IP="$existing_remote_ip"
  WG_ENDPOINT_MODE="$previous_endpoint_mode"
  WG_ENDPOINT_IP="$previous_endpoint_ip"
  WG_TRANSPORT_IFACE="$previous_transport_iface"
  wg_choose_auto_endpoint "$TUNNEL_ID" "$ROLE"

  if [ "${WG_ENDPOINT_MODE:-public}" != "gre" ]; then
    prompt_remote_public_ip "$existing_remote_ip" || return
    WG_ENDPOINT_MODE="public"
    WG_ENDPOINT_IP="$REMOTE_PUBLIC_IP"
    WG_TRANSPORT_IFACE=""
  else
    echo "Same-number GRE tunnel is active and reachable."
    echo "WireGuard will automatically use GRE as transport to avoid public UDP/WireGuard blocking."
    echo "No remote public IP is needed for the WireGuard endpoint in this mode."
    # Keep the public IP in metadata if it was previously known, but do not require it for the endpoint.
    REMOTE_PUBLIC_IP="${REMOTE_PUBLIC_IP:-$existing_remote_ip}"
  fi

  if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
    WG_MTU="1280"
  else
    WG_MTU="1420"
  fi

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
    read -rp "REMOTE WireGuard public key [keep/CLEAR/new]: " peer_key_input
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
    if [ "${WG_ENDPOINT_MODE:-public}" = "gre" ]; then
      echo "Transport interface : ${WG_TRANSPORT_IFACE:-gre$id}"
    fi
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
            echo "Diagnosis: no WireGuard handshake yet. WireGuard is using GRE transport. Check that GRE tunnel $id still pings, the peer public key is correct, and UDP $(wg_default_port "$id") is allowed over gre$id on both servers."
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
  read -rp "Enter WireGuard tunnel number to check, or leave empty to check all listed WireGuard tunnels: " selected_id

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
  systemctl daemon-reload

  # Avoid the previous bug: if wg-quick already created the interface, systemd start fails.
  # Bring only this WireGuard interface down first, then let systemd own it.
  wg-quick down "$ifc" >/dev/null 2>&1 || true
  ip link delete "$ifc" 2>/dev/null || true

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
    wg-quick down "$ifc" >/dev/null 2>&1 || true
    ip link delete "$ifc" 2>/dev/null || true
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
  read -rp "Enter WireGuard tunnel number to repair/restart, for example 1: " selected_id
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

  if command -v wg-quick >/dev/null 2>&1; then
    wg-quick down "$ifc" >/dev/null 2>&1 || true
  fi
  ip link delete "$ifc" 2>/dev/null || true
  wg_remove_firewall_rules "$id"

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
  read -rp "Enter WireGuard tunnel number to remove, for example 1: " selected_id
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
# FOU-GRE over UDP helpers
# -----------------------------
fougre_iface() {
  echo "${FOUGRE_IFACE_PREFIX}$1"
}

fougre_config_file() {
  echo "$FOUGRE_CONFIG_DIR/tunnel-$1.conf"
}

fougre_service_name() {
  echo "fougre-tunnel@$1.service"
}

fougre_default_key() {
  echo "$1"
}

fougre_default_port() {
  local id="$1"
  echo $((53000 + id))
}

fougre_print_ip_plan() {
  local id="$1"
  echo "FOU-GRE over UDP tunnel $id plan:"
  echo "  Interface        : $(fougre_iface "$id")"
  echo "  Config file      : $FOUGRE_CONFIG_DIR/tunnel-$id.conf"
  echo "  Service          : $(fougre_service_name "$id")"
  echo "  GRE key          : $(fougre_default_key "$id")"
  echo "  Default UDP port : $(fougre_default_port "$id")"
  echo "  Iran role IP     : 10.30.$id.1/30"
  echo "  Kharej role IP   : 10.30.$id.2/30"
  echo
  echo "Normal GRE uses greN + 10.10.N.x, WireGuard uses wgtunN + 10.20.N.x."
  echo "FOU-GRE uses fougreN + 10.30.N.x, so it stays isolated from the other types."
}

fougre_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.30.$id.1"
  else
    echo "10.30.$id.2"
  fi
}

fougre_remote_inner_ip_for_role() {
  local id="$1"
  local role="$2"
  if [ "$role" = "1" ]; then
    echo "10.30.$id.2"
  else
    echo "10.30.$id.1"
  fi
}

fougre_supported() {
  command -v ip >/dev/null 2>&1 || return 1
  ip fou help 2>&1 | grep -qi "Usage:" || return 1
  # Try to load the kernel modules, but do not fail only because modprobe is
  # unavailable or the modules are built into the kernel.
  modprobe fou >/dev/null 2>&1 || true
  modprobe ip_gre >/dev/null 2>&1 || true
  ip fou show >/dev/null 2>&1 || return 1
  return 0
}

fougre_print_unsupported_message() {
  echo "FOU-GRE is not available on this server."
  echo "Reason: this kernel/iproute2 does not support 'ip fou' in the current environment."
  echo "Safe fallback: use WireGuard over UDP with separate wgtunN + 10.20.N.x, so it will not conflict with greN or fougreN."
}

fougre_ensure_tools() {
  if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required but 'ip' was not found." >&2
    return 1
  fi
  if ! fougre_supported; then
    fougre_print_unsupported_message >&2
    return 1
  fi
}

fougre_offer_wireguard_fallback_from_current() {
  local interactive="${1:-1}"
  local default_wg_port chosen
  [ "$interactive" -eq 1 ] || return 1

  echo
  fougre_print_unsupported_message
  echo
  if ! confirm_default_yes "Create a WireGuard UDP fallback tunnel with the same tunnel number now?"; then
    echo "Cancelled. No tunnel was changed."
    return 1
  fi

  default_wg_port="$(wg_default_port "$TUNNEL_ID")"
  chosen="$(find_free_udp_port_for_wireguard "$default_wg_port" "$TUNNEL_ID")" || {
    echo "Could not find a free WireGuard UDP port for fallback." >&2
    return 1
  }
  LOCAL_WG_PORT="$chosen"
  if [ "$chosen" != "$default_wg_port" ]; then
    echo "Default WireGuard UDP port $default_wg_port is busy/reserved; selected free port $chosen instead."
  fi
  prompt_remote_udp_port_for_wireguard "$LOCAL_WG_PORT" || return 1

  WG_ENDPOINT_MODE="public"
  WG_ENDPOINT_IP="$REMOTE_PUBLIC_IP"
  WG_TRANSPORT_IFACE=""
  WG_MTU="1420"
  EXTRA_ALLOWED_IPS=""
  REMOTE_WG_PUBLIC_KEY=""

  echo
  echo "Starting WireGuard fallback using:"
  echo "  Interface              : $(wg_iface_name "$TUNNEL_ID")"
  echo "  Inner IP range         : 10.20.$TUNNEL_ID.0/30"
  echo "  Local UDP ListenPort   : $LOCAL_WG_PORT"
  echo "  Remote UDP ListenPort  : $REMOTE_WG_PORT"
  echo "  Endpoint IP            : $REMOTE_PUBLIC_IP"
  echo
  wg_create_tunnel 1
}

fougre_save_config() {
  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Cannot save FOU-GRE config: invalid tunnel number" >&2
    return 1
  fi

  mkdir -p "$FOUGRE_CONFIG_DIR"
  local file
  file="$(fougre_config_file "$TUNNEL_ID")"

  {
    write_var TUNNEL_TYPE "fougre"
    write_var TUNNEL_ID "$TUNNEL_ID"
    write_var FOUGRE_IFACE "$FOUGRE_IFACE"
    write_var FOUGRE_KEY "$FOUGRE_KEY"
    write_var ROLE "$ROLE"
    write_var SERVER_ROLE "${SERVER_ROLE:-}"
    write_var LOCAL_PUBLIC_IP "$LOCAL_PUBLIC_IP"
    write_var REMOTE_PUBLIC_IP "$REMOTE_PUBLIC_IP"
    write_var LOCAL_FOUGRE_IP "$LOCAL_FOUGRE_IP"
    write_var REMOTE_FOUGRE_IP "$REMOTE_FOUGRE_IP"
    write_var LOCAL_FOUGRE_PORT "$LOCAL_FOUGRE_PORT"
    write_var REMOTE_FOUGRE_PORT "$REMOTE_FOUGRE_PORT"
    write_var FOUGRE_MTU "${FOUGRE_MTU:-1360}"
  } > "$file"
  chmod 600 "$file"
  echo "Saved FOU-GRE tunnel $TUNNEL_ID configuration to $file"
}

fougre_load_config() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    return 1
  fi
  local file
  file="$(fougre_config_file "$id")"
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    FOUGRE_IFACE="${FOUGRE_IFACE:-$(fougre_iface "$id")}"
    FOUGRE_KEY="${FOUGRE_KEY:-$id}"
    LOCAL_FOUGRE_PORT="${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$id")}"
    REMOTE_FOUGRE_PORT="${REMOTE_FOUGRE_PORT:-$LOCAL_FOUGRE_PORT}"
    FOUGRE_MTU="${FOUGRE_MTU:-1360}"
    return 0
  fi
  return 1
}

fougre_collect_ids() {
  {
    if [ -d "$FOUGRE_CONFIG_DIR" ]; then
      local f id
      for f in "$FOUGRE_CONFIG_DIR"/tunnel-*.conf; do
        [ -e "$f" ] || continue
        id="${f##*/tunnel-}"
        id="${id%.conf}"
        validate_tunnel_id "$id" && echo "$id"
      done
    fi
    ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E "^${FOUGRE_IFACE_PREFIX}[0-9]+$" | sed "s/^${FOUGRE_IFACE_PREFIX}//" || true
  } | sort -n -u
}

fougre_list_tunnels() {
  echo "FOU-GRE over UDP tunnels:"
  local ids id ifc file service_state remote local_port remote_port link_state
  ids="$(fougre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "  none"
    return 0
  fi

  while IFS= read -r id; do
    [ -n "$id" ] || continue
    ifc="$(fougre_iface "$id")"
    file="$(fougre_config_file "$id")"
    service_state="not-installed"
    remote="unknown"
    local_port="$(fougre_default_port "$id")"
    remote_port="$local_port"

    if fougre_load_config "$id"; then
      remote="${REMOTE_PUBLIC_IP:-unknown}"
      local_port="${LOCAL_FOUGRE_PORT:-$local_port}"
      remote_port="${REMOTE_FOUGRE_PORT:-$remote_port}"
    fi

    if command -v systemctl >/dev/null 2>&1; then
      if [ -f "$FOUGRE_SERVICE_TEMPLATE" ]; then
        service_state="template-installed"
      fi
      if systemctl is-enabled --quiet "$(fougre_service_name "$id")" 2>/dev/null; then
        service_state="enabled"
      fi
      if systemctl is-active --quiet "$(fougre_service_name "$id")" 2>/dev/null; then
        service_state="active"
      fi
    fi

    if ip link show "$ifc" >/dev/null 2>&1; then
      link_state="active"
    else
      link_state="inactive"
    fi
    echo "  - tunnel $id | iface $ifc | $link_state | UDP local/remote: $local_port/$remote_port | remote public: $remote | config: $file | service: $service_state"
  done <<< "$ids"
}

fougre_disable_rp_filter() {
  local ifc="${1:-}"
  for rp in /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/default/rp_filter "/proc/sys/net/ipv4/conf/$ifc/rp_filter"; do
    [ -e "$rp" ] && echo 0 > "$rp" 2>/dev/null || true
  done

  mkdir -p /etc/sysctl.d 2>/dev/null || true
  cat > /etc/sysctl.d/99-fougre-multitunnel.conf <<EOF_SYSCTL
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
EOF_SYSCTL
  sysctl -q -p /etc/sysctl.d/99-fougre-multitunnel.conf >/dev/null 2>&1 || true
}

fougre_apply_firewall_rules() {
  local id="$1"
  local ifc remote local_ip local_port remote_port subnet
  ifc="$(fougre_iface "$id")"
  remote="${REMOTE_PUBLIC_IP:-}"
  local_ip="${LOCAL_PUBLIC_IP:-}"
  local_port="${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$id")}"
  remote_port="${REMOTE_FOUGRE_PORT:-$local_port}"
  subnet="10.30.$id.0/24"

  fougre_disable_rp_filter "$ifc"

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -i "$ifc" -j ACCEPT || true
    iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -o "$ifc" -j ACCEPT || true
    iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i "$ifc" -j ACCEPT || true
    iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -o "$ifc" -j ACCEPT || true

    iptables -C INPUT -s "$subnet" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s "$subnet" -j ACCEPT || true
    iptables -C OUTPUT -d "$subnet" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -d "$subnet" -j ACCEPT || true
    iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "$subnet" -j ACCEPT || true
    iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "$subnet" -j ACCEPT || true

    if [ -n "$remote" ]; then
      if [ -n "$local_ip" ]; then
        iptables -C INPUT -p udp -s "$remote" -d "$local_ip" --dport "$local_port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp -s "$remote" -d "$local_ip" --dport "$local_port" -j ACCEPT || true
        iptables -C OUTPUT -p udp -s "$local_ip" -d "$remote" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p udp -s "$local_ip" -d "$remote" --dport "$remote_port" -j ACCEPT || true
      fi
      iptables -C INPUT -p udp -s "$remote" --dport "$local_port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp -s "$remote" --dport "$local_port" -j ACCEPT || true
      iptables -C OUTPUT -p udp -d "$remote" --dport "$remote_port" -j ACCEPT 2>/dev/null || iptables -I OUTPUT 1 -p udp -d "$remote" --dport "$remote_port" -j ACCEPT || true
    else
      iptables -C INPUT -p udp --dport "$local_port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "$local_port" -j ACCEPT || true
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw allow "$local_port/udp" comment "fougre$id" >/dev/null 2>&1 || true
    ufw allow in on "$ifc" >/dev/null 2>&1 || true
    ufw allow out on "$ifc" >/dev/null 2>&1 || true
    ufw route allow in on "$ifc" >/dev/null 2>&1 || true
    ufw route allow out on "$ifc" >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="$local_port/udp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-interface="$ifc" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

fougre_remove_firewall_rules() {
  local id="$1"
  local ifc subnet local_port remote remote_port local_ip
  ifc="$(fougre_iface "$id")"
  subnet="10.30.$id.0/24"
  local_port="$(fougre_default_port "$id")"
  remote_port="$local_port"
  remote=""
  local_ip=""
  if fougre_load_config "$id"; then
    local_port="${LOCAL_FOUGRE_PORT:-$local_port}"
    remote_port="${REMOTE_FOUGRE_PORT:-$remote_port}"
    remote="${REMOTE_PUBLIC_IP:-}"
    local_ip="${LOCAL_PUBLIC_IP:-}"
  fi

  if command -v iptables >/dev/null 2>&1; then
    while iptables -C INPUT -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D INPUT -i "$ifc" -j ACCEPT || break; done
    while iptables -C OUTPUT -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -o "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -i "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -i "$ifc" -j ACCEPT || break; done
    while iptables -C FORWARD -o "$ifc" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -o "$ifc" -j ACCEPT || break; done
    while iptables -C INPUT -s "$subnet" -j ACCEPT 2>/dev/null; do iptables -D INPUT -s "$subnet" -j ACCEPT || break; done
    while iptables -C OUTPUT -d "$subnet" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -d "$subnet" -j ACCEPT || break; done
    while iptables -C FORWARD -s "$subnet" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -s "$subnet" -j ACCEPT || break; done
    while iptables -C FORWARD -d "$subnet" -j ACCEPT 2>/dev/null; do iptables -D FORWARD -d "$subnet" -j ACCEPT || break; done
    while iptables -C INPUT -p udp --dport "$local_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport "$local_port" -j ACCEPT || break; done
    [ -n "$remote" ] && while iptables -C INPUT -p udp -s "$remote" --dport "$local_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp -s "$remote" --dport "$local_port" -j ACCEPT || break; done
    [ -n "$remote" ] && while iptables -C OUTPUT -p udp -d "$remote" --dport "$remote_port" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -p udp -d "$remote" --dport "$remote_port" -j ACCEPT || break; done
    [ -n "$remote" ] && [ -n "$local_ip" ] && while iptables -C INPUT -p udp -s "$remote" -d "$local_ip" --dport "$local_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp -s "$remote" -d "$local_ip" --dport "$local_port" -j ACCEPT || break; done
    [ -n "$remote" ] && [ -n "$local_ip" ] && while iptables -C OUTPUT -p udp -s "$local_ip" -d "$remote" --dport "$remote_port" -j ACCEPT 2>/dev/null; do iptables -D OUTPUT -p udp -s "$local_ip" -d "$remote" --dport "$remote_port" -j ACCEPT || break; done
  fi

  if command -v ufw >/dev/null 2>&1; then
    ufw delete allow "$local_port/udp" >/dev/null 2>&1 || true
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="$local_port/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

fougre_create_tunnel() {
  local interactive=${1:-0}

  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Invalid tunnel number. Use 1 to 254." >&2
    return 1
  fi

  if ! fougre_ensure_tools; then
    fougre_offer_wireguard_fallback_from_current "$interactive"
    return $?
  fi

  FOUGRE_IFACE="$(fougre_iface "$TUNNEL_ID")"
  FOUGRE_KEY="${FOUGRE_KEY:-$(fougre_default_key "$TUNNEL_ID")}"
  LOCAL_FOUGRE_PORT="${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$TUNNEL_ID")}"
  REMOTE_FOUGRE_PORT="${REMOTE_FOUGRE_PORT:-$LOCAL_FOUGRE_PORT}"
  FOUGRE_MTU="${FOUGRE_MTU:-1360}"

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  if [ -z "${LOCAL_PUBLIC_IP:-}" ]; then
    echo "Failed to detect local public IPv4" >&2
    return 1
  fi

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
    LOCAL_FOUGRE_IP="10.30.$TUNNEL_ID.1/30"
    REMOTE_FOUGRE_IP="10.30.$TUNNEL_ID.2"
  else
    SERVER_ROLE="KHAREJ"
    LOCAL_FOUGRE_IP="10.30.$TUNNEL_ID.2/30"
    REMOTE_FOUGRE_IP="10.30.$TUNNEL_ID.1"
  fi

  echo "[*] Local server public IP: $LOCAL_PUBLIC_IP"
  echo "[*] Tunnel type: FOU-GRE over UDP"
  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $FOUGRE_IFACE"
  echo "[*] GRE key: $FOUGRE_KEY"
  echo "[*] Server role: $SERVER_ROLE"
  echo "[*] Remote server public IP: $REMOTE_PUBLIC_IP"
  echo "[*] Local UDP receive port: $LOCAL_FOUGRE_PORT"
  echo "[*] Remote UDP endpoint port: $REMOTE_FOUGRE_PORT"
  echo "[*] MTU: $FOUGRE_MTU"

  ip link set "$FOUGRE_IFACE" down 2>/dev/null || true
  ip tunnel del "$FOUGRE_IFACE" 2>/dev/null || true
  ip link delete "$FOUGRE_IFACE" 2>/dev/null || true
  ip fou del port "$LOCAL_FOUGRE_PORT" local "$LOCAL_PUBLIC_IP" 2>/dev/null || true
  ip fou del port "$LOCAL_FOUGRE_PORT" 2>/dev/null || true

  if ! ip fou add port "$LOCAL_FOUGRE_PORT" ipproto 47 local "$LOCAL_PUBLIC_IP" 2>/dev/null; then
    if ! ip fou add port "$LOCAL_FOUGRE_PORT" ipproto 47 2>/dev/null; then
      echo "Could not register FOU receive port $LOCAL_FOUGRE_PORT. Falling back if interactive." >&2
      fougre_offer_wireguard_fallback_from_current "$interactive"
      return $?
    fi
  fi

  if ! ip link add name "$FOUGRE_IFACE" type gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$FOUGRE_KEY" ttl 255 encap fou encap-sport auto encap-dport "$REMOTE_FOUGRE_PORT" 2>/dev/null; then
    if ! ip tunnel add "$FOUGRE_IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" key "$FOUGRE_KEY" ttl 255 encap fou encap-sport auto encap-dport "$REMOTE_FOUGRE_PORT" 2>/dev/null; then
      echo "Could not create FOU-GRE interface. Falling back if interactive." >&2
      ip fou del port "$LOCAL_FOUGRE_PORT" local "$LOCAL_PUBLIC_IP" 2>/dev/null || true
      ip fou del port "$LOCAL_FOUGRE_PORT" 2>/dev/null || true
      fougre_offer_wireguard_fallback_from_current "$interactive"
      return $?
    fi
  fi
  ip addr add "$LOCAL_FOUGRE_IP" dev "$FOUGRE_IFACE"
  ip link set "$FOUGRE_IFACE" mtu "$FOUGRE_MTU"
  ip link set "$FOUGRE_IFACE" up

  if ! ip link show "$FOUGRE_IFACE" >/dev/null 2>&1; then
    echo "FOU-GRE interface creation failed" >&2
    return 1
  fi

  enable_ip_forward
  fougre_apply_firewall_rules "$TUNNEL_ID"

  echo "[OK] FOU-GRE over UDP tunnel created as $FOUGRE_IFACE"
  echo "Local FOU-GRE IP : $LOCAL_FOUGRE_IP"
  echo "Remote FOU-GRE IP: $REMOTE_FOUGRE_IP"

  if [ "$interactive" -eq 1 ]; then
    fougre_save_config
    if [ -f "$(fougre_config_file "$TUNNEL_ID")" ] && command -v systemctl >/dev/null 2>&1; then
      if fougre_install_service "$TUNNEL_ID"; then
        echo "FOU-GRE persistence enabled for $(fougre_service_name "$TUNNEL_ID")."
      else
        echo "Failed to enable FOU-GRE persistence. Tunnel is currently created, but it may not survive reboot." >&2
      fi
    fi
  fi
}

fougre_menu_config_tunnel() {
  show_header "Configure FOU-GRE over UDP Tunnel"
  if ! fougre_supported; then
    fougre_print_unsupported_message
    echo
    if confirm_default_yes "Use WireGuard UDP fallback instead?"; then
      wg_menu_config_tunnel
    else
      echo "Cancelled. No tunnel was changed."
    fi
    return
  fi

  prompt_role || return
  local selected_role existing_local_ip existing_remote_ip existing_local_port existing_remote_port existing_key
  selected_role="$ROLE"
  echo
  prompt_tunnel_id "Enter FOU-GRE tunnel number before IP [1-254]: " || return

  existing_local_ip=""
  existing_remote_ip=""
  existing_local_port=""
  existing_remote_port=""
  existing_key=""
  if fougre_load_config "$TUNNEL_ID"; then
    existing_local_ip="${LOCAL_PUBLIC_IP:-}"
    existing_remote_ip="${REMOTE_PUBLIC_IP:-}"
    existing_local_port="${LOCAL_FOUGRE_PORT:-}"
    existing_remote_port="${REMOTE_FOUGRE_PORT:-}"
    existing_key="${FOUGRE_KEY:-}"
  fi
  ROLE="$selected_role"
  FOUGRE_KEY="${existing_key:-$(fougre_default_key "$TUNNEL_ID")}"

  echo
  fougre_print_ip_plan "$TUNNEL_ID"
  echo
  echo "This mode wraps GRE protocol 47 inside UDP. Use it when raw GRE has high loss or is filtered."
  echo "For servers with multiple IP addresses, choose the exact LOCAL IPv4 that should be used by this tunnel."
  prompt_local_tunnel_ip "${existing_local_ip:-$(detect_local_public_ip || true)}" "Enter LOCAL server Public IPv4 for FOU-GRE bind" || return
  echo
  prompt_remote_public_ip "$existing_remote_ip" || return
  echo
  prompt_local_udp_port_for_fougre "${existing_local_port:-$(fougre_default_port "$TUNNEL_ID")}" "$TUNNEL_ID" || return
  prompt_remote_udp_port "${existing_remote_port:-$LOCAL_FOUGRE_PORT}" "Enter REMOTE server FOU-GRE UDP receive port" || return
  FOUGRE_MTU="1360"

  echo
  echo "Auto FOU-GRE values for tunnel $TUNNEL_ID:"
  echo "  Interface              : $(fougre_iface "$TUNNEL_ID")"
  echo "  Local bind public IP   : $LOCAL_PUBLIC_IP"
  echo "  Remote public IP       : $REMOTE_PUBLIC_IP"
  echo "  Local UDP receive port : $LOCAL_FOUGRE_PORT"
  echo "  Remote UDP port        : $REMOTE_FOUGRE_PORT"
  echo "  Inner IP range         : 10.30.$TUNNEL_ID.0/30"
  echo "  MTU                    : $FOUGRE_MTU"
  echo

  fougre_create_tunnel 1 || echo "FOU-GRE tunnel creation failed"
}

fougre_check_one_tunnel() {
  local id="$1"
  local ifc remote_public_of_tun
  ifc="$(fougre_iface "$id")"

  echo
  echo "FOU-GRE tunnel $id ($ifc) status"
  echo "-----------------------------------"
  if fougre_load_config "$id"; then
    echo "Saved role           : ${SERVER_ROLE:-unknown}"
    echo "Local public IP      : ${LOCAL_PUBLIC_IP:-unknown}"
    echo "Remote public IP     : ${REMOTE_PUBLIC_IP:-unknown}"
    echo "Local FOU-GRE IP     : ${LOCAL_FOUGRE_IP:-unknown}"
    echo "Remote FOU-GRE IP    : ${REMOTE_FOUGRE_IP:-unknown}"
    echo "Local UDP port       : ${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$id")}"
    echo "Remote UDP port      : ${REMOTE_FOUGRE_PORT:-$(fougre_default_port "$id")}"
    echo "MTU                  : ${FOUGRE_MTU:-1360}"
  else
    echo "No saved metadata found for tunnel $id."
  fi

  if command -v systemctl >/dev/null 2>&1; then
    echo "Systemd service      : $(systemctl is-active "$(fougre_service_name "$id")" 2>/dev/null || true) / $(systemctl is-enabled "$(fougre_service_name "$id")" 2>/dev/null || true)"
  fi

  echo
  echo "FOU receive ports:"
  if fougre_supported; then
    ip fou show 2>/dev/null | grep -E "(^|[[:space:]])port[[:space:]]+${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$id")}" || echo "  no matching FOU port found"
  else
    echo "  ip fou unsupported on this server"
  fi

  if ip link show "$ifc" >/dev/null 2>&1; then
    echo "$ifc interface       : exists"
    ip -br addr show "$ifc" 2>/dev/null || true
    remote_public_of_tun=$(ip tunnel show "$ifc" 2>/dev/null | awk -F'remote ' '{print $2}' | awk '{print $1}') || true
    if [ -n "$remote_public_of_tun" ]; then
      echo "Tunnel remote public IP: $remote_public_of_tun"
      echo "Pinging remote public IP (1 try)..."
      ping -c 1 -W 1 "$remote_public_of_tun" 2>&1 || true
    fi

    if fougre_load_config "$id" && [ -n "${REMOTE_FOUGRE_IP:-}" ]; then
      echo
      echo "Pinging remote FOU-GRE inner IP $REMOTE_FOUGRE_IP (4 tries)..."
      if ping -c 4 "$REMOTE_FOUGRE_IP" >/tmp/fougre_ping_$$.log 2>&1; then
        cat /tmp/fougre_ping_$$.log
        echo "[OK] FOU-GRE inner tunnel is UP"
      else
        cat /tmp/fougre_ping_$$.log
        echo "[WARN] FOU-GRE inner ping failed"
        echo "Diagnosis: check both sides use each other's public IPs, matching remote UDP ports, and that UDP ${LOCAL_FOUGRE_PORT:-$(fougre_default_port "$id")} is open inbound on this server. If public ping works but inner ping fails, run repair/restart on both sides."
      fi
      rm -f /tmp/fougre_ping_$$.log
    fi
  else
    echo "$ifc interface       : not found"
  fi
}

fougre_status_check() {
  show_header "FOU-GRE over UDP Tunnel Status"
  fougre_list_tunnels
  echo
  read -rp "Enter FOU-GRE tunnel number to check, or leave empty to check all listed FOU-GRE tunnels: " selected_id

  if [ -n "$selected_id" ]; then
    if ! validate_tunnel_id "$selected_id"; then
      echo "Invalid tunnel number. Use 1 to 254."
      return
    fi
    fougre_check_one_tunnel "$selected_id"
    return
  fi

  local ids id
  ids="$(fougre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No FOU-GRE tunnels found."
    return
  fi
  while IFS= read -r id; do
    [ -n "$id" ] && fougre_check_one_tunnel "$id"
  done <<< "$ids"
}

fougre_install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "Cannot install FOU-GRE service: invalid tunnel number" >&2
    return 1
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available on this system; cannot install FOU-GRE service." >&2
    return 1
  fi

  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"

  cat > "$FOUGRE_SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=FOU-GRE over UDP Tunnel %i Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start-fougre %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SERVICE

  systemctl daemon-reload
  systemctl enable "$(fougre_service_name "$id")"
  echo "FOU-GRE service installed and enabled for boot ($(fougre_service_name "$id"))"
}

fougre_service_start() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "FOU-GRE service start needs a tunnel number, e.g. --service start-fougre 1" >&2
    return 1
  fi
  if fougre_load_config "$id"; then
    echo "Starting FOU-GRE tunnel $id from saved config..."
    fougre_create_tunnel 0
  else
    echo "No saved FOU-GRE configuration for tunnel $id at $(fougre_config_file "$id")." >&2
    return 1
  fi
}

fougre_restart_one_tunnel() {
  local id="$1"
  local ifc svc
  if ! validate_tunnel_id "$id"; then
    echo "Invalid FOU-GRE tunnel number." >&2
    return 1
  fi
  ifc="$(fougre_iface "$id")"
  svc="$(fougre_service_name "$id")"

  if ! fougre_load_config "$id"; then
    echo "No saved FOU-GRE configuration found for tunnel $id." >&2
    return 1
  fi

  echo "Restarting FOU-GRE tunnel $id ($ifc) without touching other tunnels..."
  enable_ip_forward
  fougre_disable_rp_filter "$ifc"

  if command -v systemctl >/dev/null 2>&1 && [ -f "$FOUGRE_SERVICE_TEMPLATE" ]; then
    systemctl daemon-reload || true
    if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
      if ! systemctl restart "$svc"; then
        echo "Systemd restart failed; trying direct start from saved config..." >&2
        fougre_create_tunnel 0
      fi
    else
      fougre_create_tunnel 0
    fi
  else
    fougre_create_tunnel 0
  fi

  fougre_apply_firewall_rules "$id"
  echo "[OK] Repaired/restarted $ifc"
  fougre_check_one_tunnel "$id"
}

fougre_repair_menu() {
  show_header "FOU-GRE Repair / Restart"
  fougre_list_tunnels
  echo
  local ids selected_id
  ids="$(fougre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No FOU-GRE tunnels found."
    return
  fi
  read -rp "Enter FOU-GRE tunnel number to repair/restart, for example 1: " selected_id
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "FOU-GRE tunnel $selected_id was not found in the list."
    return
  fi
  fougre_restart_one_tunnel "$selected_id"
}

fougre_remove_one_tunnel() {
  local id="$1"
  local ifc file local_port local_ip
  ifc="$(fougre_iface "$id")"
  file="$(fougre_config_file "$id")"
  local_port="$(fougre_default_port "$id")"
  local_ip=""
  if fougre_load_config "$id"; then
    local_port="${LOCAL_FOUGRE_PORT:-$local_port}"
    local_ip="${LOCAL_PUBLIC_IP:-}"
  fi

  echo "Removing FOU-GRE tunnel $id ($ifc)..."

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$(fougre_service_name "$id")" 2>/dev/null || true
  fi

  ip link set dev "$ifc" down 2>/dev/null || true
  ip tunnel del "$ifc" 2>/dev/null || true
  ip link delete "$ifc" 2>/dev/null || true
  if [ -n "$local_ip" ]; then
    ip fou del port "$local_port" local "$local_ip" 2>/dev/null || true
  fi
  ip fou del port "$local_port" 2>/dev/null || true
  fougre_remove_firewall_rules "$id"

  rm -f "$file"
  echo "- Config removed: $file"
  echo "- FOU UDP receive port removed: $local_port"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
  fi
  echo "[OK] FOU-GRE tunnel $id removed."
}

fougre_remove_menu() {
  show_header "Remove FOU-GRE over UDP Tunnel"
  fougre_list_tunnels
  echo
  local ids selected_id
  ids="$(fougre_collect_ids || true)"
  if [ -z "$ids" ]; then
    echo "No FOU-GRE tunnels found."
    return
  fi
  read -rp "Enter FOU-GRE tunnel number to remove, for example 1: " selected_id
  if ! validate_tunnel_id "$selected_id"; then
    echo "Invalid tunnel number."
    return
  fi
  if ! echo "$ids" | grep -qx "$selected_id"; then
    echo "FOU-GRE tunnel $selected_id was not found in the list."
    return
  fi
  if confirm_yes "Are you sure you want to remove FOU-GRE tunnel $selected_id completely?"; then
    fougre_remove_one_tunnel "$selected_id"
  else
    echo "Cancelled."
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

menu_config_tunnel() {
  show_header "Create / Update Tunnel"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_menu_config_tunnel ;;
    wireguard) wg_menu_config_tunnel ;;
    fougre) fougre_menu_config_tunnel ;;
  esac
}

status_check() {
  show_header "Tunnel Status"
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_status_check ;;
    wireguard) wg_status_check ;;
    fougre) fougre_status_check ;;
  esac
}

remove_tun() {
  show_header "Remove Tunnel"
  echo "First choose which tunnel type you want to remove."
  echo
  ask_tunnel_type || return
  case "$SELECTED_TUNNEL_TYPE" in
    gre) gre_remove_menu ;;
    wireguard) wg_remove_menu ;;
    fougre) fougre_remove_menu ;;
  esac
}

list_saved_tunnels() {
  show_header "Saved / Active Tunnels"
  gre_list_tunnels
  echo
  wg_list_tunnels
  echo
  fougre_list_tunnels
}

show_menu() {
  show_header "GRE + WireGuard + FOU-GRE/WG-Fallback Tunnel Management"
  echo "1) create/update tunnel"
  echo "2) status"
  echo "3) remove tunnel"
  echo "4) list saved/active tunnels"
  echo "5) repair/restart Normal GRE tunnel"
  echo "6) repair/restart WireGuard tunnel"
  echo "7) repair/restart FOU-GRE over UDP tunnel"
  echo "   (v9: FOU-GRE + automatic WireGuard UDP fallback + safer UDP port checks)"
  echo "0) Exit"
  echo
  read -rp "Choose an option [0-7]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ; pause ;;
    2) status_check ; pause ;;
    3) remove_tun ; pause ;;
    4) list_saved_tunnels ; pause ;;
    5) gre_repair_menu ; pause ;;
    6) wg_repair_menu ; pause ;;
    7) fougre_repair_menu ; pause ;;
    0) echo "Bye"; exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
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
    start-fougre)
      ensure_root
      fougre_service_start "${3:-}"
      exit $?
      ;;
    start)
      # Backward compatibility with older gre-tunnel@ service template.
      ensure_root
      gre_service_start "${3:-}"
      exit $?
      ;;
    *)
      echo "Unknown service command. Use --service start-gre <id> or --service start-fougre <id>." >&2
      exit 1
      ;;
  esac
fi

ensure_root
while true; do
  show_menu
done
