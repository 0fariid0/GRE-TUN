#!/usr/bin/env bash
set -euo pipefail

# GRE + WireGuard persistent multi-tunnel manager v8
# Menu: create, delete, reset all
# GRE:       greN    + 10.10.N.x
# WireGuard: wgtunN  + 10.20.N.x

GRE_CONFIG_DIR="/etc/gre-tunnels"
GRE_LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gretun-manager.sh"
GRE_SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
GRE_LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"

WG_META_DIR="/etc/wgtun-tunnels"
WG_KEY_DIR="$WG_META_DIR/keys"
WG_CONFIG_DIR="/etc/wireguard"
WG_IFACE_PREFIX="wgtun"

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_base_deps() {
  if need_cmd ip && need_cmd systemctl; then
    return 0
  fi

  echo "Installing required base packages..."
  if need_cmd apt-get; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 systemd
  elif need_cmd dnf; then
    dnf install -y iproute systemd
  elif need_cmd yum; then
    yum install -y iproute systemd
  elif need_cmd pacman; then
    pacman -Sy --noconfirm iproute2 systemd
  else
    echo "Could not detect package manager. Please install iproute2 and systemd." >&2
    exit 1
  fi
}

install_wireguard_deps() {
  if need_cmd wg && need_cmd wg-quick; then
    return 0
  fi

  echo "Installing WireGuard tools..."
  if need_cmd apt-get; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard wireguard-tools
  elif need_cmd dnf; then
    dnf install -y wireguard-tools
  elif need_cmd yum; then
    yum install -y epel-release || true
    yum install -y wireguard-tools
  elif need_cmd pacman; then
    pacman -Sy --noconfirm wireguard-tools
  else
    echo "Could not detect package manager. Please install wireguard-tools." >&2
    exit 1
  fi
}

ensure_dirs() {
  mkdir -p "$GRE_CONFIG_DIR" "$WG_META_DIR" "$WG_KEY_DIR" "$WG_CONFIG_DIR"
  chmod 700 "$WG_META_DIR" "$WG_KEY_DIR" "$WG_CONFIG_DIR" 2>/dev/null || true
}

install_self() {
  if [ "${BASH_SOURCE[0]}" != "$INSTALL_BIN" ] && [ -r "${BASH_SOURCE[0]}" ]; then
    cp -f "${BASH_SOURCE[0]}" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
  elif [ -r "$INSTALL_BIN" ]; then
    chmod 755 "$INSTALL_BIN"
  else
    echo "Warning: could not install script to $INSTALL_BIN" >&2
    echo "Systemd services need this path to exist." >&2
  fi
}

write_gre_systemd_unit() {
  cat > "$GRE_SERVICE_TEMPLATE" <<EOF2
[Unit]
Description=Persistent GRE tunnel %i
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$INSTALL_BIN --systemd-start-gre %i
ExecStop=$INSTALL_BIN --systemd-stop-gre %i
TimeoutStartSec=30

[Install]
WantedBy=multi-user.target
EOF2

  systemctl daemon-reload
}

bootstrap() {
  install_base_deps
  ensure_dirs
  install_self
  write_gre_systemd_unit

  # Disable old single legacy service if it exists, because it can conflict with greN interfaces.
  if [ -f "$GRE_LEGACY_SERVICE_UNIT" ]; then
    systemctl disable --now gre-tunnel.service >/dev/null 2>&1 || true
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
  if ! validate_ipv4 "${REMOTE_PUBLIC_IP:-}"; then
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
  read -rp "Press Enter to continue..." _ || true
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
  echo
  read -rp "Choose [1-2]: " TUNNEL_TYPE_CHOICE
  case "$TUNNEL_TYPE_CHOICE" in
    1) SELECTED_TUNNEL_TYPE="gre" ;;
    2) SELECTED_TUNNEL_TYPE="wireguard" ;;
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

quote_conf_value() {
  printf '%q' "$1"
}

load_gre_config() {
  local iface="$1"
  local cfg="$GRE_CONFIG_DIR/$iface.conf"
  if [ ! -f "$cfg" ]; then
    echo "GRE config not found: $cfg" >&2
    return 1
  fi
  # shellcheck disable=SC1090
  source "$cfg"
}

start_gre() {
  local iface_arg="${1:-}"
  [ -n "$iface_arg" ] || { echo "Missing GRE instance name" >&2; exit 1; }
  load_gre_config "$iface_arg"

  : "${IFACE:?missing IFACE}"
  : "${LOCAL_PUBLIC_IP:?missing LOCAL_PUBLIC_IP}"
  : "${REMOTE_PUBLIC_IP:?missing REMOTE_PUBLIC_IP}"
  : "${LOCAL_TUNNEL_IP:?missing LOCAL_TUNNEL_IP}"

  ip link del "$IFACE" >/dev/null 2>&1 || true
  ip tunnel add "$IFACE" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255
  ip addr add "$LOCAL_TUNNEL_IP/30" dev "$IFACE"
  ip link set "$IFACE" mtu "${MTU:-1476}" up

  echo "GRE $IFACE is up: $LOCAL_TUNNEL_IP/30 -> ${REMOTE_TUNNEL_IP:-unknown}"
}

stop_gre() {
  local iface_arg="${1:-}"
  [ -n "$iface_arg" ] || exit 0
  if load_gre_config "$iface_arg" >/dev/null 2>&1; then
    ip link del "$IFACE" >/dev/null 2>&1 || true
  else
    ip link del "$iface_arg" >/dev/null 2>&1 || true
  fi
}

create_gre_tunnel() {
  show_header "Create GRE tunnel"
  prompt_tunnel_id "Enter GRE tunnel number [1-254]: " || return 1
  prompt_role || return 1
  prompt_local_tunnel_ip "" "Enter LOCAL server Public IPv4 for GRE bind" || return 1
  prompt_remote_public_ip || return 1

  local iface="gre$TUNNEL_ID"
  local local_tunnel_ip remote_tunnel_ip
  if [ "$ROLE" = "1" ]; then
    local_tunnel_ip="10.10.$TUNNEL_ID.1"
    remote_tunnel_ip="10.10.$TUNNEL_ID.2"
  else
    local_tunnel_ip="10.10.$TUNNEL_ID.2"
    remote_tunnel_ip="10.10.$TUNNEL_ID.1"
  fi

  local cfg="$GRE_CONFIG_DIR/$iface.conf"
  if [ -f "$cfg" ]; then
    echo "Config already exists: $cfg"
    confirm_yes "Overwrite it?" || return 1
  fi

  cat > "$cfg" <<EOF2
TUNNEL_ID=$(quote_conf_value "$TUNNEL_ID")
IFACE=$(quote_conf_value "$iface")
ROLE=$(quote_conf_value "$ROLE")
LOCAL_PUBLIC_IP=$(quote_conf_value "$LOCAL_PUBLIC_IP")
REMOTE_PUBLIC_IP=$(quote_conf_value "$REMOTE_PUBLIC_IP")
LOCAL_TUNNEL_IP=$(quote_conf_value "$local_tunnel_ip")
REMOTE_TUNNEL_IP=$(quote_conf_value "$remote_tunnel_ip")
MTU=1476
EOF2

  chmod 600 "$cfg"
  systemctl daemon-reload
  systemctl enable --now "gre-tunnel@$iface.service"

  echo
  echo "GRE tunnel created and enabled on boot."
  echo "Interface: $iface"
  echo "Local tunnel IP:  $local_tunnel_ip/30"
  echo "Remote tunnel IP: $remote_tunnel_ip"
}

validate_wg_key_or_empty() {
  local key="${1:-}"
  [ -z "$key" ] && return 0
  [[ "$key" =~ ^[A-Za-z0-9+/]{42,44}=*$ ]]
}

wg_public_key_for_iface() {
  local iface="$1"
  local key_file="$WG_KEY_DIR/$iface.key"
  if [ ! -f "$key_file" ]; then
    umask 077
    wg genkey > "$key_file"
  fi
  wg pubkey < "$key_file"
}

create_wg_dropin_for_gre_transport() {
  local wg_iface="$1"
  local gre_iface="$2"
  local dir="/etc/systemd/system/wg-quick@$wg_iface.service.d"
  mkdir -p "$dir"
  cat > "$dir/override.conf" <<EOF2
[Unit]
Wants=network-online.target gre-tunnel@$gre_iface.service
After=network-online.target gre-tunnel@$gre_iface.service
EOF2
  systemctl daemon-reload
}

remove_wg_dropin() {
  local wg_iface="$1"
  rm -rf "/etc/systemd/system/wg-quick@$wg_iface.service.d"
  systemctl daemon-reload
}

create_wireguard_tunnel() {
  show_header "Create WireGuard tunnel"
  install_wireguard_deps

  prompt_tunnel_id "Enter WireGuard tunnel number [1-254]: " || return 1
  prompt_role || return 1

  local wg_iface="$WG_IFACE_PREFIX$TUNNEL_ID"
  local local_wg_ip remote_wg_ip
  if [ "$ROLE" = "1" ]; then
    local_wg_ip="10.20.$TUNNEL_ID.1"
    remote_wg_ip="10.20.$TUNNEL_ID.2"
  else
    local_wg_ip="10.20.$TUNNEL_ID.2"
    remote_wg_ip="10.20.$TUNNEL_ID.1"
  fi

  local default_port=$((51820 + TUNNEL_ID))
  local local_port remote_port input
  read -rp "Local WireGuard UDP listen port [$default_port]: " input
  local_port="${input:-$default_port}"
  [[ "$local_port" =~ ^[0-9]+$ ]] && [ "$local_port" -ge 1 ] && [ "$local_port" -le 65535 ] || { echo "Invalid port"; return 1; }

  read -rp "Remote WireGuard UDP port [$local_port]: " input
  remote_port="${input:-$local_port}"
  [[ "$remote_port" =~ ^[0-9]+$ ]] && [ "$remote_port" -ge 1 ] && [ "$remote_port" -le 65535 ] || { echo "Invalid port"; return 1; }

  echo
  echo "WireGuard transport:"
  echo "1) Public UDP directly over internet"
  echo "2) UDP over an existing GRE tunnel"
  read -rp "Choose [1-2]: " WG_TRANSPORT_CHOICE

  local endpoint_ip mtu gre_transport_iface=""
  case "$WG_TRANSPORT_CHOICE" in
    1)
      prompt_remote_public_ip || return 1
      endpoint_ip="$REMOTE_PUBLIC_IP"
      mtu="1420"
      ;;
    2)
      prompt_tunnel_id "Enter existing GRE tunnel number used as transport [1-254]: " || return 1
      gre_transport_iface="gre$TUNNEL_ID"
      if [ ! -f "$GRE_CONFIG_DIR/$gre_transport_iface.conf" ]; then
        echo "GRE transport config not found: $GRE_CONFIG_DIR/$gre_transport_iface.conf"
        echo "Create the GRE tunnel first, then create WireGuard over it."
        return 1
      fi
      local gre_remote_default
      # shellcheck disable=SC1090
      source "$GRE_CONFIG_DIR/$gre_transport_iface.conf"
      gre_remote_default="${REMOTE_TUNNEL_IP:-}"
      read -rp "Remote GRE tunnel IP for WireGuard endpoint [$gre_remote_default]: " input
      endpoint_ip="${input:-$gre_remote_default}"
      validate_ipv4 "$endpoint_ip" || { echo "Invalid endpoint IP"; return 1; }
      mtu="1380"
      ;;
    *)
      echo "Invalid selection"
      return 1
      ;;
  esac

  local pubkey peer_pubkey private_key_file conf_file
  private_key_file="$WG_KEY_DIR/$wg_iface.key"
  pubkey="$(wg_public_key_for_iface "$wg_iface")"
  conf_file="$WG_CONFIG_DIR/$wg_iface.conf"

  echo
  echo "Local public key for $wg_iface:"
  echo "$pubkey"
  echo
  read -rp "Paste REMOTE peer public key: " peer_pubkey
  if ! validate_wg_key_or_empty "$peer_pubkey" || [ -z "$peer_pubkey" ]; then
    echo "Invalid or empty WireGuard peer public key."
    echo "Run this script on the other server first to get its public key, then create this tunnel."
    return 1
  fi

  if [ -f "$conf_file" ]; then
    echo "Config already exists: $conf_file"
    confirm_yes "Overwrite it?" || return 1
  fi

  cat > "$conf_file" <<EOF2
[Interface]
Address = $local_wg_ip/30
ListenPort = $local_port
PrivateKey = $(cat "$private_key_file")
MTU = $mtu

[Peer]
PublicKey = $peer_pubkey
AllowedIPs = $remote_wg_ip/32
Endpoint = $endpoint_ip:$remote_port
PersistentKeepalive = 25
EOF2
  chmod 600 "$conf_file"

  if [ -n "$gre_transport_iface" ]; then
    create_wg_dropin_for_gre_transport "$wg_iface" "$gre_transport_iface"
  else
    remove_wg_dropin "$wg_iface" >/dev/null 2>&1 || true
  fi

  systemctl daemon-reload
  systemctl enable --now "wg-quick@$wg_iface.service"

  echo
  echo "WireGuard tunnel created and enabled on boot."
  echo "Interface: $wg_iface"
  echo "Local WG IP:  $local_wg_ip/30"
  echo "Remote WG IP: $remote_wg_ip"
  echo "Endpoint:     $endpoint_ip:$remote_port"
}

delete_gre_tunnel() {
  show_header "Delete GRE tunnel"
  prompt_tunnel_id "Enter GRE tunnel number to delete [1-254]: " || return 1
  local iface="gre$TUNNEL_ID"

  systemctl disable --now "gre-tunnel@$iface.service" >/dev/null 2>&1 || true
  ip link del "$iface" >/dev/null 2>&1 || true
  rm -f "$GRE_CONFIG_DIR/$iface.conf"
  systemctl daemon-reload

  echo "Deleted GRE tunnel: $iface"
}

delete_wireguard_tunnel() {
  show_header "Delete WireGuard tunnel"
  prompt_tunnel_id "Enter WireGuard tunnel number to delete [1-254]: " || return 1
  local iface="$WG_IFACE_PREFIX$TUNNEL_ID"

  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  rm -f "$WG_CONFIG_DIR/$iface.conf" "$WG_KEY_DIR/$iface.key"
  remove_wg_dropin "$iface" >/dev/null 2>&1 || true
  ip link del "$iface" >/dev/null 2>&1 || true
  systemctl daemon-reload

  echo "Deleted WireGuard tunnel: $iface"
}

delete_tunnel_menu() {
  show_header "Delete tunnel"
  ask_tunnel_type || return 1
  case "$SELECTED_TUNNEL_TYPE" in
    gre) delete_gre_tunnel ;;
    wireguard) delete_wireguard_tunnel ;;
  esac
}

reset_all_tunnels() {
  show_header "Reset all tunnels"
  confirm_yes "This will stop and recreate all saved GRE and WireGuard tunnels. Continue?" || return 1

  systemctl daemon-reload

  echo "Stopping WireGuard tunnels first..."
  local conf iface
  shopt -s nullglob
  for conf in "$WG_CONFIG_DIR"/$WG_IFACE_PREFIX*.conf; do
    iface="$(basename "$conf" .conf)"
    systemctl stop "wg-quick@$iface.service" >/dev/null 2>&1 || true
    ip link del "$iface" >/dev/null 2>&1 || true
  done

  echo "Stopping GRE tunnels..."
  for conf in "$GRE_CONFIG_DIR"/gre*.conf; do
    iface="$(basename "$conf" .conf)"
    systemctl stop "gre-tunnel@$iface.service" >/dev/null 2>&1 || true
    ip link del "$iface" >/dev/null 2>&1 || true
  done

  echo "Starting GRE tunnels..."
  for conf in "$GRE_CONFIG_DIR"/gre*.conf; do
    iface="$(basename "$conf" .conf)"
    systemctl enable "gre-tunnel@$iface.service" >/dev/null 2>&1 || true
    systemctl restart "gre-tunnel@$iface.service"
    echo "  restarted $iface"
  done

  echo "Starting WireGuard tunnels..."
  for conf in "$WG_CONFIG_DIR"/$WG_IFACE_PREFIX*.conf; do
    iface="$(basename "$conf" .conf)"
    systemctl enable "wg-quick@$iface.service" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@$iface.service"
    echo "  restarted $iface"
  done
  shopt -u nullglob

  echo
  echo "All saved tunnels were reset and re-enabled for boot."
}

create_tunnel_menu() {
  show_header "Create tunnel"
  ask_tunnel_type || return 1
  case "$SELECTED_TUNNEL_TYPE" in
    gre) create_gre_tunnel ;;
    wireguard) create_wireguard_tunnel ;;
  esac
}

main_menu() {
  while true; do
    show_header "GRE + WireGuard Tunnel Manager v8"
    echo "1) Create tunnel"
    echo "2) Delete tunnel"
    echo "3) Reset all tunnels"
    echo "4) Exit"
    echo
    read -rp "Choose [1-4]: " choice
    case "$choice" in
      1) create_tunnel_menu; pause ;;
      2) delete_tunnel_menu; pause ;;
      3) reset_all_tunnels; pause ;;
      4) exit 0 ;;
      *) echo "Invalid selection"; pause ;;
    esac
  done
}

main() {
  ensure_root

  case "${1:-}" in
    --systemd-start-gre)
      start_gre "${2:-}"
      exit 0
      ;;
    --systemd-stop-gre)
      stop_gre "${2:-}"
      exit 0
      ;;
  esac

  bootstrap
  main_menu
}

main "$@"
