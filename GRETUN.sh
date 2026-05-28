#!/bin/bash
set -euo pipefail

CONFIG_DIR="/etc/gre-tunnels"
LEGACY_CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_TEMPLATE="/etc/systemd/system/gre-tunnel@.service"
LEGACY_SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
  fi
}

detect_local_public_ip() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'
}

validate_tunnel_id() {
  local id="${1:-}"
  [[ "$id" =~ ^[0-9]+$ ]] || return 1
  [ "$id" -ge 1 ] && [ "$id" -le 254 ]
}

tunnel_iface() {
  echo "gre$1"
}

config_file() {
  echo "$CONFIG_DIR/tunnel-$1.conf"
}

service_name() {
  echo "gre-tunnel@$1.service"
}

prompt_tunnel_id() {
  local prompt="${1:-Enter tunnel number [1-254]: }"
  read -rp "$prompt" TUNNEL_ID
  if ! validate_tunnel_id "$TUNNEL_ID"; then
    echo "Invalid tunnel number. Use a number from 1 to 254."
    return 1
  fi
  TUN_IFACE="$(tunnel_iface "$TUNNEL_ID")"
  TUN_KEY="$TUNNEL_ID"
}

print_tunnel_ip_plan() {
  local id="$1"
  echo "Tunnel $id IP plan:"
  echo "  Iran/local-side role 1 : 10.10.$id.1/30"
  echo "  Kharej/remote-side role 2: 10.10.$id.2/30"
  echo "  Interface name: gre$id"
  echo "  GRE key: $id"
}

save_config() {
  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Cannot save config: invalid tunnel number" >&2
    return 1
  fi

  mkdir -p "$CONFIG_DIR"
  local file
  file="$(config_file "$TUNNEL_ID")"

  cat > "$file" <<EOF_CONF
TUNNEL_ID="$TUNNEL_ID"
TUN_IFACE="$TUN_IFACE"
TUN_KEY="$TUN_KEY"
ROLE="$ROLE"
LOCAL_PUBLIC_IP="$LOCAL_PUBLIC_IP"
REMOTE_PUBLIC_IP="$REMOTE_PUBLIC_IP"
LOCAL_GRE_IP="$LOCAL_GRE_IP"
REMOTE_GRE_IP="$REMOTE_GRE_IP"
EOF_CONF
  chmod 600 "$file"
  echo "Saved tunnel $TUNNEL_ID configuration to $file"
}

load_config() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    return 1
  fi

  local file
  file="$(config_file "$id")"
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    source "$file"
    TUNNEL_ID="$id"
    TUN_IFACE="${TUN_IFACE:-$(tunnel_iface "$id")}"
    TUN_KEY="${TUN_KEY:-$id}"
    return 0
  fi

  # Backward compatibility for old single-tunnel installs.
  if [ "$id" = "1" ] && [ -f "$LEGACY_CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$LEGACY_CONF_FILE"
    TUNNEL_ID="1"
    TUN_IFACE="gre1"
    TUN_KEY="1"
    return 0
  fi

  return 1
}

list_saved_tunnels() {
  echo "Saved tunnel configs:"
  if [ -d "$CONFIG_DIR" ] && compgen -G "$CONFIG_DIR/tunnel-*.conf" >/dev/null; then
    local f id
    for f in "$CONFIG_DIR"/tunnel-*.conf; do
      id="${f##*/tunnel-}"
      id="${id%.conf}"
      if validate_tunnel_id "$id"; then
        echo "  - tunnel $id: $f"
      fi
    done
  elif [ -f "$LEGACY_CONF_FILE" ]; then
    echo "  - legacy tunnel 1: $LEGACY_CONF_FILE"
  else
    echo "  none"
  fi
}

create_tunnel() {
  # create_tunnel [interactive]
  # expects TUNNEL_ID, ROLE and REMOTE_PUBLIC_IP set
  local interactive=${1:-0}
  if [ "$interactive" -eq 1 ]; then
    clear
  fi

  if ! validate_tunnel_id "${TUNNEL_ID:-}"; then
    echo "Invalid tunnel number. Use 1 to 254." >&2
    return 1
  fi

  TUN_IFACE="$(tunnel_iface "$TUNNEL_ID")"
  TUN_KEY="${TUN_KEY:-$TUNNEL_ID}"

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
    SERVER_ROLE="kharej"
    LOCAL_GRE_IP="10.10.$TUNNEL_ID.2/30"
    REMOTE_GRE_IP="10.10.$TUNNEL_ID.1"
  fi

  echo "[*] Tunnel number: $TUNNEL_ID"
  echo "[*] Interface: $TUN_IFACE"
  echo "[*] GRE key: $TUN_KEY"
  echo "[*] Server role: $SERVER_ROLE"

  modprobe ip_gre || true

  # Remove only this tunnel interface so other GRE tunnels stay intact.
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

  echo 1 > /proc/sys/net/ipv4/ip_forward || true
  if [ -f /etc/sysctl.conf ]; then
    if grep -q '^#\?net.ipv4.ip_forward=' /etc/sysctl.conf; then
      sed -i 's/^#\?net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true
    else
      echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf || true
    fi
    sysctl -p >/dev/null 2>&1 || true
  fi

  # Allow GRE protocol in iptables.
  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
    iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -j ACCEPT
  fi

  echo "[OK] GRE tunnel created as $TUN_IFACE"
  echo "Local GRE IP: $LOCAL_GRE_IP"
  echo "Remote GRE IP: $REMOTE_GRE_IP"

  # If called interactively from the menu, offer to save config and install service.
  if [ "$interactive" -eq 1 ]; then
    read -rp "Save this tunnel configuration? [y/N]: " yn
    case "$yn" in
      [Yy]*) save_config ;;
      *) echo "Configuration not saved." ;;
    esac

    local file
    file="$(config_file "$TUNNEL_ID")"
    if [ -f "$file" ]; then
      echo "Installing persistent service for tunnel $TUNNEL_ID..."
      install_service "$TUNNEL_ID" || echo "Failed to install service; you can install it manually later."
    else
      read -rp "Configuration not saved; install persistent service anyway? [y/N]: " sn
      case "$sn" in
        [Yy]*) install_service "$TUNNEL_ID" || echo "Failed to install service." ;;
        *) echo "Service not installed." ;;
      esac
    fi
  fi

  return 0
}

menu_config_tunnel() {
  clear
  echo
  echo "Configure GRE Tunnel"
  echo "1) Iran Server"
  echo "2) kharej Server"
  echo
  read -rp "Select server type [1-2]: " ROLE
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "Invalid selection"
    return
  fi

  echo
  if ! prompt_tunnel_id "Enter tunnel number before IP [1-254]: "; then
    return
  fi
  print_tunnel_ip_plan "$TUNNEL_ID"
  echo

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  echo "Local Public IP detected: $LOCAL_PUBLIC_IP"
  read -rp "Enter REMOTE server Public IPv4: " REMOTE_PUBLIC_IP
  if [ -z "$REMOTE_PUBLIC_IP" ]; then
    echo "Remote IP cannot be empty"
    return
  fi

  # call create_tunnel interactively (will handle save+install flow)
  create_tunnel 1 || echo "create_tunnel failed"
}

check_one_tunnel() {
  local id="$1"
  local ifc
  ifc="$(tunnel_iface "$id")"

  echo
  echo "Tunnel $id ($ifc) status"
  echo "----------------------"
  if ip link show "$ifc" >/dev/null 2>&1; then
    echo "$ifc: exists and is $(ip link show "$ifc" | awk -F': ' 'NR==1{print $2}')"
    local remote_public_of_tun
    remote_public_of_tun=$(ip tunnel show "$ifc" 2>/dev/null | awk -F'remote ' '{print $2}' | awk '{print $1}') || true
    if [ -n "$remote_public_of_tun" ]; then
      echo "Tunnel remote public IP: $remote_public_of_tun"
      echo "Pinging remote public IP (1 try)..."
      local ping_public_out
      ping_public_out=$(ping -c 1 -W 1 "$remote_public_of_tun" 2>&1) || true
      echo "$ping_public_out"
      if echo "$ping_public_out" | grep -qE '1 received|1 packets received|bytes from'; then
        echo "Remote public is reachable"
      else
        echo "Remote public is NOT reachable"
      fi
    fi

    if load_config "$id" && [ -n "${REMOTE_GRE_IP:-}" ]; then
      echo "Pinging remote GRE inner IP $REMOTE_GRE_IP (4 tries)..."
      local ping_inner_out
      ping_inner_out=$(ping -c 4 "$REMOTE_GRE_IP" 2>&1) || true
      echo "$ping_inner_out"
      if echo "$ping_inner_out" | grep -qE '([1-9]) received|([1-9]) packets received|bytes from'; then
        echo "GRE inner tunnel is UP"
      else
        echo "GRE inner tunnel seems DOWN"
      fi
    else
      echo "No saved inner GRE IP for tunnel $id; save config first for inner ping test."
    fi
  else
    echo "$ifc interface not found"
  fi
}

status_check() {
  clear
  echo
  echo "GRE Tunnel Status"
  list_saved_tunnels
  echo
  read -rp "Enter tunnel number to check, or leave empty to list existing GRE interfaces: " selected_id

  if [ -n "$selected_id" ]; then
    if ! validate_tunnel_id "$selected_id"; then
      echo "Invalid tunnel number. Use 1 to 254."
      return
    fi
    check_one_tunnel "$selected_id"
    return
  fi

  mapfile -t tunifs < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^gre[0-9]+$' || true)
  if [ ${#tunifs[@]} -eq 0 ]; then
    echo "No numbered GRE interfaces found."
    return
  fi

  local ifc id
  for ifc in "${tunifs[@]}"; do
    id="${ifc#gre}"
    if validate_tunnel_id "$id"; then
      check_one_tunnel "$id"
    fi
  done
}

remove_one_tunnel() {
  local id="$1"
  local ifc file
  ifc="$(tunnel_iface "$id")"
  file="$(config_file "$id")"

  echo "Removing tunnel $id ($ifc)..."
  ip link set dev "$ifc" down 2>/dev/null || true
  if ip tunnel del "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip tunnel del'"
  elif ip link delete "$ifc" 2>/dev/null; then
    echo "- $ifc removed with 'ip link delete'"
  else
    echo "- $ifc was not found or could not be removed automatically."
  fi

  read -rp "Remove saved config $file as well? [y/N]: " yn
  case "$yn" in
    [Yy]*) rm -f "$file"; echo "Config removed." ;;
    *) echo "Config kept." ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files | grep -q '^gre-tunnel@\.service'; then
      read -rp "Disable persistent service $(service_name "$id") as well? [y/N]: " sy
      case "$sy" in
        [Yy]*) uninstall_service "$id" ;;
        *) echo "Service left installed." ;;
      esac
    fi
  fi
}

remove_all_tunnels() {
  echo "Removing GRE/GRETAP/ERSPAN interfaces..."
  mapfile -t tunifs < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre|gretap|erspan)' || true)

  if [ ${#tunifs[@]} -eq 0 ]; then
    echo "No GRE/GRETAP/ERSPAN interfaces found."
  else
    local ifc removed
    for ifc in "${tunifs[@]}"; do
      echo "Found tunnel/interface: $ifc"
      ip link set dev "$ifc" down 2>/dev/null || true

      removed=0
      if ip tunnel del "$ifc" 2>/dev/null; then
        echo "- $ifc removed with 'ip tunnel del'"
        removed=1
      fi

      if [ $removed -eq 0 ]; then
        if ip link delete "$ifc" 2>/dev/null; then
          echo "- $ifc removed with 'ip link delete'"
          removed=1
        fi
      fi

      if [ $removed -eq 0 ]; then
        if ip link delete dev "$ifc" type gretap 2>/dev/null; then
          echo "- $ifc removed with 'ip link delete dev $ifc type gretap'"
          removed=1
        fi
      fi

      if [ $removed -eq 0 ]; then
        echo "- Could not remove $ifc automatically. Showing debug info for manual inspection:"
        ip -d link show "$ifc" || true
        echo "You can try to remove it manually, e.g.:"
        echo "  sudo ip link set dev $ifc down"
        echo "  sudo ip link delete $ifc"
      fi
    done
  fi

  echo "Done."
  read -rp "Remove all saved configs in $CONFIG_DIR as well? [y/N]: " yn
  case "$yn" in
    [Yy]*) rm -rf "$CONFIG_DIR"; rm -f "$LEGACY_CONF_FILE"; echo "Configs removed." ;;
    *) echo "Configs kept." ;;
  esac

  if command -v systemctl >/dev/null 2>&1; then
    read -rp "Disable all gre-tunnel@ services as well? [y/N]: " sy
    case "$sy" in
      [Yy]*) uninstall_service_all ;;
      *) echo "Services left installed." ;;
    esac
  fi
}

remove_tun() {
  clear
  echo
  echo "Remove GRE Tunnel"
  list_saved_tunnels
  echo
  read -rp "Enter tunnel number to remove, or leave empty to remove all GRE/GRETAP/ERSPAN interfaces: " selected_id

  if [ -n "$selected_id" ]; then
    if ! validate_tunnel_id "$selected_id"; then
      echo "Invalid tunnel number. Use 1 to 254."
      return
    fi
    remove_one_tunnel "$selected_id"
  else
    remove_all_tunnels
  fi
}

install_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "Cannot install service: invalid tunnel number" >&2
    return 1
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not available on this system; cannot install service." >&2
    return 1
  fi

  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f "$0" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"

  cat > "$SERVICE_TEMPLATE" <<EOF_SERVICE
[Unit]
Description=GRE Tunnel %i Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start %i
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF_SERVICE

  # Remove the old single-tunnel service if it exists, to avoid conflicts.
  if [ -f "$LEGACY_SERVICE_UNIT" ]; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$LEGACY_SERVICE_UNIT"
  fi

  systemctl daemon-reload
  systemctl enable --now "$(service_name "$id")"
  echo "Service installed and started ($(service_name "$id"))"
}

uninstall_service() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "Cannot uninstall service: invalid tunnel number" >&2
    return 1
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$(service_name "$id")" 2>/dev/null || true
    systemctl daemon-reload
  fi
  echo "Service disabled for tunnel $id ($(service_name "$id"))"
  echo "Shared script/template kept for other tunnels: $INSTALL_BIN / $SERVICE_TEMPLATE"
}

uninstall_service_all() {
  if command -v systemctl >/dev/null 2>&1; then
    mapfile -t services < <(systemctl list-unit-files 'gre-tunnel@*.service' --no-legend 2>/dev/null | awk '{print $1}' || true)
    local svc
    for svc in "${services[@]}"; do
      systemctl disable --now "$svc" 2>/dev/null || true
    done
    rm -f "$SERVICE_TEMPLATE" "$LEGACY_SERVICE_UNIT"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
  echo "All GRE tunnel services uninstalled and script removed from $INSTALL_BIN"
}

service_start() {
  local id="${1:-${TUNNEL_ID:-}}"
  if ! validate_tunnel_id "$id"; then
    echo "Service start needs a tunnel number, e.g. --service start 1" >&2
    return 1
  fi

  if load_config "$id"; then
    echo "Starting tunnel $id from saved config..."
    create_tunnel 0
  else
    echo "No saved configuration for tunnel $id at $(config_file "$id"). Service cannot start." >&2
    return 1
  fi
}

show_menu() {
  clear
  echo "==============================="
  echo " ++ GRE Tunnel Management ++"
  echo "==============================="
  echo
  echo "1) config tunnel"
  echo "2) status"
  echo "3) remove tun"
  echo "4) list saved tunnels"
  echo "0) Exit"
  echo
  read -rp "Choose an option [0-4]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ; read -rp "Press Enter to continue..." _ ;;
    2) status_check ; read -rp "Press Enter to continue..." _ ;;
    3) remove_tun ; read -rp "Press Enter to continue..." _ ;;
    4) clear ; list_saved_tunnels ; read -rp "Press Enter to continue..." _ ;;
    0) echo "Bye"; exit 0 ;;
    *) echo "Invalid option"; sleep 1 ;;
  esac
}

### Script entry
if [[ "${1:-}" == "--service" ]]; then
  if [[ "${2:-}" == "start" ]]; then
    ensure_root
    service_start "${3:-}"
    exit $?
  fi
fi

ensure_root
while true; do
  show_menu
done
