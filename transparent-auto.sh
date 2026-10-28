#!/usr/bin/env bash
# One entry point on both sides; install prerequisites only when missing.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Run: sudo bash transparent-auto.sh' >&2; exit 1; }
auto_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for required in GRETUN.sh install-local.sh transparent_forward.py; do
  [ -f "$auto_dir/$required" ] || { echo 'Extract the full package before running the automatic setup.' >&2; exit 1; }
done
missing=()
command -v python3 >/dev/null 2>&1 || missing+=(python3)
if ! command -v ip >/dev/null 2>&1 || ! command -v ss >/dev/null 2>&1; then missing+=(iproute2); fi
if ! command -v iptables >/dev/null 2>&1 || ! command -v iptables-save >/dev/null 2>&1; then missing+=(iptables); fi
command -v conntrack >/dev/null 2>&1 || missing+=(conntrack)
if [ "${#missing[@]}" -gt 0 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    packages=()
    for item in "${missing[@]}"; do
      case "$item" in iproute2) packages+=(iproute) ;; conntrack) packages+=(conntrack-tools) ;; *) packages+=("$item") ;; esac
    done
    dnf install -y "${packages[@]}"
  else
    echo 'Install the missing prerequisites, then retry:' "${missing[@]}" >&2
    exit 1
  fi
fi
# Installs manager/module/engine files; does not activate a transparent forward.
bash "$auto_dir/install-local.sh" </dev/null
exec python3 /usr/local/lib/gretun/transparent_forward.py auto
