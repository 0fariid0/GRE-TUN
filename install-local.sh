#!/usr/bin/env bash
# Install this local distribution without touching running tunnels.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Run with sudo bash install-local.sh' >&2; exit 1; }
package_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
bash -n "$package_dir/GRETUN.sh"
# All shipped engine bytes must match before replacing the local manager.
(cd "$package_dir/engines/backpack" && sha256sum -c BUNDLE-SHA256SUMS)
install -d -m 0755 /usr/local/bin /usr/local/share/gretun/engines/backpack
for asset in backpack_linux_amd64.tar.gz backpack_linux_arm64.tar.gz; do
  install -m 0644 "$package_dir/engines/backpack/$asset" "/usr/local/share/gretun/engines/backpack/$asset.new"
  mv -f "/usr/local/share/gretun/engines/backpack/$asset.new" "/usr/local/share/gretun/engines/backpack/$asset"
done
install -m 0755 "$package_dir/GRETUN.sh" /usr/local/bin/gretun-manager.sh.new
mv -f /usr/local/bin/gretun-manager.sh.new /usr/local/bin/gretun-manager.sh
echo 'Installed. Running tunnels and their configurations were not restarted or replaced.'
echo 'Next time, open instantly from the installed local file:'
echo 'sudo bash /usr/local/bin/gretun-manager.sh'
if [ -t 0 ]; then exec bash /usr/local/bin/gretun-manager.sh; fi
