# 12.4.0 installation and ON/OFF validation

Added direct main-menu entry 9 and visible HAProxy submenu entry 9. The curl/process-substitution entry installs a release-pinned Python helper, checking SHA256 and parsing syntax before atomic replacement. Existing matching helpers need no network. Failed downloads/checksums preserve the installed helper. Fedora/RHEL package mapping uses conntrack-tools.

ON asks server role, discovers routes/interfaces and eligible TCP ports, then performs existing trial/return-path setup. OFF asks role and ports, drains selected profiles and cleans only when conntrack reports zero. Outside requires acknowledgement that Iran forwards were disabled first. No remote SSH control is implied.

81 unittest methods pass, including 11 installer/toggle regressions. Shell syntax and Python compilation checked. Tests cover mocked network configuration and local loopback readiness; this environment cannot exercise actual GRE/WireGuard kernel forwarding or a real Xray handshake. Existing test reports document earlier versions.
