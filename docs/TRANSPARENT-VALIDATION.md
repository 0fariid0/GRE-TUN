# GRE-TUN 12.2.0 validation

Base: 0fariid0/GRE-TUN commit 03d8d22, version 12.1.1.

Completed:

- Bash syntax: GRETUN.sh and install-local.sh.
- Python compile: optional module and tests.
- 46 unittest methods, including subcases: plan validation, wrong-host/wrong-route rejection, independent return marks/tables for two Iran paths, trial isolation, promote, drain, refusal to remove live paths, rollback on reload/firewall/state-write failures, missing permissions, idempotent restore, collisions with other routing tables, WireGuard key preservation, Table=off and live AllowedIPs restoration, foreign manual-edit preservation, legacy manager guards, and scoped WireGuard ExecStartPost installation/removal.
- Real HAProxy parsers: source-built official tags v2.4.0 (commit 6cbbecf09734aeb5fa8bb88f36f06a6f6d35e813) and v2.8.0 (commit fdd8154ed37fef7f351075caa357917f94704dd7). Both supplied profiles in trial, active, and drained states accepted: 12 configurations total.
- Generated systemd unit accepted by systemd-analyze verify, with stub dependency units and temporary installed paths. No host service was installed or started for validation.
- BackPack engine bundle hashes match the unchanged upstream bundle manifest.
- Distribution ZIP integrity and content checksums verified.

Limits:

- Host has no CAP_NET_ADMIN/CAP_NET_RAW and cannot create a network namespace. No end-to-end packet delivery, real client-source socket interception, WireGuard packet transport, Xray handshake, live session continuity, or reboot integration test could be executed here.
- Kernel commands in lifecycle tests use an in-memory command model; these are meaningful state/rollback checks, not proof of deployed packet delivery.
- Exact installed HAProxy patch versions 2.4.30 and 2.8.16 were not executed. Major-branch parser compatibility was checked using the official release tags above.
- Production promotion must follow a successful real-client trial. A provider-specific routing/firewall issue can still prevent transparent delivery; no universal zero-downtime guarantee is made.
- Optional feature is IPv4 TCP, root-worker native HAProxy and systemd only. Custom HTTP/IPv6/TLS-termination, multipath/overlapping tunnels, custom WireGuard AllowedIPs/multiple peers/hooks, and BackPack transparent transport require separate work.
