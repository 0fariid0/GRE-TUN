# GRE-TUN 12.3.0 automatic setup validation

Base: the delivered GRE-TUN 12.2.0 distribution. Existing transparent trial/promote/drain lifecycle retained.

Completed:
- 70 unittest methods passed (including subcases).
- Automatic kernel-kind discovery: conventional and arbitrary GRE/GREPLUS/WireGuard names; down/non-tunnel interfaces not silently used.
- Unique peer discovery for /30, /31, explicit point-to-point and single-peer WireGuard /32; ambiguous peers refused.
- Iran mapping through actual HAProxy backend routes, with no interface/IP/token prompt; automatic outside route preparation across detected links.
- Outside readiness gating: wrong peer/address/port, missing firewall rules, wrong marked route and unavailable IPv4 backend refused.
- Actual loopback TCP readiness exchange and rejection of a wrong peer. This is not a GRE/WireGuard transport test.
- Repeat-run idempotence and no duplicate profile/reload; partial batch failures preserve already-working profiles.
- WireGuard /32 peer PostUp host route with Table=off, key preservation and no generic default-route insertion.
- Bash syntax: GRETUN.sh, install-local.sh, transparent-auto.sh. Python compilation.
- systemd-analyze verify: generated restore, scoped WG post-start and readiness units with temporary/stub dependencies.
- Original BackPack bundle integrity unchanged.

Limits:
- No CAP_NET_ADMIN/CAP_NET_RAW in the build environment; no end-to-end source-IP interception, native GRE/WireGuard transfer, Xray authentication, reboot transport or client session continuity test was possible.
- Existing HAProxy config-generation functions were retained from 12.2.0. Real parser checks on official HAProxy 2.4.0/2.8.0 were performed for that version; no new parser claim is made for this automatic wrapper.
- A real client trial remains required before Activate. All system preparation is automatic, not Xray authentication using unavailable client credentials.
