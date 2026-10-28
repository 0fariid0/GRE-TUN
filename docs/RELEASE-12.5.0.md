# 12.5.0 review and validation

The user's capture was taken after OFF: there was no port 12044 listener, and normal inner-IP TCP traffic was passing. It does not establish the cause of the earlier transparent outage. Do not describe this release as a proven fix for that specific server failure.

Changes: direct original-port activation, interface-bound transparent backend, non-local TCP connect preflight before first production reload, legacy trial/active migration, draining-to-active re-enable, rollback of failed re-enable, no trial firewall opening for direct profiles, readiness service listener wait, diagnostic error capture, atomic matching helper installation.

The probe uses IP_TRANSPARENT and SO_BINDTODEVICE, with reserved benchmark source 198.18.255.254 and an ephemeral source port, connecting to the selected backend. It verifies TCP reachability with a non-local source, not Xray authentication, real-client ISP behavior, source-specific firewalls, or every future connection. It sends no application payload. It can fail closed on networks that filter that benchmark range. No arbitrary client source is assumed.

95 automated unit/regression tests passed. Tests model kernel operations; a loopback test exercises real readiness sockets. Shell syntax, Python compilation, archive CRC, and distribution hashes verified separately. Privileged namespace test unavailable: unshare -Urn failed, CapEff=0. Real end-to-end GRE/WireGuard forwarding and Xray handshake NOT tested.

Primary references reviewed:
- https://www.kernel.org/doc/Documentation/networking/tproxy.txt — transparent sockets and marked local delivery.
- https://docs.haproxy.org/2.4/configuration.html — source usesrc clientip and interface binding.

Historical advanced CLI/token functions remain for backwards compatibility and recovery, but are not exposed by the simplified auto menu.
