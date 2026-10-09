# Validation — GRE-TUN 12.1.0

Base repository: `https://github.com/0fariid0/GRE-TUN`, commit `6bccd6b` (12.0.6).
Engine: unmodified official BackPack v1.8.5, source tag commit `ff86354bcafbd054e7888e48343145323c9b2207`.

## Completed

- Bash syntax checks on GRETUN.sh and install-local.sh.
- **33 automated tests passed**, including subcases for all four carriers and both roles.
- The real official amd64 engine accepted all eight generated L3 configurations using `backpack check -c`.
- Both shipped engine archives match the upstream published SHA-256 checksums. The adapter pins those exact hashes.
- Actual offline engine installation/extraction/version check in temporary directories; corrupt archive rejected.
- Open+exit through the actual menu entry point with privileged/network commands replaced by failing stubs: no such commands called. Last run: **0.021 seconds** in this container, including process launch and exit. This is not a measurement on the user's server or of a curl download.
- 45 original function definitions checked by SHA-256: main menu, original GRE/GRE Plus/WireGuard setup functions, and every HAProxy function are unchanged.
- Inventory mapping exposes `bptun7`, `10.40.7.1/30` and `10.40.7.2` to the existing HAProxy UDP path resolver.
- Config input rejection, isolated interface/port collision handling, cancellation, inventory dispatch, and existing multi-select speed input tested.
- Mocked systemd lifecycle verifies new creation, failed creation cleanup, failed edit rollback preserving token and service state, invalid-edit rejection, busy-port failure, and deletion isolation.
- QUIC can retain a running configuration while waiting for the remote handshake; no connection success is claimed.
- Firewall helper tests show adapter-owned rules, no NAT forwarding and no table flush; periodic repair respects manual service stops.
- BackPack operation lock tested.
- `systemd-analyze verify` passed for the generated service template with temporary executable/config paths. No service was installed or started on the host.

## Reproduce

From the distribution folder, on Linux amd64/arm64 with Python 3 and Bash:

```bash
bash -n GRETUN.sh
bash -n install-local.sh
python3 -m unittest discover -s tests -v
```

The tests extract and verify the bundled engine into a temporary directory. Optional `BACKPACK_TEST_ENGINE` overrides that location. Network/firewall/systemd mutations in lifecycle tests are mocked; do not interpret them as live network measurements.

## Limits

No access to the user's servers. No `/dev/net/tun` is available in this container, so a two-host tunnel, kernel TUN setup, provider firewall, real handshake/traffic, boot recovery and sustained throughput have not been exercised. The ARM archive was checksum-verified but not executed on this amd64 host. Upstream full Go tests were not rerun; the engine is distributed unchanged from its official release.

After configuring both hosts, use the existing ping and iperf3 menus to verify actual connectivity and performance. For a real failure inspect the existing diagnostic menu or `journalctl -u gretun-backpack@ID.service`.

Raw local test output: `test-results.txt`.
