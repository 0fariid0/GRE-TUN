# GRE-TUN v12.6.3

GRE, GRE Plus, WireGuard + optional transparent IPv4 TCP client IP forwarding.

## Install / update
```bash
sudo bash GRETUN.sh --install
sudo bash /usr/local/bin/gretun-manager.sh
```
Upload both GRETUN.sh and README.md to your repository. Existing curl installation uses GRETUN.sh.

## Transparent client IP
Menu 9: ON / OFF, select Iran or Outside, then port numbers. Enable Outside first, then Iran. No PROXY protocol or Xray configuration change. Applies to IPv4 TCP, not UDP. Runtime configuration and systemd files are generated automatically; no separate download required.

## Automatic changes removed
No periodic tunnel health timer, GRE supervisor polling, automatic tunnel recreation, hourly UDP repair, or startup configuration repair. Old managed health/UDP repair timers are disabled during install or normal startup. GRE services run once at boot; operator create/update/reset remains available. Existing tunnel definitions and unrelated services are retained. Boot-time UDP rules and transparent return-path services remain necessary for forwarding; they do not monitor or recreate tunnels.

## Limits
A tunnel failure remains until manually repaired/reset. Real server connectivity and client handshakes must be checked on your servers. No guarantee of uninterrupted connections during operator changes.

## Forwarding interface
Menu 9 has ON, OFF and Back. Colors: green ON/READY, gray OFF, yellow draining/skipped, red mismatch/failed. Tables separate local configuration status, detected links, port numbers, selected routes and per-port results. Enter ports separated by commas or spaces; 0 selects all, 00 cancels. ON on Outside precedes ON on Iran. OFF on Iran precedes OFF on Outside. READY is local preparation, not proof of a live client handshake. NO_COLOR disables colors; non-terminal output is plain text. No additional confirmation or trial port.
