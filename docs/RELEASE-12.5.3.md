# Reset-all regression fix

Root cause: reset_all_tunnels unconditionally called transparent_guard all, refusing the entire reset with any active/draining transparent profile. A second blocker was wg_restart_one_tunnel regenerating the protected WG config via wg_write_config. Reset now uses a distinct preflight (does not bypass destructive/edit guards), restarts the saved WG service/config without key regeneration, restores all transparent routes after startup, and reports failures accurately.

Preflight validates saved GRE/Plus configs and WG metadata/file availability before stopping anything. Transparent preflight validates plans, transaction phases and original/patched protected WG file hashes. Pending-key WG remains skipped. Existing remove/reconfigure guards are retained.

111 automated tests, bash syntax and Python compilation pass. Regression harness uses fake systemctl/ip/wg tools; real kernel tunnels and production resets not exercised. Existing reset confirmation remains because it explicitly interrupts tunnels.
