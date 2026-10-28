# 12.5.2

Evidence: SYN and SYN-ACK traverse GRE in both directions; Iran socket MARK counters increment; global src_valid_mark=1 and accept_local=0. apply_network previously enabled loose rp_filter=2. Linux reverse validation includes skb mark when src_valid_mark is effective, so the transparent local-default table can yield RTN_LOCAL for the source. This is rejected without accept_local.

Set accept_local=1 on the dedicated Iran interface before enabling loose RPF. Journal the original value before mutation, including migration from old records. Share original across profiles; restore on last cleanup or failed stage rollback. Keep it during draining. Never modify all/default or outside accept_local. Underlying TCP preflight remains enabled.

104 tests pass including initial zero value, ordering before probe, cleanup restoration, failure rollback, old-profile migration and outside isolation. No CAP_NET_ADMIN here: real tunnel packet/handshake validation unavailable. No claim of proven production success yet.

Primary source: https://github.com/torvalds/linux/blob/master/net/ipv4/fib_frontend.c (__fib_validate_source); https://www.kernel.org/doc/html/next/networking/ip-sysctl.html (src_valid_mark, accept_local).
