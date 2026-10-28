# 12.5.1

Removed IRAN-OFF acknowledgement and Enter-to-apply from automatic setup. Selecting role and ports immediately applies ON or OFF. The outside-first ON / Iran-first OFF order still applies but is informational, not a confirmation gate.

Automatic status table before each menu choice and after role selection: Iran active mapping, normal forwards, legacy trial, draining, recovery, outside ready paths, and unprepared Xray tunnel paths. Iran active profiles are checked against their frontend backend mapping; mismatch is not reported as ON. Status describes local configuration, not a live handshake.

100 automated tests pass, including no-confirmation outside OFF, direct menu ON, role filtering, per-interface outside states, legacy status, config drift, and prior network/rollback regression coverage. No new live server/kernel tunnel test was possible. See prior release notes for limitations.
