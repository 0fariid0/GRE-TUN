# GRE endpoint edit

Existing GRE/GRE Plus IDs now enter an endpoint-only editor before destructive-edit guards. It reloads and displays saved role/local/remote public addresses, keeps each address on Enter, cancels on 00 before applying, and does nothing when values are unchanged. New IDs retain original creation flow. Saved role and inner addressing are retained, not switched by the initial role selection.

Checks only matching transparent profiles using scoped reset-check; existing edit/remove guards remain elsewhere. Applies same-interface config and route restoration. Saved config backup and old-runtime recreation are attempted on create failure. No private WG config/key editing added; WG path unchanged.

119 tests pass including GRE local/remote-only edits, defaults, cancellation, GRE Plus, outside labels, config rollback and scoped preflight; includes prior reset/Transparent suite. Kernel interface operations are mocked, so real GRE peer connectivity is not verified here.
