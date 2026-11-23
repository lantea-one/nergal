# ADR 0041: Versioned rule enabled state

Status: Accepted.

Every authored filter, raw rpfilter, DNAT, postrouting and bridge/sub-chain rule
retains an Enabled boolean in policy intent, defaulting to true for old documents.
The configured forward MSS clamp also retains a separate enabled flag so disabling
it cannot discard its size. Serialize false explicitly; reject non-boolean state.

Validate every rule and reference, including disabled rules. Disabling is not a way
to smuggle unsupported input into a revision for later activation. After successful
validation, emit only enabled rules and only their dynamic meter objects, retaining
relative active-rule order. Empty chains/tables and their defaults remain explicit.
A disabled drop or NAT return exemption can broaden traffic; never equate disabled
with a safe verdict or silently change defaults.

Controller revision JSON is authoritative for disabled intent and metadata. Native
observations describe only active kernel enforcement and cannot reconstruct dormant
rules. Protected agent artifacts and complete native receipts still gate atomic
replacement and independent local timed rollback. Native reconstruction is an
active projection, not an original-policy export.

Inline checkboxes submit draft transformations with Administrator/CSRF protection.
Auditors see state but cannot change it. Preserve settings, positions, descriptions
and pinned references; ordinary edits must preserve state. Expose all primary,
auxiliary, raw and bridge regular-chain states. Show state changes in an intent
review even when native output is unchanged. Saving a revision and confirmed apply
remain separate from toggling a draft. No browser-to-kernel shortcut is introduced.

Verify strict codec defaults/denials, defensive snapshots, full validation of
inactive rules, exact re-enable output, meter omission and ordering. Exercise UI
RBAC/CSRF and saved revision immutability. Real packet checks must include disabling
accept/drop and NAT exemptions; mapped-identity agent tests must retain independent
watchdog recovery and confirmed apply. No production firewall is involved.
