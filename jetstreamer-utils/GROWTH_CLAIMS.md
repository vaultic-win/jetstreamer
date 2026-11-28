# Horizon remaining-growth evidence

`jetstreamer-horizon-growth-claim` validates resource evidence for a later admission
decision. Seal the executable and its hash-bound plan normally. Its receipt never
authorizes replay, deletion, publication, or R2 mutation.

The plan's `observations` list must contain at least six chronological routine
schema-v2 observer receipts. Each needs sufficient positive rates, advancing slots,
stable zero-restart controller/producer invocations, and no mutations. Routine
observations remain at least 1,800 seconds apart and must satisfy the observer's
minimum interval from their immediate predecessor.

When a user-requested status observation interrupts that chain, explicitly list its
absolute path and SHA-256 in the optional `user_requested_bridges` evidence array.
The array defaults to empty for existing plans. Each bridge must declare
`observation_reason: "user-requested-status"` and
`routine_minimum_interval_enforced: false`. Bridges must lie strictly between
selected routine receipts; the merged chain must bind every immediate predecessor's
path, hash, timestamp, and exact interval. Each list must itself be chronological.
No receipt discovery, silent skipping, or chain repair is performed.

Bridges retain the same live invocation and no-mutation gates. They may lack useful
rates; when a last-slot marker exists, its slot and terminal must remain consistent.
Their scratch peaks contribute to the conservative maximum. They **never** count
toward the required six routine observations. The output records them separately
with `counts_as_routine_growth_window: false`.

The existing checked growth formula and independent verified century-floor proof
remain required. A successful claim is not sufficient admission: fresh whole-host
resource checks, all other active growth claims, candidate peak, compatibility gates,
and an invocation-bound proven guard remain independent requirements. Never change
a running producer or an existing immutable deployment to adopt this tool.
