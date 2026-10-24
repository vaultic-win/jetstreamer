# Full 227 terminal failure event

`capture-full227-failure SPEC --spec-sha256 SHA --self-sha256 SHA` captures only
the failed full 227 invocation `a10f37b57711425a81633c62c66438d5`, original parent
PID 121077, launch receipt `12eb6beb`, sealed raw journal `97b9b039`, manager dump
`50f3701e`, and open repair record `36b1900f`. It never reruns the producer or
changes a guard, archive, R2 object, or resource observation.

The sealed spec has schema
`jetstreamer-private-full227-failure-capture-spec-v1`, plus `observer`, `fleet`
as path/SHA256 objects and `output`. Output must be `proof.json` beneath a
root-owned private `/var/lib/jetstreamer/horizon-full227-terminal-proof-*`
directory. Use the current accepted coordinated sample within 30 minutes of its
original observation time. Sample 338 or a later normal sample is accepted; do
not refresh the observation clock to make a stale sample fit.

Capture proves the registered original diagnostic, exact immutable launch,
raw mismatch at slot98091122/entry232/transaction223/signature3f6m… with expected
None and actual InstructionError 0 Custom(2), unique PID1 exit 1 and failed
exit-code events, and current loadedfailed same-IID owner with MainPID 0 and no
restart. Its command must match the original launch. Complete fresh unit
censuses before and after may differ from the accepted census only in 227's
authenticated terminal row. No other owner may disappear, restart, change
command or transition. The preserved raw manager dump is independently checked.
Existing output is an idempotent retry only with the same sealed spec/helper.

To reconcile this event, retain the existing observer, tracked units, all
diagnostic and pipeline claims, configuration/history and every other epoch
gate. Set `previous_fleet` to the accepted fleet and `metadata_event` to the
captured proof; use a fresh no-clobber output path. Only 227's gate changes to
`failed-needs-repair`; retain all its previous evidence and append the new proof
and exact open repair record. A meaningful repair next_action is required.
All reserve-stop bindings remain unchanged. The event proof must have been
captured within 5 minutes of this reconciliation. Census validation repeats at
the actual reconciliation call site, and the normal final census must match.

The fleet retains the original diagnostic as terminal history, omits it from
active work and marks 227 failed. It preserves the old observer time and actual
resource counters; the event is not an admission or fresh capacity sample.
Reassess capacity only through the normal fresh-observation/admission gates.

Root can then use the existing `status-retire-inactive` workflow with this fresh
terminal fleet, the original 227publication receipt and the exact open repair
record. The existing full 227 status owner adapter identifies the original
unit/IID, and generic inactive-status checks authenticate its durable failed
terminal state, no replacement/active owner and conditional object identity.
There is no new remote deletion path. Latest stale publication was sample 337;
the 338publisher refused the failed owner and wrote no replacement.

Failure capture, source integration and stale-status retirement leave repair 227
open. Canonical/full/plugin/boundary and authenticated upload/readback/sidecar
gates remain necessary for readiness. Every source and runtime authority flag
in this event remains false.
