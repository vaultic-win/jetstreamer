# Full 227 operational status

`fleet/full227_status.rs` reports the actual admitted full 227 diagnostic. It
never creates a pipeline claim, substitutes a historical worker, grants archive
qualification, or writes archive/sidecar objects. It reuses `publish_epoch_status`
and the existing authenticated conditional publication/readback transport.

Root integration points:

```rust
// fleet.rs
mod full227_status;
pub(super) async fn publish_full227_status() -> Result<()> {
    full227_status::run().await
}
pub(super) fn full227_status_inactive_owner(
    receipt: &StatusPublicationReceipt,
) -> Result<Option<(String, String)>> {
    full227_status::inactive_owner(receipt)
}
```

Add CLI alias `status-publish-full227` to the async wrapper. Alongside the
existing qualification receipt matcher, call
`full227_status::matches(receipt, epoch, &observer, &before)` in fleet
reconciliation. In `inactive_status::owner_units`, call
`fleet::full227_status_inactive_owner(publication)` before the generic observer
decoder and return its single exact owner when present. This selects ownership
only: terminal evidence, no replacement/downstream work, queued-trigger checks,
authenticated conditional deletion and durable cleanup receipts remain required.

The sealed model schema is `jetstreamer-full227-status-plan-v1`. Its fields are:

- `mode`: `launch-event` for the initial accepted launch/first-guard lifecycle
  event, then `observation` for normal coordinated30-minute updates;
- `observer`, `fleet`, `launch`: exact path/SHA-256 bindings. The accepted plan
  must register that same diagnostic launch, root and actual invocation ID;
- `receipt_directory`, `estimate_receipt`: private absolute paths. Give each
  sample a new estimate destination; retain old immutable evidence;
- `initialization_allowance_millis`, `fallback_slots_per_second`: positive best
  estimates bound to the evidence and explained in `estimate_basis`;
- `downstream_allowance_millis`: positive integers for exactly `archive_close`,
  `boundary`, `full_verification`, `plugin_verification`, `readback`,
  `sidecar_commit`, `upload`;
- `estimate_basis` and nonempty `estimate_evidence` path/SHA-256 bindings, covering
  initialization, provisional rate and downstream work. Prefer recent measured
  phase durations and conservatively explain any cross-epoch rate assumption.

Execute the reviewed sealed tool with:

```text
status-publish-full227 MODEL --plan-sha256 SHA --self-sha256 SHA [--check-only]
```

The initial event is at the actual launch capture clock, requires a registered
full 227 diagnostic and its exact first real protective guard/PID1 completion,
and reads the invocation journal once at that cutoff. The adapter emits
`verification` while initializing and `replay` once real progress markers prove
slot execution; a reached replay terminal returns to `verification` for the
remaining close/check/upload/readback/sidecar work. Subsequent updates use the
coordinated observer's invocation-bound progress, never a separate polling loop.
An explicit user-requested observation uses the same path. Upload/readback
handoffs use the existing separately qualified delivery publisher when their
actual downstream owner takes over.

Elapsed time derives from the real PID1 monotonic start, checked against the
captured launch. During replay, bytes come from this producer's private
`archives/epoch-227.jet` before cohort import. The reader derives the exact
destination namespace from the canonical output path, selects only the run
whose PID matches the captured node, and binds its epoch range and manifest
fingerprint through `cohort-state.json`. It rejects ambiguous runs, symlinks,
multiple hard links and changing directory identities; it never scans AccountsDb.
Zero means this bound run has not created its archive yet. After cohort import,
the canonical destination supplies the size. The immutable estimate records
the measured path, source and cohort-state digest.

Observed slots between the pinned bootstrap and epoch 227 remain `verification`.
They retain the full epoch estimate and provisional rate until epoch recording
begins; a fast pre-epoch warmup does not shorten the estimate for 432000 slots.
ETA includes the complete432000-slot
epoch, its suffix and every declared downstream stage through verified sidecar
commit. A sufficient measured rate replaces the provisional rate. If transaction
or account counters reset, retain their raw reset count and accept a slot rate
only when the observer's accumulated slot delta exactly equals last-minus-first,
both endpoints bind this epoch and terminal slot, and the timestamp-derived rate
matches the reported rate. The observer's reset accumulation makes this equality
independent proof that slots themselves never reset. Invalid rates, slot resets,
unproved accounting resets, unknown owners or stale samples fail closed.
When initialization exceeds its original allowance, the provisional model
expands its remaining initialization allowance instead of pinning an overdue
stage to zero; revise that model from new evidence at the next coordinated poll.

Each immutable `jetstreamer-full227-status-observation-v1` envelope binds the
real launch, observer, accepted fleet, model, progress, start and exact payload.
The ordinary publication receipt's `observer_receipt` points to this envelope;
it is an observation/estimate bundle, not a synthetic v2 resource sample.
`pipeline_binding` stays absent and both owner IDs name the actual standalone
service. Dedicated ownership adapters validate that envelope and reproduce the
model; do not feed it to the legacy ordinary-replay observer decoder.

Retries reuse the frozen payload for that sample, recover the authenticated
publication receipt without replacing same-timestamp content, and retain all
archive/sidecar and inactive-status gates. No public URL is required. Never
create a status before actual launch or leave it as a live countdown after a
positively established terminal event without an active downstream owner.
