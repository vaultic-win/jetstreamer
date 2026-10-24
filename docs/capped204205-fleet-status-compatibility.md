# Capped 204/205 fleet and status compatibility

Source base: frozen R2 consumer `7fb74c9f33777369d14634dc9ca101ad071f57b3`.
This adapter is prepared on branch `capped204205-continuation-lifecycle` in its
own worktree. The original node baseline `8f328729` and the frozen shared
node/control/probe source `7d4266bcf876496e9a8f56656f38cfe464151bf4`
and all their artifacts are preserved.
No host observation, service action, admission, Bank run or R2 operation has run.

The deployed observer is binary `78dc39c3b8cf3e4198e6d2b35348ba764fe1c2ceecbd12cc536090ae8315facd`,
from source `3e932681` based on `42bac936`. This branch predates its output-file
and RSS additions. Its observer executable must not be built or deployed.
The shared `process_references.rs` source is identical to the deployed source.

The deployed replay observer requires one stable worker beneath the configured
scratch directory. Prefix reread, suffix validation and V4 assembly legitimately
have no worker. Its optional output-file evidence is closed to the two original
prefix units/IIDs/PIDs and cannot be borrowed by future continuation units.
An unavailable diagnostic observation is therefore not proof of inactivity or
zero resource use. The adapter leaves observer configuration and binary unchanged,
preserves old diagnostics, and consumes separately captured bounded metadata,
actual guard heartbeats and complete manager/terminal evidence in the same
30-minute campaign cycle. Explicit user status requests remain eligible for
out-of-band observations under the existing observer reason contract.

There is also a concrete frozen-control compatibility blocker. In
`historical.rs::bind_worker_executable`, the actual worker is a readonly copy
owned by UID 1000 at `scratch/.../bound-worker/historical-worker`.
The frozen control's `process_sample` instead requires the child executable to
equal `Plan.worker.path` and requires UID 0 for executable hashing. It would
reject that legitimate worker at native startup. A separately qualified shared
control correction must authenticate the actual copied inode/path, content
digest and process identity before a live launch. The status adapter does not
weaken or bypass this guard and does not assert that the frozen candidate can
already launch safely.

The separate source-only copied-worker successor
`cb1fb523088538637a024a1d857862a9696970d1` extracts the actual small binder
into `worker_executable.rs` and corrects source/copy/mapped-inode authentication.
Its Cargo qualification, concrete artifacts and real disposable capability are
still required. This R2 adapter grants none of that authority.

The successor to preserved lifecycle commit `0c9e709d` also corrects the
guard worker `start_time` contract: the actual guard serializes procfs start
ticks as a decimal JSON string. A field-specific reader requires a canonical
positive `u64` decimal string and rejects integers, null, zero, signs, whitespace,
leading zeroes, fractions, exponents, non-ASCII digits and overflow. The generic
JSON integer reader remains strict. An actual-shaped synthetic guard payload
and negative variants are covered by source tests; Cargo remains pending.

Public status phases are limited here to `replay`, `verification`, `upload` and
`readback`. ETA policy includes prefix reread, native restore and suffix replay,
suffix validation, assembly, independent full verification, current-plugin
verification, required boundaries/import, upload, readback/source revalidation
and sidecar commit. All estimates remain definite unsigned integers and best
guesses, never success or publication proofs.

The observer audit is a source audit of actual deployed commit `3e932681`,
including its `observe_replay`, `observe_worker`, `private_archive223` and
`prefix_output204205` paths. Its special parent mode is closed to epoch 223;
ordinary continuation rows require exactly one worker and output credits bind
only the original 204/205 invocations. No observer change is selected here.
The source adapters consume real independent guard heartbeats and bounded
manager/output metadata alongside the existing coordinated observation. Raw
observer diagnostics, including errors, remain in the accepted lineage.
No observer executable from this older R2 branch may be built or deployed.
Any future observer change must begin at corrected commit `3e932681` and retain
the RSS PID/start identity checks, final revalidation and bounded census retries.

The prepared commands are `capture-capped204205-work`,
`prepare-capped204205-fleet-status` and `publish-capped204205-status`.
They consume concrete hash-bound specs; none starts, stops or restarts a
producer. Capture writes no-clobber copies of the first actual guard fire,
continuation PID 1 start history, current guard, complete before/after unit
censuses, generated archive metadata, terminal history and downstream history.
The continuation's actual PID/IID, command, producer plan, complete-path
admission, source capture and original successful invocation are revalidated.
Original natural inactivity remains mandatory at every evaluation. An unknown,
replaced, pending or unavailable owner cannot become inactive from a diagnostic
error. Unresolved ownership is preserved privately and blocks status replacement
and cleanup.

The frozen phase protocol names `native_restore` for both restoration and suffix
execution. The adapter derives private `suffix_execution` only from a real
guard-observed worker with PID, process start time, RSS and VMAs. Workerless
restoration is `verification`; observed suffix execution is `replay`.
Prefix validation, suffix validation, assembly and private completion remain
`verification`. The reported bytes are those of the current final V4 output
file, or zero before it exists. Retained prefix and suffix sizes stay private
and cannot be substituted for the final output's size.

Each ETA policy binds the exact epoch, producer-plan binding, launch binding and
current frame binding. Its nonempty `estimate_evidence` list binds the planning
or measured evidence. `current_stage` must equal the observed derived stage;
`current_stage_remaining_millis` is a fresh positive forecast for that frame.
The `stage_allowance_millis` map covers every stage exactly: `waiting_for_guard`,
`prefix_validation`, `native_restore`, `suffix_execution`, `suffix_validation`,
`assembly`, `full_verification`, `plugin_verification`, `boundary_checks`,
`local_import`, `upload`, `readback` and `sidecar_commit`. Assembly includes
archive close/fsync; readback and sidecar commit include source revalidation.
The estimator adds all later allowances with checked arithmetic. It never
resets an old policy's countdown on a new sample. The elapsed clock remains
the original epoch owner's authenticated PID 1 start throughout delivery.

Preparation emits `claim.json`, `fleet-plan.json`, `event.json` and a durable
`status-estimate.json` using the original raw plan as a lossless base. Earlier
claims move into `capped204205_history`; all unrelated owners, gates, failures
and pipeline history remain byte-value equivalent. Status publication delegates
to the existing reviewed conditional publisher, authenticated readback and
durable receipt writer. The binding remains operational metadata only.

A downstream actor requires its actual launch command, PID/IID, PID 1 history,
origin launch and independent evidence. The producer must have naturally exited
with the exact private V4 continuation receipt before a downstream handoff is
accepted. Keep all downstream actors in subsequent capture specs, including
terminal actors, so their complete history remains available. Private native or
V4 success does not satisfy independent final archive/current-plugin/boundary
checks and confers no canonical sidecar or archive publication authority.

When no actor remains active, capture requires durable terminal manager events,
no queued jobs or triggers, empty/absent cgroups and no private-root process
references. The existing inactive-status lifecycle additionally validates the
exact latest owned publication, positive fleet inactivity and a fresh complete
race check before its conditional status-only delete, authenticated absence and
durable receipt. It rechecks downstream terminal history and protects newer
owners. A stale model, missing worker or disappeared unit is insufficient.
The existing verified-ready-pair cleanup remains the separate completion path.

This is source preparation. No positive launch, admission, capability, manager,
guard or future invocation evidence is supplied by this document. Cargo tests,
strict Clippy and release artifact freezing remain pending the campaign's
exclusive Cargo grant; no deployment or operational qualification is claimed.
