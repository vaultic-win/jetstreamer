#191–194 delivery source integration

This branch stages the real native queue, independent verifier dispatcher, gated
same-PID uploader, custody reader and routine publisher. It is not deployed.
No build, test, replay observation, runtime transition or R2 mutation was run by
the integration child. Rustfmt parsing and `git diff --check` passed.

The old `e0946ae7` was only an unwired custody draft. Subsequent changes now:

- Bind exact original producer/controller-rebind provenance, canonical final
  root84239250 and four archive-close markers. Before import they do not demand
  a future batch receipt. After import they validate actual native source/public
  batch semantics, sealed manifest checkpoints and root controller attestation.
- Support the exact naturally terminated controller. Collected or cleared
  terminal fields require a real previously captured exit0 manager receipt;
  missing evidence never becomes a fabricated active controller.
- Stage the independent full/plugin dispatcher and qualified compatible191
  verifier profile. Fresh per-task immutable specs are sealed only when their
  actual coordinated admission is available. Real three-word receipts are
  mirrored into the uploader's accepted directories; no legacy watcher is
  restarted or adopted.
- Give waiting191–194 tasks a real persistent native queue owner. Manager
  PID/IID/start/program/plan and root-private revision history are bound; one
  verifier and one serial sync may overlap only within independent admission.
  Unknown task children fail closed. Narrowly authenticated direct read-only
  systemctl/journalctl clients are observed separately and never become jobs.
- Preserve actual `ROOT/history/state-REV.json` cutoff state. Same-owner later
  head revisions are explicitly post-cutoff transitions and never backdated.
  Failure/replacement/unknown manager state remains an incident. The first
  implementation still isolates a historical active verifier that has already
  become terminal after cutoff instead of inventing its old process liveness.
- Authenticate the uploader's actual same-PID/start/executable transition from
  `sync-verified191` to the exact normal64MiB/concurrency2 sync argv. Its real
  prelaunch and pre-exec admission proofs bind the same observer/completion,
  queue plan/IID, native inputs, full/plugin receipts and capacity claims.
- Compute upload and readback from their own PID/IID-bound journals at cutoff.
  A separately sealed evidence-backed provisional source-revalidation allowance
  stays positive and grows explicitly when overdue. It grants no integrity or
  publication authority. Canonical ready receipt validation remains independent.
- Remove only191–194 from the ordinary replay model after native terminal proof,
  publish supported integer ETA/status payloads through the authenticated Rust
  pipeline path, and preserve original producer elapsed time. Queue upload maps
  to `upload`; readback/source revalidation maps to `readback`; waiting/scans map
  to `verification`.
- Isolate191 metadata failures without suppressing ordinary lane publications,
  private141's independent incident/terminal lifecycle, fleet or successors.
  Exact five-owner controller rebind stays unchanged until the proven191
  transition; its four-owner successor retains every other original binding.
  Memory planning stays dynamic and independent of the unchanged capped186
  five-owner disk envelope.

The parent and executor own current admission/bootstrap and deployment. Before
rollout they must merge this branch onto current account-updates (including the
actual private141 guard-stop/cleanup transition), coordinate the shared modern
build target, run new adversarial and old-profile tests, seal all tools/specs and
policy evidence, and qualify exact sandbox/receipt/readback routes. Fresh event
production and forecasts must use the existing single coordinated cadence.

Actual verification task completion, source/public native batches, queue history,
capacity receipts and R2 ready receipts must come from their real Rust/PID1
writers. These documents and schemas are not permission to handwrite them.
Boundary190–191 through194–195 dispatch stays separate from publication and must
use qualified modern readers before guarded retirement. Growth claims are not
released merely because this source exists or replay reaches its terminal slot.

The persistent manager is intentionally credential-free and network-isolated.
Only separately admitted exact sync services receive the fixed R2 envfile.
The84GiB additional capacity envelope protects2GiB queue/short dispatcher,
64GiB sole verifier,16GiB possible compiler and2GiB overlapping uploader, in
addition to prior resident planning and reservation ceilings. The old OS claims,
explicit other pending OS growth and bounded evidence allowance remain protected.
The verifier's scalar read-only home floor never substitutes for live replay
growth reservations, century floors or guards.
