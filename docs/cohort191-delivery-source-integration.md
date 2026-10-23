#191–194 delivery source integration

This branch stages the real native queue, independent verifier dispatcher, gated
same-PID uploader, custody reader and routine publisher. It is not deployed.
The initial integration handoff was source-only. The later qualification below
is authoritative for compilation/tests; no replay observation, production runtime
transition, deployment or R2 mutation was performed by this integration child.

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


## Qualified source baseline,2026-10-23

Source `9e523697` includes parent `ce5aaf79` through merge `053cbf18`, preserving
all native191/141/209/227 module and CLI registrations. Its follow-ups are
`b9460aaf` (custody/PID-pipeline imports and identity serialization), `35eaa5e6`
(verifier borrow and anonymous PrivateTmp client capture) and `9e523697`
(strict Clippy fixes with explicit parsing of string PID1/journal PIDs).

Four default suites passed942 tests with64 ignored: observer library110/2,
R2 executable613/46, routine executable203/16, native verify-pair16/0.
Attempt3 ran all four; after the final R2-only lint changes, attempt4 reran the
full R2 suite successfully. Strict selected-target Clippy with tests and
`-D warnings`, workspace `cargo fmt --all -- --check`, and three release builds
passed. This is targeted native orchestration/default-profile coverage, not a
claim that the entire workspace feature matrix or ignored native probes ran.

The final unit was
`horizon-cohort191-integration-qualification-20261023-v4.service`,
IID `403f8e13a880444cae815d48c10b9851`, naturally completed at23:54:06UTC with
MainPID0, active/exited, Resultsuccess, ExecMainStatus0 and peak2970308608bytes.
It ran as UID/GIDsol with CPU200%, MemoryHigh12GiB/Max16GiB, swap0,512tasks,
PrivateNetwork, PrivateTmp, strict/read-only source/home and only the approved
Cargo cache/shared target writable. The1800second bound remained in force.
Attempts1–3 retain their failed compile/lint evidence; no failed attempt was
rewritten as success. Actual manager/journal captures are under the isolated
integration worktree's `.ops-cohort191-integration-qualification-20261023-v1/`.

All Cargo commands used offline/locked resolution, two jobs, incremental0,
dev/test/release debug0, DOCS_RS=1 and target
`/var/lib/jetstreamer-builds/readback-progress-20261022-v1`:

```sh
cargo test --offline --locked -p jetstreamer-horizon-observe --lib -- --test-threads=2
cargo test --offline --locked -p jetstreamer-r2 --bin jetstreamer-r2 -- --test-threads=2
cargo test --offline --locked -p jetstreamer-horizon-observe --bin jetstreamer-horizon-routine-cycle -- --test-threads=2
cargo test --offline --locked -p jetstreamer-horizon-observe --bin jetstreamer-horizon-verify-pair -- --test-threads=2
cargo clippy --offline --locked -p jetstreamer-r2 --bin jetstreamer-r2 -p jetstreamer-horizon-observe --lib --bin jetstreamer-horizon-routine-cycle --bin jetstreamer-horizon-verify-pair --tests -- -D warnings
cargo build --offline --locked --release -p jetstreamer-r2 --bin jetstreamer-r2 -p jetstreamer-horizon-observe --bin jetstreamer-horizon-routine-cycle --bin jetstreamer-horizon-verify-pair
```

Actual release SHA256 values:

| Artifact | SHA256 |
| --- | --- |
| jetstreamer-r2 | b1fdded30bfb805dfffed2fbc91e22ef0b8b07c9748d3a1ec870fdd449a08f37 |
| jetstreamer-horizon-routine-cycle | eec4624baba960558a3cae04065b1e8439bded4f07b1bb4f1caf60b5bcc41a3e |
| jetstreamer-horizon-verify-pair | b89641f4bfe5cdd141652cd32905233937439725ca523ec18b66a411460e436a |

The parent separately preserved this tested baseline in its build-artifact seal;
these hashes are not future operational spec hashes or deployment authority.
Review then found a missing first post191 observer transition: the old five-owner
observer configuration cannot survive191 natural completion, while the existing
runtime profile requires a later observer-bound custody event. A terminal-only
collector and offline four-owner preparation route are required before operational
readiness. Work on that repair is source-only until a separately coordinated build
slot; the942-test baseline does not qualify that later change. No owner census is
weakened, and full/plugin/sync remain dependent on real fresh four-owner resources.
