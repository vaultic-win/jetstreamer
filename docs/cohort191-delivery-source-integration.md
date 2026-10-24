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

## First post191 transition repair, source-only

The follow-up source adds `capture-terminal191 PLAN --plan-sha256 SHA
--self-sha256 SHA` to the fixed native R2 tool. Its immutable
`jetstreamer-cohort191-terminal-collection-plan-v1` binds the actual program,
source_batch and public_batch after the native writers have produced them, and
output `/var/lib/jetstreamer/horizon-cohort191-terminal-transition-20261023-v1/terminal.json`.
It has no observer, forecast, speculative resource hash or task admission.
The collector requires the original producer's actual PID1 natural success,
trusted84239250 root and four archive closes, a naturally terminal original
rebound controller, and native root-controller import attestation with all four
materialized archives. It checks native close lengths against imported members,
rechecks original identities and import custody, and publishes a no-clobber
root-private proof with every authority flag false. If PID1 has collected the
controller, its separately captured real exit0 receipt remains mandatory.

The offline routine entry is:

```text
jetstreamer-horizon-routine-cycle CURRENT_PLAN --plan-sha256 ACTUAL_SHA --self-sha256 ACTUAL_SHA --prepare-next-delivery191 HANDOFF_SPEC --handoff-sha256 ACTUAL_SPEC_SHA
```

The separately sealed `jetstreamer-cohort191-routine-handoff-spec-v1` contains
`profile` with the actual publisher Bound, terminal_event Bound returned by the
collector, and the fixed event-directory namespace; publication_authorized,
replay_launch_authorized and r2_mutations are all false. This deliberately uses
the observer-independent terminal-transition proof, not a future complete
queue/status event. The normal plan/receipt readers enforce root ownership,
actual SHA binding and immutable handoff/collection plans. An optional explicit sample_target_utc may postpone a
missed successor only on the original30minute grid; the actual predecessor and
minimum1800seconds remain unchanged. No timestamp is guessed from wall time and
no extra resource observation is taken.

The preparation consumes the last accepted completed five-owner cycle. It
requires exactly152–153,155–156,191–194,183–184,185, unchanged paired owner IDs,
the original191 producer and rebound controller IDs, and the exact four191
members. Only191–194 is removed from observer replay rows, model ranges and
expected epochs. Every surviving row, diagnostic, predecessor, clock and other
profile is retained. A distinct four-owner namespace avoids overwriting the
already prepared five-owner successor. The regular Rust preparation writer
produces the observer/cycle sources and normal sealer plans; it does not seal,
adopt, observe, launch or publish anything itself.

The parent must run the existing native sealer on both generated plans, run the
new sealed routine's normal `--check-only`, then adopt that exact successor
through the existing coordinator/timer lifecycle. Do not leave an already armed
five-owner plan to run after191 has naturally stopped. The genuine queue owner
must exist before any observer cutoff used to publish that ownership; queue task
admissions are supplied only after the actual first four-owner resource and cycle
receipts. No later-born manager or task may be backdated into that cutoff.

Successor preparation now retains the four-owner observer configuration and
applies the same191 effective model before exact census validation. Historical
five-owner rebind evidence remains unchanged; its existing four-owner transform
and current owner checks retain the other four bindings. Dispatcher fresh_owners
is unchanged and continues to require every actor actually present in the fresh
four-owner resource receipt to remain live.

New adversarial tests cover observer-independent terminal proof, foreign or live
owners, absent/partial imports, mismatched native close lengths, collected
controllers lacking their real terminal capture, future-observer injection,
missing/duplicate or rebound survivor rows and exact preservation of diagnostics
and large counters. One test exercises the real observer-config gate: the stale
five-owner config fails against the four-owner model and the precise transformed
config passes. These new tests and this follow-up source have not been compiled
or run; only rustfmt parsing and whitespace checks have run while141 status holds
the shared target. The successful942-test/release baseline above remains separate.

## Guarded local retirement audit, source-only

Keep the current191–194 defer and retain all four canonical pairs until the
whole cohort is ready and a separate boundary/retirement route is qualified.
No early191 retirement or physical capacity relief is claimed by this branch.
The normal boundary watcher currently covers101–181; its existence is not proof
of any190–191 through194–195 boundary.

The source obligation is more precise than an unconditional four-file hold:

- Initial queue admission and the new terminal collector require all four actual
  canonical archive/sidecar pairs and the complete native import attestation.
  Preserve that actual terminal proof; recollecting it after retirement would
  fail its all-four materialization gate.
- Later dispatcher/sync custody checks materialize their selected epoch. Current
  metadata capture materializes exactly the working/non-ready epochs and records
  local identity only for current claims. Ready members instead require their
  canonical durable whole-object R2 receipt. The follow-up now explicitly matches
  each such receipt's epoch, digest and length to its native public-batch member;
  a historical receipt for a different payload cannot replace local custody.
- Native batch receipts, sealed root manifest, original root/four-close and PID1
  terminal evidence, collected-controller exit capture if needed, root-controller
  state/receipt attestation, queue history/intents/launches, full/plugin receipts,
  ready receipts and original status provenance must remain. Local payload
  retirement does not authorize deleting any of those proofs or changing the
  terminal controller's retained evidence. No automatic queue restart/replay is
  permitted; startup intentionally insists on its original all-four custody.
- Once all four are ready, the real queue naturally completes. A later all-ready
  capture must omit the now-terminal manager as a live claim and bind the four
  real ready receipts; it must not retain an invented live queue owner merely to
  keep an old capture plan usable. Normal authenticated status cleanup remains
  separate. All-ready custody can then validate retained import metadata without
  opening a retired canonical payload, but that route still needs qualification
  with actual retired-file fixtures before any early-retirement exception.

The required boundary set is190–191,191–192,192–193,193–194,194–195. The current
native `jetstreamer-horizon-verify-pair` profile covers independent full/plugin
verification only and cannot be relabeled a boundary verifier. The relevant edge
reader is `archive_boundaries --verify-pair LEFT RIGHT`, whose source checks
contiguous epoch/slot ranges, parent slot/hash and the initial anchor. Its actual
newly built sealed executable and large-update decoding compatibility must be
qualified independently; no future boundary SHA is supplied here.

The next implementation after the current terminal-transition tests is a narrow
Rust five-pair boundary dispatcher/receipt writer. It must authenticate exact
left/right files or separately authenticated restore scratch copies, both
matching full receipts and actual compatible reader/wrapper hashes, real native
service identity and successful edge result, unchanged identity/digest afterward,
and fsynced no-clobber four-word receipts. Each receipt is
`LEFT_SHA RIGHT_SHA BOUNDARY_READER_SHA NATIVE_BOUNDARY_WRITER_SHA` at
`boundary-L-R.ok`, matching the normal progressive retirement parser. Neighbors
190 and195 require their own real full evidence;191-only full profiles cannot be
borrowed for them. If a neighbor is absent, use separately admitted authenticated
restore into exact scratch, preserve that receipt and prove the restored digest.
Do not infer a missing neighbor or cross-host boundary from a canonical sidecar.

Run those boundary scans serially after the cohort's full/plugin tasks are
terminal, or qualify an explicit additional concurrency/resource claim; the84GiB
queue/verifier/compiler/uploader envelope is not spare boundary capacity. Keep
credentials/network out of the boundary reader. No watcher range is broadened by
this audit. Boundary receipts must exist before removing either local member
needed to produce them.

Whole-cohort retirement then requires four independently matched full/plugin and
canonical authenticated R2 ready receipts, all five adjacent-boundary receipts,
normal current remote archive/sidecar re-observation, exact gate-tool allowlists,
and the existing shared local-mutation lock. Use the normal Rust progressive
`--check-retirement-only` policy preflight for each explicit epoch before the
separately authorized `retire-local` path; preserve normal defer handling until
that exact guarded transition is approved. The preflight performs no child/R2 or
local removal. None of these boundary/retirement actions has been run here.
