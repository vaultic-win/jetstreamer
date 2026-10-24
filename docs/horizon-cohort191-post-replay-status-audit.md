# Epoch191–194 post-replay status audit

This audit uses the accepted2026-10-23 21:56 sample and immutable deployed
source/receipts only. It makes no new resource/replay observation, launch,
runtime change, R2 mutation or archive-readiness claim. The22:26 refresh is
outside this source task and remains the parent's responsibility.

## Accepted evidence and current estimate

- Observer: `/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T215600Z.json`,
  SHA-256 `643fb88e2665d9871e0e1407cda40e8ca1ff7b4d9605734d5c3fafc214931e00`.
- Fleet: `/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261023T215600Z.json`,
  SHA-256 `afeb19655480947a7ec07031734340e341beeaf2d483f4715d62761ae0c83dc2`.
- Same-cycle model SHA-256:
  `665e596e07977fd31bc42a17ed8600d32c6adffe6e77548aed495c9f1f1ad82d`.
- Same-cycle estimates SHA-256:
  `dd26a1feca265b94fca87b84cb154d05e045282c1661f7d941cad3967f22b2a0`.
- Routine plan SHA-256:
  `8920f277679919f8c0d3e15163142003f9a7183d1878f265a5153f24728bf75d`.

The exact producer is
`jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service`,
IID `ea93199ed2fa470d99de248c2a10b246`. Its controller is
`jetstreamer-epochs191-194-target5-controller-v2-r2.service`, current IID
`c741f57764384e07a08484e6451f8f0c`. Controller-rebind proof
`/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json`
has SHA-256 `a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2`.
The original producer and clock were preserved when that controller changed.

At21:56 the producer was at84205000, with terminal84239999 and a qualified
2.822306096289095 slots/second rate:34999 slots remain. The accepted model
adds a common12,401,000ms replay projection to12/24/36/48hour downstream
allowances, yielding55,601,000 /98,801,000 /142,001,000 /185,201,000ms for
191/192/193/194. These are the *existing accepted planning estimates*, not a
new sample or measured downstream stage durations. All four objects were
authenticated, current and bound-live in the saved fleet.

The source cohort is v1.6.15 with bootstrap82511783, output starting82512000,
and final epoch slot84239999. Its final independently supplied root checkpoint
is84239250 (not84239999);749 later archive slots remain after that checkpoint.
Both complete span and all manifest root obligations matter. Never invent a
canonical checkpoint hash at the epoch's final slot.

## Exact deployed pins

The21:56 routine ran
`/usr/local/lib/jetstreamer/horizon-epoch141-eta-risk-tools-20261023-v1/jetstreamer-horizon-routine-cycle`,
SHA-256 `5c042c57a3fb50f5657f4a46692e7cbbf7716f0ae5acec0f918404a1af9563ae`.
Its legacy R2 reader is
`/usr/local/lib/jetstreamer/horizon-original141-capped-root-reader-20261023-v1/jetstreamer-r2`,
SHA-256 `98d7e79faa62d8250d307f8fcc3b7dd2bd14f0e67424d4c8eced429663ac5d86`.
The v5 estimator is
`/usr/local/lib/jetstreamer/horizon-status-v5-20261020-v1/jetstreamer-horizon-status-estimate`,
SHA-256 `df286b7dd2df14e30203b780d4cfcbd9a565505f671dc07f5a82e44fe8c93e76`.

The exact controller source is
`/usr/local/lib/jetstreamer/controller-epochs191-194-target5-20261016-v2/adaptive-root-cohort-sweep.py`,
SHA-256 `62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e`.
The existing deployment
`/usr/local/lib/jetstreamer/deploy-epochs191-194-target5-20261016-v1`
binds node SHA-256 `a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65`,
worker SHA-256 `9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893`,
and preflight SHA-256 `8e16ef3a6f8ae1b2ea3614fbafcb18be34136a8c976e63a386c0fc7c176ce6d0`.
The manifest fingerprint is
`sha256:0294b1813c7d9cdd3266af2705602e1e2a8920d2159944e0a26b498f58f653f9`.

## Current support stops at replay

`routine_cohort191.rs` qualifies only the193-terminal-to194-terminal replay
model change. Ordinary routine validation and v5 estimation still require a
live, stable zero-restart producer/worker and a qualified replay rate. Worker
exit, finalization or producer collection cannot be repaired by retaining an
old rate or relabeling the old ordinary status.

There is **no currently tested/pinned191 post-replay status route**:

- `cohort_finalization::{scope,handoff_scope}` has exact216–219,160 and198
  profiles, not191–194.
- `pipeline_status::Binding::validate` permits controller handoff only for its
  existing exact origins. Its UID1001 receipt-directory exception is similarly
  restricted to160/198/144, not191–194.
- The routine has no191 pipeline profile, transition, finalization proof,
  post-replay estimate publisher or successor/completion binding.
- Actual-importer namespace parsing supports
  `jetstreamer-root-import-...-eFIRST-LAST-SEQUENCE.service`, but that alone is
  observational scope parsing, not authenticated191 provenance or a live claim.
- Legacy full/plugin watcher status readers cover qualified160/198 children;
  a range watcher with no actual matching child is never a191 verification owner.

At21:56 the full verifier `jetstreamer-horizon-audit-epochs182-200-v5.service`,
plugin watcher `jetstreamer-horizon-plugin-receipt-watcher-shard-e-v5-fsync.service`,
and boundary watcher `jetstreamer-horizon-boundary-audit-181-200-v7-fsync.service`
were all **failed**. No191 upload/readback owner appears in the saved fleet.
This is existing evidence, not a fresh failure observation. Their old invocation
IDs must not be adopted as healthy future owners. Qualified repair/dispatch is
needed; the existing12hour increments are not proof those stages are running.

## Required terminal-to-sidecar transition

1. Authenticate exact last-slot/root evidence and native producer lifecycle.
   A missing worker/rate is not success or inactivity. While the actual parent
   is still closing/fsyncing/hashing the complete source cohort, bind it as
   `producer-finalization`, wire phase `verification`, with its original clock.
   Do not require a finished batch receipt before representing genuine active
   archive close; do require actual native terminal/checkpoint/close evidence.
2. Once all four private archives and the v2 committed source-batch receipt
   are sealed, authenticate the controller's pending import ownership. Capture
   the exact root-owned state and full source-receipt semantics at that event
   or a normal coordinated sample. Do not read mutable current state here and
   backdate it into21:56. The future batch SHA and path are not yet authenticated
   by the saved sample and must not be invented.
3. The controller serializes import. It creates
   `jetstreamer-root-import-e191-194-t5-20261016-v2-r2-e191-194-SEQUENCE.service`
   with `--recover-staged-cohort-only`, exact manifest/fingerprint and committed
   source receipt. Bind the actual sequence, native IID, command and public
   private root `/home/sol/.jetstreamer-private/epochs191-194-target5-20261016-v2-import`.
   The controller rehashes source archives before import and public archives
   when capturing completion; budget those scans and transaction recovery,
   not merely a filesystem rename. Importer success remains `verification`.
4. Import completion needs the bound public batch, source/public receipt
   semantic equality, no pending batch marker and root controller completion
   attestation. The importer is RemainAfterExit=yes and is subsequently stopped
   by its controller after durable attestation. Preserve evidence before that
   lifecycle is collected; do not retain its old live claim afterward.
5. Dispatch/repair independent full and current-plugin verifiers and bind
   each actual child to the correct epoch, canonical path, bytes and SHA-256.
   Producer checkpoint success, a private checksum, or a sleeping/failed watcher
   is not either receipt. Full/plugin may overlap only under their qualified
   resource and queue policy. Canonical archives are `/home/sol/horizon/epoch-N.jet`.
6. Bind the actual progressive delivery invocation and exact matching full/plugin
   receipts. Use `upload`, then `readback`; estimate readback from its own
   invocation-bound progress, age/stall penalty and throughput. Keep source
   revalidation and canonical sidecar commit as explicit remaining work. Include
   work ahead of each epoch if the qualified coordinator serializes whole syncs.
   Do not assume191→194 commit order without qualifying/enforcing that topology.
7. Adjacent boundaries normally gate *local retirement*, while upload requires
   full/current-plugin receipts. Keep boundary repair visible but add it to the
   sidecar critical path only if the actual chosen publication policy requires
   it. Do not invent a circular neighboring-sidecar upload dependency.
8. On authenticated ready pair, use normal exact status completion cleanup.
   If a failure leaves no actual producer, repair/task or downstream owner,
   use only the separate authenticated inactive lifecycle and retain open repair.
   Keep an active downstream claim represented; never delete merely because
   replay ended. Neither a missed ETA nor absent rate proves inactivity.

The routine transition must atomically remove only191–194 from the ordinary
replay model/observer census, add four evidence-bound pipeline entries and keep
the other seven ordinary epoch estimates,141 profile, full fleet, and single
cadence intact. Validate ordinary and pipeline completion receipts separately,
carry the new optional profile into the successor, and isolate a191 metadata
incident so it does not suppress unrelated statuses. Preserve the genuine
predecessor and shared2156 evidence; no healthy restart or duplicate sampling.

## Staged model candidate and qualification work remaining

`cohort191_delivery_model.rs` is a pure, source-only forecast candidate. It is
not wired into any publisher, observer or routine. Its v2 input requires the
exact four epochs, explicit remaining finalization/import work, full/plugin
queue budgets, optional publication-boundary policy and separate upload,
readback and source-revalidation/sidecar budgets. It models full/plugin overlap
and a qualified serial whole-sync lane; all durations are checked integer
milliseconds. The later authenticated publisher must validate every stage,
owner, measurement and ready-pair proof before supplying these arithmetic inputs.

For each epoch, after shared close/import work, verification availability is
`max(full remaining including queue, plugin remaining including queue)` plus
any truly required boundary gate. Sync starts at the later of verification
availability and preceding committed whole sync, then adds upload, independent
readback and final revalidation/sidecar work. This is a critical-path estimate,
not mechanical countdown of the old12/24/36/48hour allowance. Active stages use
fresh measured remaining work; queued budgets are explicitly provisional
planning policy and must be revised for dispatch or contention changes.

Tests cover shared gates, uploader/readback serialization, stalls increasing
later estimates, ready-pair-only zero, invalid phase order, missing/reordered
epochs and overflow. Only rustfmt and diff checks have run; **no build/test or
deployment qualification is claimed**. After coordinating modern-target
ownership, run the observer library's `cohort191_delivery_model::tests`, full
observer/R2 tests and strict Clippy when the actual profile integration exists.
Then build/seal a new exact191 R2 reader/publisher and routine coordinator; do
not replace existing immutable packages or masquerade as198. Qualify its exact
live and denied-owner/check-only paths in the matching sandbox, bind a fresh
coordinated observer/fleet and native event evidence, and let the parent make
the explicit immutable metadata handoff. No currently deployed package can be
named as that future tested publisher until those gates pass.

## Source integration staged after `e0946ae7` (not yet built or deployed)

`e0946ae7` itself contains the pure forecast and an unwired custody draft. The
subsequent source chunk adds an opt-in `cohort191_delivery` routine profile,
closed native custody validation in the R2 fleet and numeric pipeline publisher,
and the compatible independent per-epoch verifier route. These are source
candidates until the parent qualifies and seals them; no current unit, timer,
R2 object, replay claim, or healthy owner is changed by staging this code.

The optional routine profile binds `publisher`, the initial `terminal_event`,
and an exact `/var/lib/jetstreamer/horizon-cohort191-delivery-events-*`
`event_directory`. It consumes `event-YYYYMMDDTHHMMSSZ.json` from the same existing
coordinated observation cutoff. An accepted native final-root/four-close event
removes only191–194 from the ordinary model/config census; the expected ordinary
list becomes152,153,155,156,183,184,185. Successor serialization preserves the
profile and derives the next event name from the next scheduled sample, never
reusing the previous ETA as a fresh observation. The existing publishers and
pins for141/144/160/198 are retained. The new R2 reader owns only191 metadata and
the provisional/final fleet reconciliation that must understand its claims.

Missing or invalid current191 custody produces a private no-clobber incident.
It does not stop the seven ordinary publications, private141 publication, or
fleet/successor work. An accepted event binds exact original replay receipts,
controller-rebind proof, original PID/IID, canonical root84239250, four archive
closes, current artifacts, phase-owner manager start, and the original producer
clock. Before import it does not demand a future source batch. After import it
checks the actual native source/public batches, all manifest checkpoint hashes,
member root summaries, source/public semantics, and controller completion
attestation; no handwritten batch or ready receipt is admitted. Historical
source archive files may disappear after import, and authenticated ready members
may retire, without requiring their old private/public artifact to reappear.

The normal three-word full/plugin receipts are checked at the existing uploader
receipt directories, with deployed verifier and wrapper hashes. Zero ETA requires
a canonical durable whole-object-readback R2 receipt, rather than a plan flag.
Direct native upload and readback forecasts must reproduce their own phase's
PID/IID-bound progress rate and stall age at the fixed sample cutoff. Upload
acknowledgements never substitute for readback progress. Source revalidation tail
estimation still fails closed until its separate progress/policy source is
qualified. No terminal timestamp is fabricated at84239999: the trusted final
root remains84239250 and the archive can close after its skipped tail.

### Independent dispatcher contract

The parent owns the new `cohort191_dispatch.rs`; no failed legacy watcher is
restarted. The custody module exposes:

```rust
pub(super) fn dispatch_import_check(
    source_batch: &Bound,
    public_batch: &Bound,
    materialized: &BTreeSet<u64>,
) -> Result<serde_json::Value>
```

Pass the requested epoch(s) in `materialized`, so later tasks do not require an
already independently verified/retired predecessor to remain local. This helper
checks immutable deployment/controller-rebind inputs, native v2 batch gates,
all four source/public archive-digest and checkpoint semantics, current requested
public archive identities/checksums, public transaction-marker absence, and the
current root controller's exact completion attestation. It rechecks state and
controller before returning. It grants no launch, publication, R2 mutation or
retirement authority and requires no imagined live verifier before PID1 launches
one. Its returned receipt binds the actual source/public paths and digests.

The independent runner profile is
`horizon-verify-canonical-pair-dev-samjohnson191-v1` with:

- Exact epoch191–194, `/home/sol/horizon`, and state
  `/var/lib/jetstreamer/horizon-cohort191-canonical-verification-20261023-v1/epoch-N/{full,plugin}`.
- Actual services `horizon-full-verify-N-native191-20261023-v1.service` and
  `horizon-plugin-verify-N-native191-20261023-v1.service`.
- Planned sealed runner
  `/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/jetstreamer-horizon-verify-pair`.
- Existing qualified compatible198 readers (`verify_archive` SHA
  `5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574`;
  `horizon_pipeline` SHA
  `e20892a111f8e26c8e25561a939eaf171771789753059100510c936d92092137`).
- Independent before/after whole-archive hashes, both full checks, current plugin
  verification, exact actual service capture, and durable real receipts mirrored
  into the uploader's existing accepted full/plugin receipt directories.

The runner authenticates its exact archive, sidecar, reader, service, plan and
fresh observer. The dispatcher must independently call `dispatch_import_check`
and preserve its native source/public provenance before launch. It must bind the
runner's newly sealed SHA into the uploader's accepted wrapper allowlists. The
runner's1TiB read-only home floor is not a growth-reservation proof or a reduction
of replay guards or century floors. Its one64GiB verifier plus64GiB reserve check
also does not replace the dispatcher's capacity receipt, current RSS reservation
ceiling, concurrent compiler reservation, OS statfs and bounded state/log checks.

After191 terminates, `memory_concurrency_target` remains independently computed
from the actual current owner count and RSS census. The unchanged five-owner
`capped186_budget` can fail closed without invalidating that four-owner memory
envelope; it must not be fabricated by retaining191 as a fifth live replay.

### Gates still required before rollout

No builds/tests have run for this source chunk. Coordinate the shared build
target first; run the meaningful native-terminal, claim-census, progress-rate,
verifier-profile and old-profile regression tests, then seal and sandbox the
exact new CLI routes. Qualify the parent's independent dispatch and serial upload
configuration, actual importer/source-batch capture, all receipt-directory/hash
allowlists, fresh same-cutoff event generation, queued ownership coverage, and
source-revalidation tail estimates. A waiting plan is not an active verifier.
Boundary190–191 through194–195 dispatch stays separate from sidecar publication
and must use qualified modern readers, rather than the failed legacy watcher,
before guarded local retirement is enabled. No512GiB remaining-growth claim is
released until the parent authenticates the completed-cohort transition.

The import controller is allowed to return naturally once `all_complete()` has
rehash-verified the public cohort. Both custody capture and dispatch admission
now accept its exact retained inactive/dead exit0 lifecycle, requiring the same
CID/command, zero restarts, no job/cgroup, real manager start, one trusted PID1
successful-deactivation event, and the exact original controller's native
`all sealed cohorts 191-194 are public` message before that event. Pending import
still requires a live original controller. This does not fabricate an active
controller claim after import.

Before systemd clears or collects terminal fields, the new exact Rust command
`capture-controller-terminal-191 --self-sha256 SHA` can preserve the actual retained
manager properties and those native/PID1 events no-clobber at
`/var/lib/jetstreamer/horizon-cohort191-controller-terminal-20261023-v1/terminal.json`.
It also binds the root controller state digest and qualified deployed reader.
A later collected or terminal-fields-cleared state requires that real prior
capture, the same state digest, re-observed terminal history, and no replacement
job/cgroup. Missing capture, changed invocation, restart, failed status or
unexplained disappearance fails closed. No such command has been executed as
part of this source work.
