# Epoch 233 first-root adapters

This source adds `admit-first-root233`, `capture-first-root233`, and
`status-publish-first-root233` to the Rust R2 tool. Each takes a sealed spec or
model through the existing `SPEC --spec-sha256 SHA --self-sha256 SHA` interface.
There is no launch, stop, archive publication, or canonical sidecar operation in
these adapters. Status publication uses the existing authenticated conditional
publisher and readback, and the existing inactive-status lifecycle recognizes
the exact new owner.

The closed profile uses the existing node `d0182812`, worker `88581898`, generic
standalone guard `044ccba7`, and deployed observer `78dc39c3`. It records only
slots 100656000 through 101087369, after bootstrap 100655540 and 459 warmup slots.
The 431370 output slots leave 630 slots of epoch 233 uncovered. Natural parent
exit, a producer manifest, and an independent reread remain distinct gates. The
generic `66019977` reader can reread this exact private prefix after separate
scan admission; the new code does not impersonate that reader, run the complete
epoch plugin, promote the runtime, or publish the archive.

`private_prefix.rs` contains reusable validation for exact command identity,
original invocation clocks, independent monotonic slot rates, sidecar-inclusive
ETAs, private growing-file metadata, and capture census preservation. Only
`first_root233` selects a new profile. Existing 209/210 candidate policies and
existing live 223/225 launchers retain their own closed rules.

The runtime unit is `horizon-qualify-233-first-root-602556d-v1.service`; its private
root is `/home/ubuntu/.jetstreamer-private/qualification-233-first-root-602556d-v1`.
The four child directories `ledger`, `scratch`, `output`, and `receipts` are owned
by UID 1000 with mode 0700. Admission requires scratch/output/receipts to be empty
and a private, digest-matching `ledger/genesis.tar.bz2`. An occupied generation
must be preserved. Admission checks cached snapshot metadata and reuses the
hash-bound CLI barriers and native successes; it does not repeat snapshot tests
or read the snapshot body.

The exact dormant node command is built by `first_root233::command()`. The source
profile's `scope()` and `environment()` are authoritative for all fixed policy
fields. The CPU assignment is **8–15** for both `AllowedCPUs` and `CPUAffinity`.
This supersedes the initial preparation artifact's 0–7 template. SOLANA, Rayon,
historical PoH, and Tokio thread settings are each 8. Capture checks raw systemd
properties, actual copied-worker digest and PID lifetime, actual worker affinity,
effective cgroup cpuset, page-rounded memory limits, task limit, and CPU quota.
The copied worker must be `bound-worker/historical-worker` beneath this root's
scratch. LimitFSIZE is 128 GiB; TasksMax is 512; the runtime bound is 72 hours.

The trial reservation is 471832246272 bytes: 300 GB scratch allowance, 128 GiB
output allowance, 32 GiB stopping/drainage allowance, and 32 MiB metadata. Scratch
is an experimental allowance, not a separately enforced quota or a proven peak.
The whole-tree guard threshold is 437438953472 bytes. Let B be the larger of the
qualified century floor plus protected remaining growth, every inherited guard
floor, and 2 TB. Initial free space must cover B plus the whole reservation, and
the new guard free-space threshold is B plus 32 GiB. Sampled stop thresholds can
overshoot; a successful exact guard proof remains mandatory.

The separate neutral-capacity memory mode protects the original live native 223
480 GiB available-memory floor, all remaining producer and independent guard hard
growth, the candidate's 225 GB cap, and 2 GiB for its new guard and one metadata
helper. It authenticates the existing shared floor component once. Both complete
resource brackets are retained; the maximum disk and normalized hard-memory
obligations must fit every sampled and actual availability value. Identity and
static cap comparisons stay exact. The live floor applies while the genuine
original 223 owner remains active. After it terminates, the shared positive
release proof must establish the exact original launch/IID and PID1 terminal
outcome, no pending replacement or trigger, an empty cgroup, no root process
references, and preserved failure history. Only then does this profile use the
host baseline. Both brackets and their frozen policies retain the full proof;
recomputation revalidates it without another live scan. Absence alone grants no
release, and the existing closed 209/210 policies retain their own rules.

The roster comes from neutral typed legacy accounting plus authenticated capped
204/205 peer frames and observer registration. There is no three-owner or fixed
lane-count serialization rule. A genuinely qualified capped peer may remain
live while 233 is admitted after a clean expanded-fleet observation. Every live
owner needs an unchanged invocation, a full coordinated window of at least 1800
seconds, below-stop worker VMAs, no hard-memory event, and acceptable host
pressure. Unknown, unresolved, or downstream peers without a qualified resource
envelope still fail closed. A valid later observation and full capacity proof
are required before another experimental increment.

The qualified neutral core's `combined_limits` result already contains static
producer/guard properties and kernel caps. Changing memory charges are recorded
separately as remaining growth; no new cap normalization or adapter is needed.
This source preserves exact cap comparisons. It reuses the reviewed
`bracketed_requirements` and `bracketed_fit` helpers from 069bdebf after separately
recomputing complete 233 disk and memory policies, retaining both original
complete policies and every availability minimum. Consolidate the real capped
admission bracket wiring from the repair branch before the one shared production
build. Preserve all raw frames, changing memory charges, actual guards, and
complete-path growth claims during that integration.

The admission spec contains `schema: jetstreamer-first-root233-admission-spec-v1`,
`resources` (the neutral observer/fleet/protected_guards object), `readiness`
(a bound immutable JSON file), and `output`. The output must be `admission.json`
in a root-private `/var/lib/jetstreamer/horizon-first-root233-admission-*`
directory. Readiness uses schema `jetstreamer-first-root233-readiness-v1`, all
fixed `scope()` fields, all denied-authority fields set false, and these required
review results and evidence:

- `r2_sha256` is the exact integrated qualified R2 executable digest. Admission,
  capture, and initial status must use that one reviewed generation.
- `source_review_passed`, `disposable_sandbox_passed`, and
  `cpu_assignment_owner_census_authenticated` are true.
- `allowed_cpus` and `cpu_affinity` are `8-15`; `node_rebuilt`, `worker_rebuilt`,
  `observer_rebuilt`, `native_snapshot_tests_repeated`, and `producer_started`
  are false.
- `source_review`, `sandbox_proof`, and `cpu_assignment_evidence` are distinct
  hash-bound immutable review artifacts. They must come from the real qualified
  source/deployment and disposable sandbox workflow, not invented pass flags.
- `guard_static_validation` contains the unchanged guard's exact
  `--validate-plan-only` result for this unit, with its self digest, zero samples,
  validated true, protective_guard_proven false, and replay_launch_authorized
  false. Static acceptance is not an actual first-fire proof.

The capture spec uses schema `jetstreamer-first-root233-capture-spec-v1`, bound
`admission`, `guard`, and `guard_plan`, and `output`. Its output is `launch.json`
in `/var/lib/jetstreamer/horizon-first-root233-capture-*`. First start only a
freshly admitted unit. Immediately bind and seal its actual guard plan using the
real IID, B-plus-32-GiB floor, exact root and tree threshold, VMA stop 3500000,
and receipt directory
`/var/lib/jetstreamer/horizon-233-first-root-guard-receipts-v1`. Use no bounded
canary, target-stop, measurement, or native-main exemption. The protective
service is `horizon-first-root233-protective-v1.service` (root oneshot, 1 GiB,
one CPU, 256 tasks, 90-second start timeout); its matching timer must be active.
Capture requires a genuine completed first guard fire and PID1 history. Stop
only the new invocation if that proof fails; preserve its evidence.

Root metadata helpers need the real capabilities required to traverse the
user-private ancestors and read another UID's `/proc` executable. Prove those
reads in the disposable sandbox; do not relax private directory permissions.
Charge and enforce each helper's 1 GiB ceiling, and allow only one additional
metadata helper concurrently with the guard. The node itself retains an empty
capability set and writes only its exact private root.

Register the real `DiagnosticClaim` in the existing fleet plan, preserve its
predecessor/history, and use the same-sample `admission_transition_guard` path.
The next normal observer includes the exact actual IID for both controller and
producer, this whole private root, range `233-233`, and worker basename
`historical-worker`; retain all other rows and the deployed observer executable.
The parent owns the single observation cadence and operational sequence.

The status model uses schema `jetstreamer-first-root233-status-model-v1`, mode
`launch-event` or `observation`, bound `observer`, `fleet`, and `launch`, a nested
`estimate`, nonempty `estimate_basis`, nonempty bound `estimate_evidence`, an
`estimate_receipt`, and `receipt_directory`. The estimate receipt is
`estimate.json` beneath `/var/lib/jetstreamer/horizon-first-root233-status-*`.
The nested estimate requires positive initialization milliseconds, a finite
positive fallback slots/second best guess, and positive millisecond allowances
for every stage listed in `private_prefix::DOWNSTREAM`, including compatibility
repair, native restart, suffix, assembly, all independent checks, upload,
readback, and canonical sidecar commit. Bind real planning evidence and disclose
uncertainty; RuntimeMaxSec is not evidence of completion speed. Launch events
read bounded actual-owner journal progress. Routine updates use the existing
coordinated observer. Warmup execution uses wire phase `replay`; restoration and
qualification use `verification`. Terminal prefix progress retains all downstream
allowances. Frozen payloads reproduce the original PID1 start through a captured
monotonic/UTC anchor and cannot reset elapsed time at a later poll.

Source-only preparation has not run Cargo, touched the target, sampled resources,
started a unit, or mutated R2. After the parent explicitly transfers the build
lease, proposed scoped QA is:

```text
CARGO_INCREMENTAL=0 cargo test --release -p jetstreamer-r2 -j2 first_root233 -- --nocapture
CARGO_INCREMENTAL=0 cargo test --release -p jetstreamer-r2 -j2 private_prefix -- --nocapture
CARGO_INCREMENTAL=0 cargo clippy --release -p jetstreamer-r2 --all-targets -j2 -- -D warnings
```

The new fixtures reject identity replacement, restart, CPU/cap expansion,
missing/failed guard evidence, lowered inherited floors, omitted hard growth,
unsafe bracket maxima, incomplete expanded observations, counter resets without
an independent slot window, backdated/reset clocks, missing recovery/delivery
allowances, and archive/sidecar authority. Positive fixtures cover real private
scope, an expanded typed roster, permitted changing obligations that fit both
brackets, worker binding, kernel rounding, launch/observation clocks, warmup,
terminal downstream estimates, and absent/growing private output.

Before production: consolidate the shared capped bracket repair, run scoped
and appropriate regression QA, capture source/build closure, independently review
and seal the exact R2 deployment and plans, prove the disposable sandbox and
outer guard validation, obtain fresh complete-fleet admission, capture the actual
launch and first guard, register it and publish the genuine initial status.
The CLI barrier and cached native passes remain reusable. Partial-prefix reread,
complete-epoch compatibility, full/current-plugin/boundary gates and publication
remain independent and unqualified.
