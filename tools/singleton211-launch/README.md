# Full211 held-gate replay source

This is an unbuilt standalone crate staged in the shared checkout for Main
qualification. It implements a full211 controller, the pre-node startup gate,
and current-fleet admission. The fleet/status/cadence adapters remain in a
separate, unapplied source packet. It does not qualify the artifacts or admit a live service.
The successful native211 input test is neither changed nor rerun.

## Layout and integration

The new `tools/singleton211-launch/` directory is already staged. Its library
owns the implementation; the binary delegates to `run_from_environment`.
No shared consumers or guard source have been edited in this integration.
See [runtime-review.md](runtime-review.md) for the current blockers and sequence.

Main must review `/tmp/horizon211-full-launch-source-20261119-v1/integration.patch`
against the current native265-integrated baseline before applying only its added hunks;
do not copy complete overlay versions over another agent's newer edits. New files
under `overlay/jetstreamer-r2/src/fleet/` are part of that patch. The overlay adds:

- The `horizon-singleton211-launch` library dependency to jetstreamer-r2.
- `fleet/singleton211.rs`: complete persisted-handoff validation, exact live
  command/PID/mapped-node checks and same-observation admission transition.
- `fleet/full211_status.rs` and its private archive resolver: definite numeric
  ETA from the original producer clock, canonical root and complete tail.
- `status-publish-full211` dispatch, fleet status acceptance and exact inactive
  status-owner routing. All R2 mutations remain in the existing Rust publisher.
- `tools/horizon_terminal_aware_observe.rs`: one optional `singleton211_handoff`
  field, which admits only the exact full211 diagnostic row. Native211/265 and
  original247–251 paths remain intact. The wrapper now needs an explicit
  `--extern horizon_singleton211_launch=...` from this exact qualified library
  when built directly with rustc. Record its actual extern binding, dependencies,
  features and source in the wrapper provenance; a search-path change is not enough.

The frozen wrapper baseline contains the replacement265 agent's earlier native265
pass-through work. The current shared wrapper has since advanced; preserve its
qualified observer pins and native265 changes when integrating the added hunks.

The separate guard feature packet remains a prerequisite:
`/tmp/horizon211-replay-guard-source-20261119-v1/guard.patch`, SHA256
`3e317b692921f7c58504e1bc2a59d67992c03f5113f41d79d885ddb2c3d3b44e`.
Build the actual retained guard feature union plus `epoch211-singleton-guard`.

## Executable route

Seal the newly built launcher at exactly:
`/var/lib/jetstreamer/horizon-singleton211-launch-20261120-v4/horizon-singleton211-launch`.
Seal the separately qualified guard at exactly:
`/var/lib/jetstreamer/horizon-211-singleton-main-guard-20261119-v1/horizon-standalone-guard`.
The guard SHA is supplied through the immutable reviewed binding and verified
against the source-publication/provenance/qualification graph; no invented
build hash is embedded in this source.

Commands, under Main's independently admitted bounded metadata service:

```text
LAUNCHER inputs SELF_SHA NEW_INPUT_EVIDENCE_DIRECTORY SEALED_CAPABILITY_DIRECTORY
LAUNCHER qualify-guard REVIEW REVIEW_SHA SELF_SHA NEW_QUALIFICATION_EXECUTION_DIRECTORY
LAUNCHER retire-qualification SEALED_CAPTURE CAPTURE_SHA SELF_SHA NEW_RETIREMENT_EXECUTION_DIRECTORY
LAUNCHER admit REVIEW REVIEW_SHA SELF_SHA NEW_EXECUTION_DIRECTORY
LAUNCHER launch REVIEW REVIEW_SHA SELF_SHA NEW_EXECUTION_DIRECTORY
LAUNCHER validate-handoff HANDOFF HANDOFF_SHA SELF_SHA
```

Input evidence paths must be fresh direct children of `/var/lib/jetstreamer`
beginning `horizon-singleton211-input-execution-`; capability destinations begin
`horizon-singleton211-input-capability-`; execution paths begin
`horizon-singleton211-execution-`. The input command completely rehashes the
8,731,506,223-byte snapshot, genesis, node, worker and preflight, then seals their
exact inode/ctime/mtime/size/owner/mode identities with the real native proof.
It runs no Bank and no replay. Admit this bounded read phase separately; it is
outside the short startup clock. Admission and the held gate recheck identities
instead of rereading 8.7 GB during that clock.

Precreate uid/gid1000 mode0700 root
`/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1`
with only `output/` (0700), containing only an empty uid1000 mode0400
`genesis.tar.bz2` bind-mount placeholder. Precreate the root-owned, traversable
`/var/lib/jetstreamer/horizon-singleton211-startup-tokens`. The four new unit
names in source must be unused. Do not reuse prior native211 roots or units.

The persistent service executes:

```text
LAUNCHER gate SEALED_STARTUP_PLAN PLAN_SHA LAUNCHER_SHA
```

It is the actual service MainPID in a finite 225,000,000,000-byte hard /
150,000,000,000-byte high cgroup, zero swap, 512 tasks, 16 explicit CPUs,
1600% quota, no restart and a three-day limit. It opens no node, worker or
snapshot body while held. Its exact mapped image, IID, boot, private sealed
plan, sole cgroup PID, no child process and no descendant cgroup are checked.

The launcher starts the exact full211 guard timer, validates a genuine no-trip
first sample, its unique PID1 start and successful completion in the original
monotonic window, and re-admits the complete fleet before sealing the one-shot
release token. The guard's empty replay-worker list is accepted only by the launcher while the
exact gate is proven held before exec. Whole-root and filesystem protections
are active already. It is not a general zero-worker startup exemption.

The gate independently validates those proofs and execs the existing sealed
node with the same PID/IID. The launcher requires the mapped node transition
before producing its handoff. The node's own source and binary stay unchanged:

```text
/var/lib/jetstreamer/horizon-singleton211-production-node-c17619b16d5d20f0-v1/jetstreamer-node 211 /home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight211-singleton.json --cohort-manifest-fingerprint=sha256:d00f6c8ff2d66ec302aea39267ace8c28931d2602c9f5185c913eb5c96ab667b --snapshot-archive=/var/lib/jetstreamer/horizon-focused-211-complete-span-store8-ca2e38b-v1/snapshot-91151575-xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx.tar.zst
```

The node retains network access for canonical block/root inputs; only genesis
is projected read-only into the fresh output. The selected copied v1.6.16
worker is pinned to `1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41`.
The normal guard recursively tracks its `historical-worker` copy under the
exact full211 root. It keeps the whole-root 471,798,691,840-byte cap and
3,500,000-VMA ceiling, with no bounded or native exemptions.

The original admission has 60 seconds total. Sealing, manager work and first
fire consume that same window; the operator deadline is at most50seconds.
An un-released gate exits when the original deadline expires. A failure after
capturing the candidate IID stops only that exact active invocation. There is
no automatic retry, resource-release, cleanup, upload or archive command.

## Review and qualification graph

Read [protective-stop.md](protective-stop.md) for actual qualification and exact
four-link retirement. The review must explicitly set `operation` to `launch`
or `qualify-guard`; a qualification gate cannot accept a replay release token.

Review schema `horizon-singleton211-current-fleet-review-v1` takes epoch211,
Main acceptance, one controller PID/start-tick/boot, timestamp, safe attempt,
16 distinct `cpu_affinity` integers, and the existing false authority flags.
Bind `guard`, `input_capability`, `fleet`, `observer`, `source_publication`,
`prestart_qualification`, `reservation_ledger`, `century` and `control_units`.

Current booking, fixed auxiliary, century, periodic-control and original
finalization schemas retain the actual native211 admission names and evidence.
No historical 204/205/225/227/223 peer model is copied. Full hard memory caps,
remaining hard growth, host/control reserves, source-bound auxiliary overhead,
periodic controls, conservative remaining disk growth and inherited guard
floors all remain charged. The candidate adds225000000000 memory and
471798691840 disk. No scratch allocation is credited toward those amounts.

The peer adapter also preserves the exact successful native211 terminal owner
and the newly registered native265 live owner. Native peer memory is not
released by this adapter: retain its complete source-bound reservation until
a separately qualified bookkeeping/drain transition removes it. Unknown peer
or pipeline shapes reject. Existing original247–251 replay/finalization and
periodic controls remain supported through the copied current-fleet validators.

Publication schema is `horizon-singleton211-source-publication-v1`, with
fresh fetched account-updates head and eight exact artifact roles: `node`,
`worker`, `guard`, `launcher`, `sealer`, `fleet`, `observer`, `inactive-status`.
Each binds a `horizon-singleton211-exact-artifact-provenance-v1` with complete
actual source/dependency/feature evidence, source_commit and source_files.
The launcher executes the committed-file and remote-ancestry checks before
startup. Main must fetch first and prove actual build-source equivalence.

Prestart schema `horizon-singleton211-prestart-qualification-v1` binds gate,
node, worker, guard, source_publication, launcher SHA and qualification_evidence.
Require true observer-complete-tuple, fleet-running-and-terminal,
inactive-status-exact-owner, terminal-retention, pre-restore-gate-tests,
native-worker-production-equivalence, and actual-first-guard-before-snapshot
acceptance fields as spelled in `admission.rs`; actual_replay_startup_qualified
must remain false. Production admission additionally requires a sealed
`protective_stop_qualification` binding whose capture, journals, generic guard
intent/completion and retirement are semantically validated. The native test success does not itself prove production
worker equivalence. The old worker and harness share Cargo.lock and test-only
runtime differences, but Main must complete the source/dependency/feature audit.

## Lifecycle and ETA

Use the generated guarded-startup-handoff as the one diagnostic launch receipt
for epoch211. The diagnostic claims are the exact unit, IID and root above.
For its first same-observer fleet transition bind that handoff's real
first_guard_sample as admission_transition_guard. The common transition checks
retain prior diagnostic history; the new bridge additionally retains all
pipeline claims and tracked owners, and authenticates the predecessor fleet.

The wrapper's optional singleton211_handoff binds the same file. Add exactly
one observer `diagnostic_replays` row with range211-211, producer_unit and
controller_unit both the full211 unit, both expected IIDs the actual handoff
IID, scratch_path the whole full211 root and worker_executable_basename
`historical-worker`. Remove the retired native211 telemetry row through its
ordinary terminal transition before adding full211: duplicate epoch owners
are rejected. No new routine clock is created; use the existing1800second
cadence. A terminal diagnostic remains explicit and does not stop ordinary
247–251 telemetry; there is no automatic release or archive-success inference.

`status-publish-full211` uses `jetstreamer-full211-status-plan-v1` with the same
model fields as full209, bound to this launch and the accepted fleet/observer.
All eight positive allowances are required: archive_close, boundary,
full_verification, plugin_verification, readback, remote_plugin_playback,
sidecar_commit, upload. The model covers canonical root91583512 plus487tail
slots, exactly432000outputs91152000..91583999. It publishes verification during
initialization and replay only with actual progress, and preserves the original
manager monotonic start. Both launch-event and observation routes retain
authenticated status readback. The inactive-status owner adapter uses the
original exact IID and existing positive terminal/no-owner deletion checks.

## Remaining gates before launch

This child ran no build, unit test, service, runtime/resource observation, Git,
cleanup or R2 operation. Existing sealed native211 evidence was read for source
compatibility review; its proof and running-origin files are root-owned mode0400. Rustfmt parsed the new source and overlay adapters;
diff/patch and manifest checks are recorded separately. Pure tests are authored,
including original-window/forged-first-fire rejection, denied gate callback,
hard-cap arithmetic, booking provenance, source-bound overhead, finalization,
periodic controls, full211 ETA/tail and private archive resolver regressions.
They have not been executed. Main must complete:

1. Integrate disjoint patches and new crate, regenerate the main Cargo.lock
   for the path dependency, publish every required source, and verify fetched
   remote containment plus exact artifact/build/source equivalence.
2. Run bounded locked offline launcher/library tests, relevant r2 fleet/status
   and wrapper tests, and guard feature-on/feature-off tests. Reconcile any
   compilation or fixture findings before sealing. Retain the actual helper
   feature union including native210-small/native227-small.
3. Qualify the actual root/unprivileged sandbox read paths, bind-mount genesis,
   PID1/sealer privileges, first timer fire, expired/missing/wrong token refusal
   and same-PID node exec. The held-gate test must prove node/snapshot work did
   not start before first-fire proof. An empty-worker sample alone is not enough.
4. Exercise the complete saved handoff through the fleet transition, ordinary
   and terminal observation, numeric status and inactive-owner validators; bind
   that actual evidence into prestart qualification. Static flags are not proof.
5. Perform current authenticated input capability, fresh complete capacity
   admission, actual launch/first-fire/exec proof, fleet registration and status
   publication, then observe actual transaction progress before counting a lane.

Full archive qualification, runtime promotion, delivery and sidecar authority
remain false. Full211 natural completion still needs independent full/current
plugin checks and the actual R2 readback played beginning-to-end through the
current account-updates plugin before readiness-sidecar publication. No old
full209 uploader shortcut is reused. Local retirement keeps its separate
authenticated remote/current-plugin/boundary/no-consumer gates.
