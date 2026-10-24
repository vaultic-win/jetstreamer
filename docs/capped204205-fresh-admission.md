# Fresh resource admission for original capped 204/205 continuation

The new `jetstreamer-r2 admit-capped204205-continuation SPEC --spec-sha256 SHA
--self-sha256 SHA` command is a root-only, one-shot admission transaction. This
source implementation does not call it, initialize a Bank, read source archive or
snapshot bodies, run a replay, change a producer, or contact R2. No successful
admission exists merely because the source or a frozen plan passes tests.

It consumes the frozen `capped_control204205::Plan` protocol and the root control
binary's read-only `validate-plan` mode. The final producer plan is published
first, with its admission **path** already fixed. The later admission binds the
actual plan digest, eliminating a circular pair of plan/receipt hashes. Root must
prepare genuine natural terminal, full independent prefix-reader, original
metadata, frozen source capture and retained snapshot evidence before this path
can be used. Original native tuple, cursor and full snapshot rehash rules remain
in the separately qualified producer/control implementation; no asserted old
native result replaces the actual suffix barrier.

## Required spec and input roles

The schema is `jetstreamer-capped204205-continuation-admission-spec-v1`. Every
`Bound` is `{ "path": "/absolute/path", "sha256": "actual lowercase digest" }`.
The exact fields, with unknown fields rejected, are:

| Field | Role |
| --- | --- |
| `producer_plan` | Immutable final continuation plan, exact schema `jetstreamer-capped204205-continuation-plan-v1` |
| `resource_proposal` | Immutable complete enforcement envelope, described below |
| `resource_capability` | Immutable actual disposable equivalent-sandbox/guard proof |
| `source_closure` | Immutable exclusive source/build closure for the exact producer/control binaries |
| `producer`, `control` | Actual root-sealed executable paths and digests; control digest equals plan `guard_sha256` |
| `observer`, `fleet` | Original accepted coordinated observation and fleet bindings |
| `protected_guards` | Exact map from every accepted active owner to its latest completed guard binding |
| `fleet_observation_readable_mirror` | New runtime path, exactly the output parent plus `fleet-observation.json` |
| `output` | Exactly the frozen plan's admission path, named `admission.json` |

Plans, proposals, capabilities, source files and executable inputs must be
root-owned, single-link and immutable. Original campaign receipts have a different
role: the actual root-owned **0600 fleet** and **0644 observer** are accepted through
the existing stable bounded no-follow reader, exact hash, canonical path,
single-link and no group/other writes. Fleet uses trusted private ancestry.
The observer also supports the exact established Foundation workspace profile:
root-owned receipt directly in
`/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness` named
`horizon-live-resource-sample-*.json`; `/home/ubuntu` is UID/GID 1000 mode 0750 and
the four workspace descendants are UID/GID 1000 mode 0775. All ancestor identities,
owners, groups and modes are stable across the read; this role exception does not
generalize to arbitrary paths or to the fleet. They are never
chmodded, rewritten or reissued as another accepted lineage.

The immutable admission output and runtime mirror live in a separate canonical
root-owned directory beneath `/var/lib/jetstreamer`. The directory and all
ancestors must be traversable by UID 1000; the directory may be 0755/0555 and must
not be writable by group/other. Both files are published 0444, fsynced and
no-clobber. The original accepted binding remains `fleet_observation` in the
receipt. `fleet_observation_readable_mirror` has the **same digest and exact bytes**
at its different path. It is a same-host runtime input, never a new accepted fleet,
an R2 object or cross-host completion evidence. An identical existing immutable
mirror can be reused on retry; conflicting data is preserved and causes failure.
No receipt is published until the mirror has been authenticated and read back.

The unprivileged producer opens the final plan, six metadata inputs, source
capture, admission, readable fleet mirror, resource proposal, producer executable,
worker, genesis, original frozen prefix and retained snapshot. Each existing
runtime input and its ancestry is checked for immutable ownership and UID 1000
readability; executables also need execute permission. Root-only capabilities,
original fleet and original observer are not mirrored unnecessarily. Root must
prepare the new empty UID 1000 private run root and traversable guard directory.

## Resource proposal

Schema: `jetstreamer-capped204205-resource-proposal-v1`. It binds `producer_plan`,
`source_closure` and `resource_capability` as exact Bounds and repeats these exact
producer-plan fields: `epoch`, `node_sha256`, `guard_sha256`, `producer_unit`,
`guard_unit`, `run_root`, `protected_existing_floor_bytes`,
`candidate_incremental_peak_bytes`, `maximum_root_physical_bytes`,
`maximum_process_rss_bytes` and `maximum_worker_vmas`.

It additionally requires `external_control_metadata_bytes` of at least 16 MiB,
plus the exact accepted fleet mirror length and the 4 MiB maximum admission
receipt staging bound (the checked admission minimum is 20 MiB plus fleet bytes),
`guard_memory_max_bytes` between 1 MiB and 1 GiB, and this exact six-field numeric
`kernel_limits` object:

| Field | Gate |
| --- | --- |
| `requested_memory_max_bytes` | Cache-inclusive hard cgroup cap, at least the whole-process RSS ceiling and within the century 1.5x observed RSS ceiling |
| `requested_memory_high_bytes` | Positive, no larger than requested maximum |
| `memory_swap_max_bytes` | Zero |
| `tasks_max` | 1 through 512 |
| `cpu_quota_usec_per_second` | 1 through 8,000,000 |
| `runtime_max_usec` | Positive, no larger than six plan stage deadlines (`maximum_stage_millis * 6000`) |

The complete incremental disk peak must cover the whole run-root cap **plus**
external control metadata and be at least the plan's 256 GiB experimental minimum.
The run-root cap includes restore, suffix, validation and assembly overlap, not
only native input. The original frozen prefix remains outside this new root.
These are enforced bounds, not an invented observed production peak. The user's
century-specific 300 GB scratch assumption does not replace exact staging/output
and metadata accounting.

Every proposal, source-closure and capability report must explicitly deny
`ordinary_replay_authorized`, `canonical_sidecar_authorized`,
`publication_authorized`, `retirement_authorized`, `remote_mutations` and
`r2_mutations`.

## Closed source and capability evidence

`jetstreamer-capped204205-source-closure-v1` binds `producer`, `control`, exact
`worker_sha256`, `exclusive_feature` equal to
`capped204205-checkpoint-continuation-diagnostic`, the actual 40-character
`source_revision`, `complete_dependency_closure_sha256`, and
`original_raw_native_tuple_and_cursor_rules_preserved: true`. Its `source_files`
map holds root-sealed hash-bound actual source members, including `Cargo.lock`,
`capped_prefix204205.rs`, `capped_control204205.rs`,
`checkpoint_continuation204205.rs`, `capped204205_resource_probe.rs`, the shared
`guard_core.rs` and every other probe module and qualified dependency in the
closure. Every supplied source member is rehashed; no source-check boolean alone
authenticates an executable.

`jetstreamer-capped204205-resource-capability-v1` is a separately qualified real
disposable equivalent-sandbox/guard proof. Missing evidence is an unqualified
denial; the emitter never synthesizes a successful proof. It must bind the exact
epoch, producer, control, source closure, kernel limits, guard memory reserve,
whole-root/RSS/VMA ceilings. `capability_kind` is
`disposable-equivalent-sandbox-guard`; `bounded_enforcement_proven` must be true,
and `observed_production_peak_claimed`, `native_initialized` and
`archive_body_read` must be false. Its ordered `stages` are
`prefix_validation`, `native_restore`, `suffix_validation`, `assembly`.

Its `enforcement` object must prove `whole_process_tree_bounded`,
`whole_root_bounded`, `guard_trip_stops_exact_invocation`,
`unproven_guard_blocks_stage_entry`, `monotonic_stage_deadlines`,
`restore_suffix_assembly_overlap_included`, `native_barrier_precedes_entries` and
`no_canonical_sidecar_or_publication`. The actual `probe_unit` is in the closed
`horizon-capped204205-resource-probe-*.service` namespace and has a genuine
nonzero `probe_invocation_id`. Its immutable `terminal_properties` and
`manager_journal` Bounds must prove a clean loaded Type=exec terminal, no restart,
zero exit, empty cgroup and one exact successful PID 1 completion with no failure
records. It also binds the actual immutable `probe` executable (also bound as
`resource_probe` in the source closure), `probe_plan` and generated `probe_receipt`.
The plan schema is `jetstreamer-capped204205-resource-probe-plan-v1`; it binds the
actual producer/control/source closure and the same kernel/guard/root/RSS/VMA
envelope, without the final continuation plan digest. Thus the capability can be
generated before the final fresh source capture/producer plan, avoiding a circular
prerequisite. The exact command is the dedicated probe executable plus its bound
plan, `--plan-sha256` and `--self-sha256`.

The generated result schema is
`jetstreamer-capped204205-resource-probe-result-v1`. It binds actual probe/plan
digests, epoch, unit/IID, generated enforcement results and the same kernel limits.
Its `actual_kernel` reports requested/host-page-rounded producer and guard memory
caps, zero swap, task cap, runtime bound and actual CPU quota/period. The emitter
independently checks their arithmetic. The actual same-PID/IID executable stdout
must contain exactly this result, followed by genuine clean PID 1 completion.
`host_machine_id` must match this host and both journal roles. Generic successful
services or root-authored boolean summaries cannot replace the generated result.

This proves bounded enforcement without demanding a completed production
replay or inventing its measured peak. The guard independently enforces its own
memory reserve and actual producer requested/page-rounded kernel controls.

## Fresh transaction and preserved gates

The emitter calls the exact sealed control's `validate-plan` before and after its
admission transaction. Schema `jetstreamer-capped204205-admission-inputs-v1`
returns the full typed proposal, rederived Serialize-only metadata policy, original
reader bindings, actual frozen archive/snapshot identities and current complete
source-idle process-reference closure. It reads no archive/snapshot body,
initializes no native state and grants no execution/resource authority itself.
The calls are lifecycle integrity checks within this transaction, not an extra
routine poll. The campaign still has one normal 30-minute observation cadence.

The already accepted observation must be current, complete and identity-stable,
with no unmodeled/omitted/duplicate owners, ordinary replay, unknown peers, high
PSI, missing century RSS history or unsafe worker/VMA evidence. The original
producer for the selected epoch must be positively inactive in the accepted raw
census and both actual current censuses. A candidate/new guard already running,
or live/unknown Foundation213 maintenance, is a failed gate.

The transaction reuses qualified complete rosters, original failure/history
checks, century inventory, protected growth, exact completed guard PID 1/command
lineage, active waiting timers, current owner identities, requested/kernel caps,
internal disk floors and remaining hard-memory growth. The disk requirement is
the plan's protected floor plus complete candidate peak; the protected floor must
cover both century-floor-plus-growth and every existing guard's unchanged floor.
Memory is `max(10% host baseline, live native223's 480 GiB floor) + candidate hard
memory + new guard hard memory + protected remaining hard growth`. An existing
canary's separately evidenced native223 floor top-up is counted once, never twice.
Actual free space, memory, caps and ownership are bracketed, checked against the
sample and rechecked before no-clobber publication. The transaction has a maximum
15-minute duration and the final sample must still be fresh.

Raw observer/fleet evidence, every prior failure and original tuple/cursor rules
are preserved. No profile is silently dropped to make admission fit. An already
running new continuation is deliberately unmodeled until its own exact actual
launch/guard/fleet/status peer adapter is separately qualified; this emitter does
not invent one or authorize a second continuation around it.

The positive receipt schema is the frozen
`jetstreamer-capped204205-continuation-admission-v1`, with original fleet and
explicit runtime-mirror bindings, exact immutable plan/proposal/kernel controls,
source/capability/reader evidence, original before/after owner/guard/cap/resource
proofs, and all unrelated authority denied. It admits the bounded resource
experiment only. Launch, first protective fire, actual native barrier, complete
suffix, V4 assembly, final independent/current-plugin verification, upload and
canonical sidecar remain distinct gates.

## Qualification state

The original emitter's 12 targeted adversarial tests passed; its complete R2 suite passed 782 tests
with 48 existing ignored. Strict production/test all-target Clippy passed, using
the shared absolute target, incremental off, locked offline release profile and
two build jobs. Logs: `/tmp/capped204205-admission-targeted-tests.log`,
`/tmp/capped204205-admission-full-tests.log`, and
`/tmp/capped204205-admission-clippy.log`. `git diff --check` passed.

The concrete disposable probe/shared-control successor is separately owned and
qualified; root must review/seal those exact successor artifacts and actual
same-host proof before any future admission. Missing generated probe, source
closure, terminal, stdout or sandbox evidence remains a denial. This emitter's
75007955 source lineage is **ineligible for holding retirement**; the anchored
4a49/55/cb69 tools retain their separate authority and receipts.

No actual admission, runtime mirror, host/resource poll, native initialization,
live probe or R2 operation has been performed from this worktree. The later
frozen release candidate build is a source artifact, with full tracked source,
Cargo lock/toolchain and literal production-dependency records; it is not a
runtime deployment or an observer executable.


## Actual manager command compatibility

The capped 204/205 capability consumer accepts its exact metadata-free probe
command and the same single systemd ExecStart record with complete display
metadata. Path, argv, digests and `ignore_errors=no` remain byte-exact. The local
adapter rejects missing, malformed, reordered or extra metadata fields and any
trailing command or record; the generic command matcher remains unchanged.


The command-compatibility successor passed 13 targeted tests and the full R2
suite (783 passed, 48 existing ignored). The regression exercises an actual
metadata-bearing manager command and adversarial changes to argv, immutable
bindings, ignore-errors policy, numeric fields and command-record boundaries.
