# Epoch 211 native admission and launcher

Source for one 45-minute, 128 GiB hard / 112 GiB high, eight-CPU, 512-task,
zero-swap native cold-input qualification. The root is bounded to 300 GB.
This does not authorize entry replay, publication, a readiness sidecar, or R2
mutation. It does not qualify the epoch's complete slot range.

**Not operationally qualified yet.** Main owns the bounded build, tests,
source publication, artifact sealing, lifecycle integration and sandbox/first-fire
qualification. No live service was inspected or changed while writing this tool.

The pinned harness is the internal-first-guard-gated image
`2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773`.
The pinned native guard is
`a91f0cc1f3a018f11731b97bbeb2132790a4dbd63dec93b7aa9abbaafeeb6d9a`.
Both exact deployment paths are constants in `src/main.rs`; an old ungated
harness or an old guard is rejected.

## Commands

```text
horizon-native211-launch admit REVIEW_PATH REVIEW_SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY
horizon-native211-launch launch REVIEW_PATH REVIEW_SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY
```

Both commands require root, an independently supplied mapped executable digest,
and a new `/var/lib/jetstreamer/horizon-native211-execution-*` directory. `admit`
captures a decision only; `launch` independently re-admits and seals its own
admission. There is no retry, resume, skip-gate, force, or cleanup command.
Failures retain evidence. A failure after the captured candidate invocation
starts stops only that exact invocation; it never stops a retained peer.

The parent must arrange a bounded launcher service and account for its finite
cap in `control_units`. Its sandbox needs PID1/journal access, the qualified
sealer, read access to the evidence/cgroups/proc, and write access only for the
named new evidence/deployment directories, the four new unit links, and the
root token namespace. Qualify those exact effective permissions before use.
The candidate's root must already be uid/gid 1000 mode 0700 and contain only an
empty mode-0700 `scratch` directory; it never downloads another input copy.
The root-owned token namespace must already exist and be traversable by the
unprivileged harness. Fresh attempt package names and all four systemd names
must be unused. The launcher does not enable units at boot.

## Admission inputs

The root-sealed `horizon-native211-current-fleet-review-v1` has `epoch:211`,
`Main_accepted:true`, `single_campaign_controller_confirmed:true`, `boot_id`,
the actual `main_controller_pid` and `main_controller_start_ticks`, a fresh
`recorded_unix_seconds`, a safe `attempt` suffix, and eight distinct integer
`cpu_affinity` members. All of these flags must be explicitly false:
`entry_replay`, `replay_launch_authorized`, `runtime_promotion_authorized`,
`full_epoch_qualified`, `canonical_sidecar_authorized`, `publication_authorized`,
`remote_mutations`, `r2_mutations`.

It binds `{path,sha256}` objects named `guard`, `fleet`, `observer`,
`source_publication`, `prestart_qualification`, `reservation_ledger`, and
`century`. `control_units` entries contain exact `unit`, `expected_exec_start`
and finite `maximum_memory_bytes`; the sum plus the new protective guard cap
must fit the 1.5 GiB control reserve. Account any additional auxiliary outside
that pool as a separate reservation. Controls never provide replay capacity.

* `source_publication`: schema `horizon-native211-source-publication-v1`,
  freshly fetched `refs/heads/account-updates`, `remote_head`, fetch timestamp,
  and accepted dependency/provenance review flags. Required artifact roles are
  `harness`, `guard`, `sealer`, `launcher`, `fleet`, `observer`, `inactive-status`.
  Each role binds `artifact`, `source_commit`, and sealed `provenance` with
  schema `horizon-native211-exact-artifact-provenance-v1`, the same artifact and
  source commit, `all_source_dependencies_enumerated:true`, and `source_files`
  entries `{repository_path,sha256}`. The tool rehashes artifacts and reads
  each exact committed source file from Git; Main's provenance review must
  enumerate the source actually used by the build, including dependencies and
  features. A commit label or a caller's contained-in-remote boolean is not
  accepted as evidence by itself.
* `prestart_qualification`: schema `horizon-native211-prestart-qualification-v1`,
  exact harness, guard, source-publication binding, launcher artifact digest,
  bound `qualification_evidence`, and accepted observer-complete-tuple,
  fleet-running-and-terminal, inactive-status-exact-owner, pre-restore-gate-test
  and terminal-retention qualification fields (see `admission.rs`). This deliberately
  blocks launch until the separately owned fleet/observer/status consumers and
  the pre-restore gate have passed their acceptance checks. It must declare
  `actual_first_guard_required_before_snapshot:true` and
  `actual_native_startup_qualified:false`. This permits only the fully admitted
  128 GiB process to reach its internal wait. The current invocation's genuine
  first-fire proof is produced and independently checked before the restore
  token is published; it cannot be a prerequisite to creating that invocation.
  A small control fixture never substitutes for this actual production proof.
* `reservation_ledger`: schema `horizon-native211-retained-reservations-v1`,
  Main acceptance, `all_active_and_dormant_obligations_preserved:true`, exact
  fleet/observer bindings, the same false authority flags, a sealed
  `previous_accepted_booking`, and `reservations`. Each reservation has unit,
  IID, full finite memory cap, conservative remaining disk growth, inherited
  guard floor, a sealed `source`, and optional digest-bound `release` receipt.
  Its source is an accepted `horizon-native211-existing-booking-v1` extraction
  with those exact values, bound `original_admission_or_handoff`, and JSON
  `original_field_pointers` for every value and owner. The previous complete
  host booking (`horizon-native211-prior-host-booking-v1`, accepted and
  `complete_host_booking:true`) cannot silently lose a reservation or reduce
  its memory/disk/floor values. A separate qualified source transition is
  required to change this baseline. Dormant jobs retain their full cap.
  Existing booking extractions may instead use
  `horizon-native211-existing-booking-v2`: replace the single
  `original_admission_or_handoff` and `original_field_pointers` with
  `field_sources`. It must contain exactly `unit`, `invocation_id`,
  `maximum_memory_bytes`, `remaining_disk_growth_bytes`, and
  `minimum_free_bytes`; each value is `{document:{path,sha256},pointer}`.
  Every original document is read through the same root-owned, no-follow,
  stable hash-bound evidence reader. Every pointed value must exactly equal
  the accepted extraction. Missing/extra fields, wrong owners/values and mixed
  old/new provenance forms fail closed. This binds genuine handoff IIDs,
  admission limits and guard floors without creating a synthetic original
  admission. The original single-document v1 extraction remains supported.

  The current Foundation booking uses
  `horizon-native211-retained-reservations-v2` with a matching
  `horizon-native211-prior-host-booking-v2`. Both carry the exact same
  `auxiliary_overhead` object:

  ```json
  {
    "schema": "horizon-native211-fixed-auxiliary-overhead-v1",
    "memory_bytes": 2640509440,
    "source": {
      "path": "/home/ubuntu/.codex/diagnostics/horizon-hard-memory-accounting-20261119-v1/capacity-correction.json",
      "sha256": "64456f938ab522c91848a8c93a32f95e1eeedef97f0e1cdd143923895f090631"
    },
    "source_field_pointer": "/auxiliary_envelope_bytes"
  }
  ```

  This closed source-bound envelope is additional fixed overhead, not a
  service or invocation. Its full bytes count against physical memory and
  remaining hard growth, including after a producer's memory release. It
  cannot substitute for booking any actual live service in the full census.
  A lower value, different source, missing predecessor overhead or ambiguous
  extra fields fails. The v1 ledger route retains its original arithmetic and
  rejects an overhead field rather than silently ignoring it. Moving to v2
  requires an accepted complete v2 predecessor; do not label an incomplete
  draft as accepted.
* `century`: schema `horizon-native211-qualified-century-census-v1`, `entries`
  covering the fleet's exact ready-pair membership and lengths/digests. Every
  entry binds full-verification, current-plugin and remote-readback receipts
  and explicitly records their Main acceptance. The tool recomputes twice the
  mean canonical archive length with upward rounding.

Fleet and review age are at most 300 seconds; source fetch age is at most 1800
seconds. The fleet must bind a genuine complete cadence observer. Unsupported
diagnostic/pipeline owner shapes fail closed. Active owner identity, command,
finite PID1/kernel caps and swap are checked twice. The full manager service
census and native `/proc` executable/cgroup census reject unbooked work.
Retained replay count is derived; it is never fixed at four or five.

A terminal drain receipt alone does not free memory. For each requested
release, the tool checks the qualified drain writer's image, its terminal
handoff and plan, the exact successful inactive invocation with no jobs,
restart/delegation/triggers, every descendant cgroup and the process census,
then rechecks the owner. Disk growth and guard floors remain reserved after
memory release. It does not delete output.

Fit uses complete hard caps plus 64 GiB host and 1.5 GiB control reserves and
the new 128 GiB candidate. It also checks MemAvailable against all remaining
hard growth. Disk fit preserves the larger of inherited floors and century
reserve plus all retained growth, then adds the complete 300 GB candidate.
Existing allocated bytes do not create speculative credit.

## Startup and evidence

The producer runs the exact harness test directly. There is no `ExecStartPre`
sleeper: the mapped harness is its actual MainPID while its internal gate
waits. The one original monotonic window is 60 seconds; the launcher uses a
50-second operator bound. New packages use only the qualified Rust deployment
sealer and no-clobber publication. After activation, the launcher seals the
actual IID/PID guard plan, installs its service and 30-second timer, and waits
for a genuine successful timer first fire. The guard disables systemd start
rate limiting for its explicit 30-second cadence. Before producer activation,
the launcher arms an ordering-only terminal-retention target and proves it
did not activate the producer; it has no Wants/Requires/BindsTo/Upholds or
boot-install dependency. The persistent native producer uses RemainAfterExit=no;
the active target retains its original terminal manager fields until capture. It captures the guard's real sample
and PID1 journal and verifies the next typed monotonic timer deadline. It
rechecks retained owners/capacity before atomically publishing the token.

The package at `horizon-native211-startup-tokens/IID/` contains
`guard-admission.json` and its exact 64-hex-plus-newline `.sha256`. The token
schema is `horizon-native211-first-guard-token-v1`, consumed independently by
the harness gate. Journal events are captured, never synthesized. The launcher
preserves the original sealed guard-plan path in the token and sample binding.

Success writes `horizon-native211-guarded-startup-v1`; this means only guarded
native execution has begun. Snapshot/accounts commitment and clean native
completion must be captured separately before any later replay qualification.

Main's relevant source check is `cargo test --manifest-path
tools/native211-launch/Cargo.toml` inside its already-qualified bounded build
envelope. Tests cover hard-budget failure, drain credit, retained disk/floors,
overflow/duplicate owners, direct internal-gate templates, template injection,
and genuine first-guard sample/PID1 ordering. Running tests does not substitute
for the exact runtime sandbox and first-fire qualification.

## Original periodic guard accounting

Foundation's four original recurring guards (248–251) each retain their full
1,073,741,824-byte cap between timer firings. They must use matching
`horizon-native211-retained-reservations-v3` and
`horizon-native211-prior-host-booking-v3` documents. Both retain the v2 fixed
`auxiliary_overhead` unchanged and include the identical `periodic_controls`
object:

```json
{
  "schema": "horizon-native211-original-periodic-controls-v1",
  "controls": [
    {
      "unit": "horizon-248-reboot-20261117-protective-v1.service",
      "timer": "horizon-248-reboot-20261117-protective-v1.timer",
      "maximum_memory_bytes": 1073741824,
      "service_source": {"path": "/var/lib/jetstreamer/horizon248-reboot-20261117-guard-v1/guard.service", "sha256": "c7cd20e232e84f8058de9101444a574e12a033d3a530e039a20274259fac9fe6"},
      "timer_source": {"path": "/var/lib/jetstreamer/horizon248-reboot-20261117-guard-v1/guard.timer", "sha256": "90b637b95289135efe99f0ee6d757e104c9badbb4982e320b5e7a7521b141024"},
      "guard_plan": {"path": "/var/lib/jetstreamer/horizon248-reboot-20261117-guard-v1/guard-plan.json", "sha256": "7f2209ef5e614df2b7d12b01070051c836e3c41d9040aca2db00e98fba9f16e3"},
      "executable": {"path": "/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard", "sha256": "044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f"}
    }
  ]
}
```

The excerpt shows one member; `periodic-controls.example.json` supplies the complete
four-member object. Acceptance requires all four exact registered
members from `periodic.rs::pins`, with original service/timer/plan/artifact
bindings. No omitted, duplicated, reduced or substituted member is accepted.
The guard plan must still bind a retained original producer/IID and its full
inherited floor. These units cannot also appear in `control_units` or producer
reservations. Legacy ledgers cannot omit this envelope when retaining one of
these original producers, even when every guard happens to be inactive.

The complete 4,294,967,296 bytes are added to both physical hard obligations and
remaining hard growth. No RSS credit is taken for these periodic controls.
The ordinary 1.5 GiB control reserve (including the new native211 guard), fixed
auxiliary overhead, original producer caps/disk growth and floors are unchanged.

Every admitted periodic guard is checked twice independently of the active
service list. Checks bind original unit bytes, exact stable command and
`ignore_errors=no`, zero restarts, finite manager/kernel caps, original timer
and guard plan, mapped main image/process membership and dormant drainage.
Only PID1's execution-history trailer is ignored during command comparison;
changed argv, ignore-errors policy or additional commands fail. A dormant guard
requires an active waiting timer with a bounded typed future deadline; a firing
guard may be activating/start under its oneshot service. Any race changing the
owner during its census fails closed. Future guard replacements require a
separate qualified source transition.

The admission path also recognizes the registered original 248–251 singleton
`producer-finalization` rows. Each must retain the original IID/PID, command,
node/manifest, complete before/after resource tuple, full 251,041,591,296-byte
memory cap, original remaining disk obligation and inherited floor. The fleet
pipeline/active rows must match exactly once, with the same authenticated EOF
and sample in the observer diagnostic row. EOF provides phase information only;
terminal, release, archive verification and publication claims remain false.
These owners still pass the same live manager/kernel census twice. Other
pipeline/diagnostic shapes remain unsupported and fail closed.
