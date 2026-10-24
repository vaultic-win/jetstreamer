# Epoch 210 native lifecycle operator protocol

The Rust `jetstreamer-r2` control commands below prepare/admit, authenticate and
record the exact epoch210 native input test. They never start a producer,
restore a Bank, create an archive, publish a sidecar or take a resource sample.
Keep the [sealed preparation bindings](epoch210-native-preparation.md) and the
300000000000-byte whole-root/128 GiB hard-memory cap unchanged.

Every command takes `SPEC --spec-sha256 SPEC_SHA --self-sha256 HELPER_SHA` as
root. Specs are canonical immutable root-owned single-link files; output parents
must be fresh root0700 directories. Receipts are no-clobber, fsynced and sealed.
Use the separately sealed lifecycle helper for fleet, status and inactive-status
consumers that must understand the new claim. Preserve existing healthy replay,
guard, verifier and uploader binaries; do not replace them merely to deploy this
control profile.

## Prepare and admit

Install the exact dormant service file as root0444 at
`/etc/systemd/system/archive-210-v1616-native-input-actual-v1.service`, SHA-256
`474e889f9d40294654f52a3f2ce0f3d3d06b89fc5f19cd97695f5aa5f42ccb24`.
Do not enable it at boot or start it yet. Precreate empty ubuntu0700 directories
`/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1` and its
`scratch/` child. Static deployment retains terminal evidence; transient units
and `RemainAfterExit=yes` are rejected by running capture.

Use a fresh accepted coordinated observer/fleet pair with the complete live and
failed history. Full 227 failed after observation 338. Do not launch
against 338's stale active census or remove its observer row. Wait for an accepted
fresh cycle whose authoritative census records its terminal state. Preserve its
original diagnostic, invocation, launch and repair evidence. There are no
synthetic terminal-owner subtraction options in this epoch 210 profile. The
original full 227 diagnostic, same-IID loaded failed manager, original launch
evidence and `failed-needs-repair` gate must remain present. Admission and
capture recheck that terminal manager alongside every live peer; missing or
replacement history cannot silently release a reservation.

Create an immutable resource plan with schema
`jetstreamer-private-epoch210-native-resource-plan-v1` and these fields:

- `epoch:210`, `mode:"native-cold"`, exact `unit` and `run_root` from preparation.
- `candidate_incremental_peak_bytes:300000000000`,
  `maximum_scratch_bytes:300000000000`, `maximum_memory_bytes:137438953472`.
- Exact `test_sha256`, `snapshot_sha256`, `genesis_sha256`, `guard_sha256`, and
  `cold_plan:{path,sha256}` from the sealed preparation.
- Definite integer `guard_minimum_free_bytes` and `required_initial_free_bytes`.
  The first must cover the larger of every bound existing guard minimum and
  the century floor plus all protected remaining growth. The second must equal
  that selected floor plus 300000000000. Admission independently recomputes these
  quantities and rejects an under-reservation.
- All eight authority fields false: `entry_replay`, `replay_launch_authorized`,
  `runtime_promotion_authorized`, `full_epoch_qualified`,
  `canonical_sidecar_authorized`, `publication_authorized`, `remote_mutations`,
  `r2_mutations`.

Run `admit-native210-input` with schema
`jetstreamer-private-epoch210-native-admission-spec-v1`, `mode:"native-cold"`,
bound-file objects `observer`, `fleet`, `cold_plan`, `resource_plan`, a
`protected_guards` map from every live owner unit to its latest completed guard,
and output
`/var/lib/jetstreamer/horizon-210-native-admission-UNIQUE/admission.json`.

The helper rehashes the exact test/guard/snapshot/genesis, requires empty scratch,
validates the complete accepted resource census and peer identities, preserves
hard-memory growth and existing guard floors, and brackets all arithmetic with
actual free-memory/free-disk, owner and cap checks. Existing full209/full227 and
optional native228 accounting is reused without changing the accepted fleet.
It requires a 90 percent host-memory target, century 1.5x RSS bound, stable VMAs
and observed pressure. A stale owner or capacity change is a hard rejection.

## Launch, protect and register

Only the campaign owner may start the exact installed native service after
admission succeeds. Bind its actual MainPID greater than one and original PID1
invocation into an immutable guard plan using the prepared exact native tuple,
300 GB whole-root and 3500000 VMA ceilings, and the admitted protected floor.
Arm `horizon-native210-protective-v1.service` and its timer using the ordinary
root oneshot sandbox and existing 1800-second cadence. Preserve its first actual
completed sandboxed no-trip fire before claiming running work.

Run `capture-native210-input` with schema
`jetstreamer-private-epoch210-native-capture-spec-v1`, `mode:"running"`, bound
`admission`, `guard`, `guard_plan`, and exact output
`/var/lib/jetstreamer/horizon-210-native-capture-actual-v1/intent.json`.
Capture checks the exact installed static file, effective sandbox/environment,
guard manager/PID1 success, unchanged complete peer census and canonical clocks.
It records the producer's original start time. The old `qualified` shortcut is
not admitted; terminal qualification uses the independent command below.

Register that intent as a pipeline claim with `epoch:210`, phase
`private-cold-snapshot-verification`, exact native unit/invocation/ExecStart and
the immutable intent as first evidence. The authenticated fleet metadata event
adds only this owner/tracked unit and preserves all existing diagnostics,
pipeline claims and gates. Only the epoch 210 gate may enter `blocked-qualification`
from `not-yet-staged` or `staged-admissible`; it cannot become ready or qualified.

Publish through the existing native `pipeline-status` path with wire phase
`verification`, zero bytes and an absent `epoch-210.jet` beside the intent.
Bind the exact accepted fleet event and original invocation clock, and provide
a definite positive estimate including all later replay/verification/upload/
readback work through the canonical sidecar. No archive placeholder is allowed.
Refresh within the same 1800-second coordinated cycle, with no extra routine poll.

## Capture terminal proof

Preserve the original unit file and raw journal before unit collection. Seal
the journal as
`/var/lib/jetstreamer/horizon-native210-terminal-raw-UNIQUE/journal.json`.
Run `capture-native210-terminal` with schema
`jetstreamer-native210-terminal-capture-spec-v1`, bound `running_origin`,
`journal`, `observer`, `fleet`, and output
`/var/lib/jetstreamer/horizon-native210-terminal-proof-UNIQUE/proof.json`.

Qualification requires original child PID and invocation, the exact canonical
slot 90719638/accounts commitment, zero entries/bootstrap writes, one successful
test and ordered PID1 success within the 2700-second run bound. The loaded unit
must be inactive/dead, successful, restart-free and unreplaced. A missing or
collected manager, failed native test or guard stop grants no qualification;
retain its evidence and repair history instead of restarting automatically.

The typed terminal metadata event preserves the original claim/history, adds
only the epoch 210 proof evidence and rechecks the current terminal manager. After
acceptance, the existing authenticated inactive-status command can conditionally
delete only this original invocation's exact status object. No other R2 key or
archive is affected. The preparation/control commands themselves perform no R2
operations.

Native success still leaves full epoch 210 unqualified. A separate singleton launch
must prove root 91151575, all 424 post-root slots and exactly 432000 output slots
through 91151999, then independent full/current-plugin checks, authenticated
upload/readback/source revalidation and sidecar commit. Preserve adjacent
boundary gates before ordinary local retirement. Keep epoch 207's MD5 blocker open.
