# Exact old epoch-185 attempt growth closure

This protocol closes only the old producer invocation
`0de9498a3c2f4c6dbd7350d052fc7e02`'s outstanding 824,633,720,832-byte
(768 GiB) future-growth reservation. It leaves epoch 185 failed and needing repair.
It neither releases physical disk space nor qualifies a partial archive or a Bank.
The retained source, scratch and inputs remain in place.

The original admission is bound by its exact deployment path and SHA-256. Its
minimum-free-space requirement exceeds the old guard floor by exactly 768 GiB.
The closure does not recompute or bless the old five-owner capacity formula.
An independently reviewed fresh census must account for every current replay,
restore, input acquisition, qualification, stopped attempt and downstream delivery
obligation before any new work can be admitted.

## Commands and trust boundaries

All commands use the ordinary sealed-root `holding-*` entry point and exact
`SPEC --spec-sha256 HEX --self-sha256 HEX` binding. No command here reads R2
credentials or performs R2 mutation.

* `holding-capture185-survivor-guards`: capture native timer metadata and the
  structured systemd `ExecStart` argv of the existing sealed Python guards.
  This writes a disjoint private receipt; it can coexist with a park operation.
* `holding-check185-attempt-growth`: authenticate actual whole-readback custody,
  eligibility, original admission and staged reconciliation; verify a fresh
  full-fleet census, live owner identities, survivor guards and retained source.
  It records a check and grants no closure. It requires the holding lock.
* `holding-close185-attempt-growth`: require a separately reviewed plan with
  explicit closure authority and a successful check no more than 900 seconds old.
  Repeat native checks around a durable once-only intent and closure receipt.
  An occupied holding lock rejects this operation, so an active park cannot race it.
* `holding-read185-attempt-growth`: authenticate the fixed closure and its exact
  immutable intent, then project the disposition over typed reservation rows.
  Exactly one explicit original claim row must contain either the full original
  reservation or zero. Duplicates, a partial unexplained disposition, and the old
  invocation under another claim key are rejected. All other rows, including a
  future epoch-185 replacement, remain unchanged. A repeated projection removes
  zero additional bytes. This view is not an admission or additive free space.
* `holding-plan185-guard-handoff`: authenticate a capacity review document and
  full-fleet evidence, observe the current native guard, and produce an immutable
  proposal preserving its exact script, controller/producer invocation IDs and
  VMA ceiling. The proposed unit names and intent/completion frontiers must be
  distinct. This command explicitly does **not** independently validate the
  capacity model or authorize/install/arm/retire metadata.

The closure's census assertions preserve other obligations and bind their evidence.
They are not a deep parser or a validation of each other admission's capacity math.
The fixed survivor-floor lower bound is 3,332,894,621,696 bytes; the actual maximum
installed surviving guard floor is retained even when higher. No guard is edited
or lowered by closing or reading this reservation.

The retained source check binds the original inode, device, length, timestamps,
ownership, mode and sidecar absence. Run/scratch/inputs metadata demonstrates their
continued presence only. It is neither a whole-tree integrity check nor a portable
Bank resume checkpoint. Authenticated custody preserves diagnostic failed bytes;
it supplies no canonical `.sha256`, valid prefix, replay-resume or retirement right.

## Separate guard handoff execution protocol

An operational executor is deliberately outside this change. It must be qualified
and reviewed separately against the concrete proposed argv and a fresh independent
all-claims capacity admission. A closure receipt alone never justifies subtracting
768 GiB from an installed floor.

1. Revalidate the exact closure, fresh all-claims census, old native guard and live
   zero-restart controller/producer identities. Recompute the proposed floor from
   the actual retained, growth, restore, post-replay and century-floor obligations.
   Require the new metadata names to be absent, rather than trusting names in a plan.
2. Preserve the old raw argv, unit config and journals outside scanner roots. Write
   a no-clobber intent binding that preservation, both profiles, capacity evidence,
   exact executable and owner identities. Every retry must validate this intent.
3. Install immutable new metadata through Rust orchestration using the existing
   sealed Python guard unchanged, exact invocation IDs, filesystem and VMA ceiling.
   Keep the old guard armed and do not stop or restart a healthy producer/controller.
4. Arm the new guard at its normal two-minute safety cadence. Prove its first
   native successful healthy fire: exact command/profile, positive invocation,
   successful service result/exit status, no safety-stop intent/completion, stable
   live owner invocation IDs and restart counts. Persist and hash-bind this evidence.
   An exit code alone is insufficient because an identity mismatch may be a no-op.
5. Only after that proof and a fresh race check, retire the old metadata timer
   without signalling either live owner. Persist a frontier before each mutation
   and verify the native result after it. Do not remove preserved config or journals.
6. Write a no-clobber completion. On an interrupted retry, authenticate each already
   completed frontier and continue only from the proven state. If a new guard is not
   proven healthy, retain the old safety guard and report the unresolved handoff.

The two-minute safety cadence is independent of the single normal 30-minute replay
observation. No extra replay polling is introduced. A terminal producer with a live
importer, such as cohort 191, is a downstream pipeline obligation rather than a live
replay guard handoff; preserve its independently owned capacity and status treatment.

No closure or proposal starts epoch-185 repair. Once an actual repair, qualification
or replay is admitted, it needs a current real owner and a numeric sidecar ETA with
recovery and delivery allowances. Until then the failed epoch remains in the repair
backlog, with no stale terminal producer countdown.

## Optional retirement after logical closure

The default `holding-retire185` plan still requires both original epoch 185 and 141
claims retained. An optional `closed_growth_disposition` binding selects a
separately reviewed capacity schema for retirement after old epoch 185 has already
closed. It authenticates the same fixed closure/intent through the typed reader,
requires the explicit original epoch 185 row already 0 with disposition delta 0, and
preserves the original epoch 141 whole-root 512 GiB cap/binding. This preserves
that original cap, with no incremental 512 GiB allocation on top of retained bytes
or a new remaining-growth calculation.

The opt-in projection binding is part of the durable retirement intent, so its
frontiers cannot be mixed with the default pre-closure retirement transaction.
All existing source identity, no-consumer, native fleet, authenticated remote
custody, full local hash, no-clobber quarantine and unlink gates remain required.
It neither changes a guard nor releases another reservation, and it grants no
physical credit before the actual unlink. Source/scratch/input preservation in
the growth closure remains unchanged: close while the original inode exists,
then separately check and authorize the opt-in retirement. The completion records
censused retired physical bytes but does not fabricate an observed free-space delta.
