# Failed 220–223 cohort: primary-source prefix evidence

`jetstreamer-epoch220-prefix-evidence` captures the exact quarantined producer
`c2adebaad0cb42b385156631156813fe` and stopped controller
`0b69b5009dc74bbda94b94d059a3daa7`. It is a read-only, incident-specific collector,
not a recovery importer or a runtime qualification gate.

Run the sealed binary as root with an absolute, absent output filename below a
root-owned owner-only directory and its independently supplied executable SHA-256:

```text
jetstreamer-epoch220-prefix-evidence OUTPUT --self-sha256 HEX
```

It independently hashes the original immutable node and preflight report, checks
their fixed identities, and requires both original service invocations to remain
terminal with zero restarts. It captures bounded JSON journal records for the
original invocation, authenticates their service, executable, UID and PID,
requires distinct ordered journal cursors, and mechanically extracts all seven
complete checkpoint tuples. Each 220–222 root accounts hash must equal its entry
in the independently hash-bound original manifest. Bootstrap, per-epoch root,
terminal, archive-close and retained-validation messages must occur in order,
before the exact epoch-223 post-update-count failure. Missing, duplicate,
foreign, changed or incomplete records fail closed. Inputs and terminal service
identities are rechecked before a no-clobber, fsynced root-only receipt is written.

The receipt preserves the raw selected JSON journal and digest. It observes no
replay resources, changes no service, creates no segment manifest or canonical
sidecar, grants no restart/import/publication/retirement authority, and performs
no network or R2 mutation. In particular, observing a root hash in the journal
does not independently reread the retained archives or prove their current bytes.

Complete private 220–222 archives still need independent rereads, a separately
reviewed failed-prefix recovery/import path, and normal full/current-plugin and
authenticated R2 delivery gates. The whole-cohort unreceipted recovery command
requires a different terminal/guard history and must not be used for this failure.
Preserve the original prefix and partial 223; never fabricate missing manifests,
truncate updates, or replay 220–222 merely to recover 223.

## Independent private rereads

The sealed `horizon-retained220-222-full-prepared-v1` package runs three disjoint
`horizon-independent-full-read-N-retained-prefix-v1.service` oneshots. Their exact
invocations, eight-thread read-only commands, retained input paths, admission and
launch receipts are tracked as `private-verification` diagnostics by the fleet.
An activating/start oneshot with a positive PID is live work, not a failed or
absent producer. This registration grants no ordinary replay, current sidecar
ETA, recovery import, status cleanup, canonical checksum, or publication authority.
The original failed epoch repair records remain open until verified R2 pairs exist.

For terminal receipt collection, bind the sealed unit member as `installed_file`
and the exact root-owned `/run/systemd/system/UNIT.service` symlink as the optional
`unit.runtime_unit_link`. The collector requires that link to target the same
sealed package's exact unit member; it still hashes the real member, authenticates
systemd's fragment path and invocation journal, and requires terminal success.
No active service needs to be changed or restarted to collect its later result.
The older fixed epoch-140 transient profile cannot use this runtime-link option.

## Epoch-223 capacity repair qualification

Each newly sealed `jetstreamer-node`, `verify_archive`, and `horizon_pipeline`
accepts the standalone `--post-update-capacity-probe` flag. It exercises that
executable's linked writer and reader in memory over the observed 16,385-record
post-update shape at slot 96,540,992, including nonempty account data and ordered
write versions. It separately proves rejection of record 32,769 and reports the
unchanged independent 16 MiB post-update data limit. Additional arguments are
rejected; no production archive, replay runtime, database or remote storage is
opened. Preserve each exact executable digest and machine-readable result.
This capability evidence does not replace the fresh admission, canonical-root,
independent full-verification, current-plugin or R2 readback/sidecar gates.

## Failed-prefix checkpoint qualification

`jetstreamer-node --failed-prefix220-checkpoint-probe` is a standalone read-only
bridge from the exact primary-source receipt to the replanned 220–222 checkpoint
scope. Both input paths and independently recorded SHA-256 values are compiled
in. It rejects additional arguments before destination, lease, runtime launch,
archive or network initialization. It uses ordinary runtime/strict manifest
validation, parses all ten fields in each full checkpoint tuple, requires their
exact original journal suffixes, and validates complete-slot tick heights.
Every observed root must match its independently hash-bound planned root; all
three terminals must be their canonical epoch ends. Carried-bank tuples are
preserved exactly between members, with monotonic transaction/write cursors.

The JSON explicitly marks the resulting checkpoint context as a candidate, not
publication authority. It proves neither current archive bytes/provenance nor
independent PoH anchors. A successful probe does not fabricate a segment manifest,
change the existing whole-cohort recovery gate, import anything, create sidecars,
restart any producer, or touch R2. Independent rereads, exact content-bound
provenance admission, reviewed failed-prefix import, and full/current-plugin
delivery gates remain required. The partial 223 archive and original failed
cohort state remain preserved.

`--failed-prefix220-artifact-probe=N` (only 220, 221 or 222, no other arguments)
is the subsequent read-only content-measurement stage. It requires the exact
successful private reread collector receipt, original reader invocation, archive
path/length/mode and non-authorizing flags. It opens only the fixed retained
archive, requires its original device/inode/single-link identity, captures and
encodes its actual provenance, and hashes the complete file under unchanged
descriptor/path identity. It rechecks the collector receipt afterward. The JSON
keeps this hash event explicitly separate from the earlier internal reread: it
does not turn that receipt into a hash-bound normal full-verification receipt or
authorize provenance admission, import, sidecars, publication or R2 mutation.

## Exact retained-content provenance registry

The audited archive recovery registry identifies only the following independently
reread and separately hashed original files, not every output of their parent:

| Epoch | Bytes | SHA-256 | Bootstrap kind / slot |
| --- | ---: | --- | --- |
| 220 | 135699623364 | `24518ca4b55e7e4c8612269fa9903836e83869daefb5c0c1efb76b91eebb56c7` | SnapshotArchive / 95039516 |
| 221 | 137055363091 | `d772aa744d5b7973653326d4a3f04f1d4060776acff40df2b2cff57ccc1b26cd` | CarriedBank / 95471999 |
| 222 | 133175903649 | `b3dc28fd206de162b47f90638348d414e7708c9f2b36873de10e4d62142f7a3a` | CarriedBank / 95903999 |

The exact provenance includes original generation `9d8e964b8adbfb6c417590fddc87fc915d056a4e`,
candidate v1.6.20 runtime, mainnet genesis, observed transaction metadata,
canonical full-epoch range, original bootstrap accounts hash, and worker digest
`f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c`.
Worker resolution must name the original immutable
`horizon-contiguous-220-223-current-9d8e964-v1` deployment, not a different path
with similar bytes. The primary tuples and captured encoded provenance supply
the snapshot/carried-bank distinction; changing that kind must reject.

This registry is consulted only alongside the existing stable full semantic/PoH
reread, exact file length/hash and worker checks. It does not promote the parent
generation into generic compatibility or replace checkpoint/root gates. It does
not authorize failed-prefix import, manufacture missing manifests, or permit
publication of partial 223. Existing snapshot-only entries remain snapshot-only;
the mutation tests exercise each entry's opposite bootstrap kind.

## Distinct failed-prefix import

`jetstreamer-node --failed-prefix220-recovery-preflight PLAN PLAN_SHA256 SELF_SHA256`
qualifies the exact deployed node and strict incident plan without decoding,
moving archives, creating sidecars or touching R2. The actual
`--failed-prefix220-recover` form repeats every preflight gate, then runs the
normal stable semantic/PoH and whole-file validation for all three archives,
with three independent eight-thread readers. There is no skip-full input.

The plan binds only schema `horizon-failed-prefix220-recovery-plan-v1`, paths
`primary_evidence`, `planning_report` and `recovery_receipt`. The first two may
be least-privilege immutable deployment copies, but their exact original SHA-256
values remain compiled in. Do not loosen the original private evidence tree's
permissions. The validation receipt must be
`/home/ubuntu/.jetstreamer-private/failed-prefix220-recovery-v1/validation.json`.
Execute as original UID 1000 with the default shared epoch leases, an owner-only
receipt directory, and the exact original immutable v1.6.20 worker configured.

Both original systemd owners must still match their pinned terminal identities
before and after validation. Complete producer-manager and queued-job censuses
reject unknown live/queued replacements; only the exact existing zero-restart
203 and 223 invocations are admitted as disjoint live producers. The original
failed run-state digest and scope are rechecked. Normal destination leases,
absence checks and the transactional destination writer lock prevent conflicting
publication. The original source inode, owner, mode, length, provenance and
content hash must all match the audited entries.

Epoch 219 is independently whole-file hashed against its known verified content
identity, then its last bucket is decoded to bind its terminal block. Epoch 220's
first parent and initial PoH anchor must match that terminal. The ordinary
`validate_recovered_cohort_gate` additionally binds all three journal-derived
checkpoint tuples and carried sibling anchors. Tests cover wrong first-parent,
wrong anchor, untracked/restarted/replaced producers and attempts to add skip,
scope, destination or cleanup fields to the plan.

Only after every reread and checkpoint gate passes is a private durable validation
receipt written and the normal no-overwrite transactional batch import invoked.
Its normal committed publication receipt is returned. **Never clean the source
run**: it still owns partial 223 and original failure evidence. Import success
does not prove current-plugin or authenticated R2 completion; dispatch those
ordinary per-epoch gates afterward. Preserve interrupted batch recovery state;
do not blindly restart the importer.
