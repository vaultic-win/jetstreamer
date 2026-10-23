# Closed-artifact holding custody

`jetstreamer-r2 holding-park SPEC --spec-sha256 HEX --self-sha256 HEX` and
`holding-restore` implement a separate custody namespace for dev-samjohnson.
They require a sealed root executable, hash-bound immutable root-owned JSON
inputs and private root-owned state at
`/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1`, including
`receipts/` and `restores/`. An exclusive transition lock spans the operation.

The user selected `node_02/` for dev-samjohnson on 2026-10-23. Its sealed mapping
is `/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json`.
Other hosts still need their own user choice; do not generate a hostname
default or borrow another server's prefix. The mapping schema is
`jetstreamer-horizon-host-holding-prefix-v2`, with `host`, `prefix`,
`user_provided_prefix: true` and the actual `authorization_reference`. Prefixes
are relative, end with `/`, and contain only unambiguous alphanumeric, `_` or
`-` components. Existing nonempty prefixes without the matching owner object
are rejected. The first owner creation is conditional and read back exactly;
an existing different owner is never replaced.

A park plan uses schema `jetstreamer-horizon-holding-park-plan-v2`, bindings
`mapping` and `eligibility`, and exact `source`, `length` and `sha256`. The
eligibility review must bind those same bytes, host and path under this host's
private artifact tree; declare the source closed and public chain data; exclude
credentials, configuration and logs; and deny canonical-archive and local
retirement authority. Process commands, maps, descriptors and links are scanned
before and after custody. Any live reference or incomplete census fails closed.

The tool reuses the existing multipart transport: per-part Content-MD5, independent
multipart ETag, conditional completion and complete authenticated SHA-256
readback. Objects use `PREFIX/objects/SHA256.blob`. Existing matching objects are
fully verified; conflicting objects are preserved and rejected. The local source
is rehashed after remote verification. Only then is a content-addressed JSON
manifest conditionally created at `PREFIX/manifests/MANIFEST_SHA256.json` and
read back. A fsynced private custody receipt binds the object, manifest, source,
mapping, eligibility and reference censuses. Receipt retries preserve original
bytes and reject conflicting evidence.

A restore plan uses schema `jetstreamer-horizon-holding-restore-plan-v2`, with
`mapping`, `custody` and `admission` bindings. Restore requires an existing
matching remote owner, manifest and object; it performs no remote writes. Its
separate fresh admission must bind the custody digest, restore length, all live
owners and protected free-space minimum. The schema is
`jetstreamer-horizon-holding-restore-admission-v2`; `restore_only` and
`all_live_growth_and_century_floor_protected` must be true, with a valid
`recorded_unix_seconds`, `minimum_free_bytes`, `custody_sha256`, `restore_bytes`
and nonempty `owners` of exact `unit`/`invocation_id` pairs, plus a hash-bound
`capacity_completion`. That completion must name the current accepted fleet:
newer routine/phase ledgers are rejected, the minimum must cover its complete
protected-growth budget, and the declared owners must exactly cover live
controllers, producers and private diagnostics. The admission
producer must derive the complete current census and arithmetic. Use
`holding-admit-restore` with schema
`jetstreamer-horizon-holding-restore-admission-plan-v2` and only `mapping`,
`custody`, and `capacity_completion` bindings. It derives all live owners and
the complete protected-growth minimum, rejects a newer fleet or changed owner,
requires both accepted sampled space and actual current space to cover the
entire restore above that minimum, then fsyncs a private admission. Its output
name binds the exact spec digest. It performs no R2 requests or mutations and
never grants retirement or replay authority. The current five-lane baseline is a lower bound,
not a replacement for additional live claims.

Restore verifies and writes into private staging, enforcing the minimum reserve
before each write. A retry reuses one deterministic partial file and hashes all
remote bytes again from zero. A completed read-only partial is reverified before
atomic no-clobber commit. Conflicting destination bytes remain untouched. The
original owner/mode and source metadata remain in the manifest for the separately
reviewed handoff back to a job; the staging blob is not itself a resumed job.

Custody and restoration explicitly deny local retirement, canonical publication,
runtime checkpoint qualification and job resume. No local-retirement command is
provided here. A holding manifest is neither a canonical `.sha256` sidecar nor
full/plugin/boundary evidence. Qualify an actual small authenticated R2 round
trip under this host's approved prefix before relying on this path, then qualify
artifact-specific retirement and restoration back to a consumer independently.
The isolated public-genesis fixture has been parked under `node_02/` and passed
complete authenticated SHA-256 readback. This establishes real custody, not
ordinary restoration or local-retirement qualification. Healthy replay and
canonical uploader deployments remain unchanged.

`holding-restore-genesis-probe` qualifies the same download, per-write floor,
hashing, fsync and no-clobber restore implementation on the separate OS volume.
Its plan schema is `jetstreamer-horizon-holding-root-genesis-probe-plan-v2`,
with only `mapping`, `custody`, and `capacity_completion` bindings. It accepts
only the exact 20,144-byte public genesis fixture and its compiled digest/path.
It revalidates the fresh complete fleet and every live owner, requires the
accepted century floor to remain 205,211,459,014 bytes, and preserves that floor
on the OS volume. Its fixed root is
`/var/lib/jetstreamer/horizon-holding-public-genesis-probe-20261023-v1`, with
private `restores/` and `receipts/` children. The root must share `/`'s device
and differ from the home holding volume. No restored bytes or probe receipts
are written on home. The distinct probe receipt grants no ordinary home-volume
restore, local retirement, checkpoint, resume or publication authority.

Keep filesystem accounting explicit: build caches under `/var/lib` live on the
OS filesystem on this host. Cleaning them does not free replay space on
`/home/sol`. Likewise, a small successful transport probe is not evidence that
a large job restore fits; ordinary restoration still needs its complete-growth
admission and artifact-specific retirement/restoration gates remain separate.

`holding-inspect136` is a read-only source inspection for the exact retained
99,718,944,924-byte failed epoch136 partial. Its plan schema is
`jetstreamer-horizon-holding-inspect136-plan-v2`, with only `mapping`, `terminal`
and `qualification` bindings. Source path, original device/inode, size, owner,
mode and failure lineage are compiled into the tool. It requires the original
controller and producer inactive with zero restarts and no relaunch/handoff
triggers, no process references to the old lane, the original sealed failure
and stopped-owner receipts, the qualified `node_02/` transport and no adjacent
sidecar. It computes SHA-256 and multipart ETag, rechecks source metadata and
closed ownership, then fsyncs a private holding-eligibility receipt. It uses no
credentials or R2 requests, copies no source bytes and cannot remove the prefix.
The receipt deliberately retains `local_retirement_authorized: false` and
requires separate staged-reference and retirement review. Feed only this
separately sealed eligibility proof to the ordinary no-clobber holding park
operation; neither inspection nor backup repairs epoch136 or qualifies it for
canonical publication or job resume.

`holding-disable136-retry` retires only the configuration of the already-stopped
original136–147 controller. Its plan schema is
`jetstreamer-horizon-holding-disable136-retry-plan-v2`, with `mapping`, `terminal`,
`qualification` and `archived_unit` bindings. It requires the exact original
failure lineage, no live/restarted owner or relaunch/handoff trigger, and the
separately sealed controller configuration with compiled SHA-256. It fsyncs an
intent under
`/var/lib/jetstreamer/horizon-terminal136-controller-retirement-20261023-v1`,
moves that exact configuration inode there without replacing anything, fsyncs
both parents, and masks only the original service with a `/dev/null` symlink.
After manager reload it proves that service remains stopped and masked. It
preserves the sealed backup and moved original, handles a crash between move
and mask, and rejects differing bytes, an occupied retained path or another
symlink. A durable completion records the transition. It neither signals a
producer nor removes replay data, changes active service limits or repairs136.

Run this only in its separate root sandbox with write access to that exact
receipt/configuration-retention directory, the holding state lock, and
`/etc/systemd/system` for the fixed service path. A full holding backup owns the
same exclusive transition lock; let it complete before the configuration action.
Keep the old controller masked during subsequent artifact-specific retirement
so its obsolete staged definition cannot consume a removed local prefix. The
archive still requires authenticated custody, fresh reference checks and a
separately qualified local-retirement path; masking is not archive deletion
authority. Healthy controllers and their immutable deployments remain in place.
