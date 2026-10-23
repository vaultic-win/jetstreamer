# Native v1.4.25 ExportSnapshot: source-only next-step review

This proposal adds no worker implementation, build, deployment, live request,
owner change or epoch-specific continuation plan. The completed synthetic stage
is recorded in `v1425-capped-checkpoint-portability.md` and the sealed result
`/usr/local/lib/jetstreamer/horizon-v1425-guarded-fixture-result-e1f9211414d1485b9f290f34c7c8e774`.
It proves bounded native serialization/restore and fresh-process output equality
for the capped synthetic fixture. It does not qualify a production export API,
default profile, mainnet checkpoint, recorder recovery or publication.

## Proposed change boundary

Use the existing `RequestBody::ExportSnapshot` and
`ResponseBody::SnapshotExported(SnapshotExport)` from
`historical-runtime/protocol-schema/src/lib.rs`. Keep their order, discriminants,
fields and protocol version unchanged. The v1.4.25 protocol facade includes that
shared schema directly. The native snapshot version remains1.2.0; it is separate
from dashboard JSON schema versions.

Limit a future worker patch to the v1.4.25 `main.rs` dispatch,
`runtime.rs` one-use freeze/export state, `snapshot.rs` native packaging, and
associated tests. Reuse pinned native serializer/status-cache APIs already used
by the test-only fixture. Do not copy the v1.0.7 Bank serializer, cleaning call
or sparse-storage accessor: its native layout and APIs differ. Do not change
runtime routing, supported slot bounds, candidate flags, builtins, shrink/clean
policy, source provenance rules or any healthy owner's binary.

## One-use freeze/export state

Add a private `Option<SnapshotExportSeal>` to `RuntimeState`. A seal binds the
successful checkpoint's slot, bank/accounts hashes, last blockhash,
capitalization, transaction count, tick height, complete-slot flag and raw next
write version. It also captures the exact current Bank identity. Do not retain
or re-emit the checkpoint's account writes through the seal: those writes have
already been returned once to the parent recorder.

The existing `freeze_checkpoint` already requires the current complete slot and
zero pending PoH hash count, freezes/roots/squashes the Bank, drains freeze-time
and squash writes, performs the existing maintenance, and calculates accounts
hash. Clear any previous seal before validating a freeze request; create the
new seal only after that complete operation succeeds and the drained cursor
equals `AccountsDb::next_write_version()`.
Require the runtime's last-entry hash to equal the Bank's terminal blockhash.
Restoration remains a completed-slot, next-slot boundary: normal initialization
resets entry/tick counters, so it cannot resume another entry in the exported
slot. Preserve original/bootstrap and newly exported snapshot lineage in the
parent's private manifest without relaxing the existing initialization range.

Adopt the existing v1.0.7 request invalidation contract explicitly: the next
request after a successful freeze must be `ExportSnapshot`. Any other worker
request, including Ping, invalidates the seal; a new successful freeze may
create another. Both individual and streaming batch entry paths must invalidate
before validation or emission, including a failed/partially emitted batch.
Runtime mutation entry points also invalidate independently so direct callers
cannot bypass the dispatcher. Initialization and failed freeze never retain an
old seal.

An export attempt consumes the seal with `take()` before checking arguments or
performing I/O. Wrong slot, wrong/malformed expected accounts hash, destination
failure, existing output or serialization failure therefore require a new
successful freeze. Require the same complete, frozen, squashed Bank, the full
sealed tuple and cursor, and the exact32-byte expected hash. Export does not
freeze again, advance a slot, drain additional writes or invoke additional
cleaning/shrinking. Compare the full tuple and cursor again after packaging;
any change fails closed and preserves private diagnostic evidence.

## Native package construction

Retain the exact selected storage Arcs from `Bank::get_snapshot_storages()` so
their files cannot be reclaimed during the export. Flush every selected
AppendVec and bind a descriptor-stable inventory: slot/store identity, safe
unique archive name, logical length and SHA256. Include exactly these files;
never walk an entire AccountsDb directory or hard-link live state into an output
that another owner may retire. Reject aliases, nonregular files, external
hardlinks, duplicated names and files whose identity/length changes during copy.

Call pinned `snapshot_utils::add_snapshot(..., SnapshotVersion::V1_2_0)` for
native `SerdeStyle::NEWER` Bank/AccountsDb serialization. Bind its serialized
raw global write version to the sealed drained cursor. Native snapshot slot
metadata and selected AppendVec IDs/lengths must agree; independent restore must
continue rejecting missing and unreferenced storage files.

Require the rooted status-cache root set to end at the frozen slot, contain no
future/non-root slot, and agree with the selected rooted deltas. Serialize those
deltas with pinned `serialize_status_cache` into `snapshots/status_cache`, plus
the exact `version` bytes1.2.0. Keep signature status, roots and duplicate
transaction behavior as explicit restore assertions. A matching accounts hash
alone is insufficient.

Create a private owner-only staging directory beneath the caller's admitted
canonical private output directory. Use in-process tar/bzip2 and pinned
`Compression::Fastest`; do not invoke host tar or
`archive_snapshot_package`, whose archive-parent purge behavior is unsuitable.
Bound member count, each logical member size, aggregate selected/copy/archive
bytes, memory and runtime before processing; retain the existing loader's
strict tar/header/AppendVec limits. Bound actual physical growth separately with
the OS guard. The synthetic fixture's512MiB selected-file/10GiB-root caps are
qualification limits, not evidence of a viable mainnet export envelope.

Initially use the selected files' complete validated logical contents. Any
sparse optimization needs a separately reviewed v1.4.25 native length/layout
accessor and compatible tar representation; do not assume the v1.0.7
`snapshot_file_layout` API exists here. A realistic selected-file census and
separate admitted space for staging, archive, restored state and retained
failures precede any larger qualification.

Fsync each member and containing directory. Finish compression, fsync the final
temporary archive, measure its length/SHA256 through the persisted descriptor,
then publish the fixed snapshot filename atomically with no-clobber semantics
and fsync its parent. Never overwrite an existing artifact or invoke retention
cleanup. On failure retain private artifacts with explicit incomplete state;
return no `SnapshotExported` response. On success return only the unchanged
wire fields: slot, archive path, accounts hash, archive size and archive SHA256.
The hash/cursor/inventory proof remains a private qualification manifest; it is
not a new protocol field or archive publication receipt.

## Required validation before deployment review

| Area | Required result |
|---|---|
| Protocol | Existing export/response and legacy discriminant tests pass unchanged; no enum/field/version edits. |
| Seal lifecycle | Reject no freeze, incomplete/wrong slot, pending PoH hashes, wrong hash length/value, repeated export, request/mutation after freeze and stale seals after errors. Every failed export consumes its seal. |
| Raw writes | Freeze emits its writes once. Export emits none and preserves the exact drained raw next-write cursor. Partial batch failure cannot leave an export seal. |
| Filesystem | Reject existing outputs, symlinks, nonregular/hardlinked inputs, changed source identity/length, duplicate/unreferenced storage, missing cache and size/count amplification. Failed publication preserves earlier artifacts. |
| Default and capped | Compile and run both native feature profiles separately with the pinned Rust1.46 offline dependency set and separately owned targets. Existing replay/maintenance tests remain unchanged. |
| Fresh-process equivalence | Exercise the actual future worker export dispatch, not just the test helper; re-exec the exact hashed worker, restore through its normal loader, and compare every checkpoint tuple, roots/cache/signature, raw account write/order/version/attribution and following request/response byte stream to uninterrupted execution. |
| Boundary coverage | Include nonempty transactions, rooted duplicate rejection, skipped-slot transition, enabled PoH tick accounting, freeze-time writes and post-restore entry/tick resets. Extend a bounded synthetic continuation across maintenance triggers to expose reset clean/shrink/leader-cache state differences. |
| Negative restore | Tampered bank/archive/version/cache/AppendVec, wrong cursor or missing source member must fail; never relax equality assertions to accommodate a divergence. |

Use the already-qualified pre-exec barrier for the first separately approved
small production-API fixture. Seal the new worker/launcher/unit/launch manifest,
obtain fresh OS admission including retained trees and all other allocations,
precreate private receipts, bind actualIID/PID/startticks/monotonic, and require
a live exact watcher plus durable no-trip sample and fresh floor before release.
Keep current CPU200%, MemoryHigh12GiB/Max16GiB, swap0, Tasks512, total30-minute
unit cap and owner-only0700 output until separately reviewed. Preserve every
failed attempt and stop/report a consensus, cursor or output mismatch.

A subsecond fixture may complete between the five-second guard samples; report
that observation limit exactly and require the pre-release and terminal proof
chain. A larger fixture needs its own measured selected-storage envelope and
bounded qualification. Passing these stages permits review of an immutable
candidate; it does not promote a route or authorize a live export by itself.

## Separate continuation and delivery work

A native Bank export does not preserve the Horizon writer or recorder's
in-memory state, and their current constructors can truncate an existing file.
Any future application uses separately finalized V2 prefix/suffix archives and
the independently verified V4 merge/provenance path, with exact source cursor,
PoH and raw-write boundaries. Generic export work does not change or authorize
any epoch-specific suffix plan, canonical checkpoint, boundary audit, R2 upload,
sidecar commit, public access or local retirement.

The next decision is review of this proposed implementation boundary. No worker
implementation, production build or deployment was performed while preparing it.
