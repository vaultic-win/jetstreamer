# Exact144 serialized delivery

`jetstreamer-publication144-deliver` is one bounded delivery worker, not a
second progressive coordinator. It never generates replay, overwrites an R2
object, or retires a local archive. Its sealed strict plan binds the exact144
publisher and tracker plans, approved R2 client, endpoint digest, root-private
output directory and the existing global uploader's lock device/inode.

`--check-staged` qualifies configuration, retained independent scan evidence,
kernel capability and client/lock bindings without acquiring the lock, querying
a publisher, hashing an archive or accessing R2. It is not launch/admission
authority. `--check-only` additionally requires the real captured publisher to
be clean terminal success, the committed absence-only canonical publication,
the exact private full/plugin descriptors and original scan identities, and the
fixed canonical checksum and archive identity. No fabricated terminal fixture
can substitute for those production gates.

`--run` additionally requires the exact nonrestarting upload oneshot. It writes
a durable intent before waiting on the same inode-checked mutation lock held
by the unchanged global uploader, then revalidates all terminal/canonical gates
after acquisition. The lock spans the existing Rust client's144-only sync and
owned-status cleanup. Both uploaders therefore serialize even if the global
coordinator independently becomes eligible for144. No live160 upload is stopped
or restarted. The archive-sync child permanently changes to UID1001/GID1003, replaces its
supplementary groups, clears ambient/effective/permitted/inheritable capabilities,
and verifies the drop before exec. The distinct fixed completion-only status
command retains root because publication receipts are root-owned0600. No
arbitrary command or different epoch can borrow that metadata identity.

The only archive command is ordinary `sync --epochs 144-144`; no overwrite,
repair-orphaned, trusted-legacy or local-deletion flag is available. A matching
whole-object-readback R2 receipt is required before archive completion. If owned
status history exists, the approved Rust completion-only status deletion path
performs its ordinary exact-key conditional cleanup. Unknown status ownership is
not deletion authority. Canonical144 and the original private assembly remain
local for ordinary adjacent-boundary retirement policy.

Intent, lock acquisition, upload exit, archive completion, status cleanup and
final completion are separate no-clobber receipts. A failure is not permission
to rerun over an occupied output directory or erase useful artifacts. The real
publication/upload fleet handoff, queued-upload ETA, positive terminal event
capture and inactive-status failure lifecycle must be qualified separately
before this worker or the canonical publisher is armed. Fresh publication
admission remains mandatory; a staged delivery configuration does not refresh it.

The ownership-aware candidate records `launch.json` itself after its durable
intent and before the global lock wait. This covers even a fast idempotent
delivery. `--capture` may verify that same capture or recover a missing one only
while the exact nonrestarting worker is live; it never changes the original
publisher clock. Its initial phase is `queued-upload` before lock acquisition,
or `upload-readback` with an exact durable lock receipt. This is historical
ownership evidence, not a current phase/ETA model: consumers must authenticate
the current worker and fresh downstream evidence separately.

`--terminal` binds the original capture/intent and the exact terminal invocation,
recording service success or failure without claiming authenticated archive
readiness. Both modes validate the sealed plan/client/canonical gate as applicable,
make no R2 request, hash no archive, and never take the global mutation lock or
invoke its client. A separate root-private metadata mutex prevents concurrent
capture writers; canonical complete JSON, fsync, owner-only final permissions
and no-clobber writes prevent partial or foreign receipts from being adopted.
Existing genuine captures are revalidated without overwriting their bytes.
No actual144capture or terminal event is claimed until a real worker exists.

The candidate archive client emits `r2-upload-start`, `r2-upload-progress` and
`r2-upload-committed` JSON events. Progress counts distinct successful part
acknowledgements only after each returned ETag matches the local part MD5;
retries do not count twice, and a short final part contributes its actual size.
Checkpoints cover the first acknowledgement, each additional GiB and the final
acknowledgement. These observations are not integrity receipts: even multipart
commit explicitly leaves `whole_file_sha256_verified` false. The independent
whole-object readback and canonical sidecar gates remain unchanged.

The status parser accepts `queued-upload` only for epoch144, and pipeline
publication further requires the exact144 upload unit and original publisher
binding. The legacy replay status CLI does not gain this phase. Parser support
alone does not qualify the queue ETA, prove an active worker or authorize a
status publication. The delivery worker and composite fleet/status reader must
still bind the separately sealed client before actual use.

The next candidate worker pins the separate progress client and writes
`upload-child-launch.json` (or the distinct status-cleanup counterpart) with the
actual spawned PID, exact client/arguments, owner, plan and spawn timestamp.
This is historical process linkage, not current liveness or archive readiness;
the status consumer must authenticate current process identity and progress.
The worker always waits for its child even if writing that receipt fails, so a
metadata error cannot leave the child unobserved. A regression exercises this
error path and requires the child to have been reaped.

The candidate routine helper supports simultaneous private141 PoH and local144
publication profiles only through the separately pinned composite-capable
progress client. Both original captures, private scan evidence and the full
native141 retry history remain mandatory. Neither older single-profile reader
can be substituted for this combined profile; adding a profile grants no new
replay, publication or mutation authority.

The follow-up delivery gate comparator tolerates only the display timestamps
and PID in systemd's `ExecStart` rendering. Executable/argv, `ignore_errors`,
rendered exit code/status, invocation ID, restart count, every other service
field and all artifact/receipt identities must remain equal. The original raw
receipts stay unchanged. This prevents a daemon reload from falsely rejecting
an otherwise unchanged long-running handoff, without accepting a new owner or
a changed publication gate.

## Authenticated child progress reader

`jetstreamer-publication144-progress PLAN --plan-sha256 SHA --self-sha256 SHA`
is a read-only progress-evidence producer, not the routine status writer. Its
strict `jetstreamer-exact144-child-progress-plan-v1` binds `delivery_plan`,
`delivery_launch`, `child_launch`, and `observer` path/SHA pairs,
`sample_unix_millis`, and a no-clobber `output_receipt` under the precreated
root-owned0700 `/var/lib/jetstreamer/horizon-epoch144-progress-20261022-v1`.
The filename is exactly `progress-SAMPLE_MILLIS.json`. Seal both executable and
plan before operational use. The initial sealed readers accept the pinned v6
delivery worker and progress client only. The nonblocking successor binds v7
and its prior lock receipt; a different worker requires separate qualification.

The reader checks the coordinated v2 sample time, exact live zero-restart
oneshot, historical capture and archive child command. Before and after its
bounded journald read it requires the actual child PID/start ticks, parent,
executable, exact sync argv, cgroup, permanent UID1001/GID1003 and empty
capabilities to agree. Progress messages must have trusted journald PID, UID,
executable, unit and invocation metadata, and timestamps inside that child and
sample interval. Missing executable metadata fails closed. A sandbox probe
showed that a two-second unprivileged child receives its own PID/UID/executable
attribution; a child that has already exited can lack `_EXE` and is not accepted.

The event state machine rejects duplicate starts, regressing/repeated counters,
clock resets, wrong object lengths or digests, out-of-order phase transitions,
and premature verification claims. Idempotent existing-object readback may
start without a new multipart upload. Multipart completion is not whole-object
proof, and successful whole-file readback still owes source revalidation and
the sidecar. Even then the output explicitly denies ready-pair proof and
status/ETA authority. It performs no resource scan, archive hash, lock
acquisition or network request.

The follow-up candidate's `authenticated-child-progress-v2` receipt adds a
definite integer forecast for an authenticated active child, binding the exact
retained198 timing calibration. Upload and ordered readback use the slower of
their actual wall-time rate and byte-scaled historical rate. Wall time runs
through the sample, including a silent interval since the last checkpoint.
The model keeps separate complete readback, source-revalidation and sidecar
allowances; complete multipart and verified readback anchor fixed downstream
deadlines that are never reset or clamped when overdue. Missing rates, stale
progress, a changed calibration or overdue phase fails closed.

Exact trusted client text markers also distinguish initial source hashing,
post-readback source revalidation, and sidecar wait. Each has its own anchored
allowance; neither a revalidation marker nor its completion is sidecar readiness
proof. Duplicate or out-of-order markers are rejected.

This forecast does not model shared-lock queue contention,
adopt an upload into the fleet, or authorize a dashboard update. It does not
retroactively change the sealed v1 reader. Queue handling, the fleet/status
consumer and the exact inactive/failure lifecycle remain separate real gates
before starting144 delivery. Use the existing coordinated cadence; do not create
a second progress polling loop.

## Nonblocking delivery candidate

The successor candidate removes the unmodeled queue: it tries the same bound
global lock once with `LOCK_EX|LOCK_NB`. A busy result creates a private,
no-clobber `lock-declined.json` and exits without a delivery capture, client,
archive/status mutation, retry, or queued claim. It neither unlocks nor stops
the existing owner. Exact terminal capture preserves that declined outcome;
later work requires an authenticated release and fresh, uniquely bound attempt.

Successful acquisition still protects the complete sync/readback/sidecar and
owned-status cleanup operation. The lock receipt must be durable before launch
capture and before the first client. Manual capture rejects the pre-lock state.
This supersedes queue behavior only for the new immutable worker; it does not
change the dormant sealed v6 worker or any running global uploader. The active
child forecast reader must be separately rebound to the new worker digest.
Nonblocking behavior removes a queue-ETA requirement, not the full/plugin,
fleet/status handoff, failure lifecycle, fresh admission or ready-pair gates.
