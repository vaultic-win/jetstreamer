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
