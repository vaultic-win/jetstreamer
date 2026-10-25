# Private epoch 223 runtime admission rendezvous

This is a source-only successor to the qualified `69ef773a` parent/runner candidate.
The new code has only been parsed/formatted; no Cargo, runtime capability, issuer,
guard, input test, replay or status publication has qualified it yet. Ordinary
profiles and the exact Bank/original-transaction gates are unchanged.

Only the static parent SHA remains a compile-time pin. Native proof and expiring
admission are now runtime `BoundFile` values; rebuilding an ELF cannot refresh
admission. `epoch223_demotion_runtime.rs` is the authoritative strict Rust schema
for this binary, with unknown fields rejected. Other bounded profiles still
decode their original `Plan` and use a default no-op `before_inputs` hook.

## Plan and actual startup

The new outer schema is `jetstreamer-epoch223-demotion-runtime-plan-v3`. It contains
the unchanged private v1 `plan`, a `mode`, and `prerequisites`. Capability mode
requires no prerequisites; bracket mode requires all of:

- `native_input`, `origin_clock`, `admission_policy`, `guard_executable`, and
  `issuer_executable`, `accounting_executable`, and `accounting_qualification`, each an actual immutable root-owned path/SHA-256 binding;
- `maximum_wait_millis` and `maximum_spawn_wait_millis`, each a positive integer
  no larger than 120,000.

The CLI mode must match the outer plan. A legacy bare plan, an unconfigured parent
pin, an unknown mode, or serialized hook selection cannot admit work.

The common runner checks its genuine systemd membership and empty private
directories, then invokes the private hook **before opening/hashing the worker,
snapshot or genesis inputs**. The hook verifies the exact runtime-plan bytes that
were decoded, captures its own real PID/IID/start ticks/boot/cgroup/ELF/ExecStart
and zero-restart `Type=exec`, `User=ubuntu`, `Restart=no` manager identity. It reads
only small immutable metadata and writes `receipts/rendezvous-start.json` with
those actual facts, the runtime-plan binding and the original epoch clock.

The original start is parsed from the unique e70a PID1 `Started` event in the
pinned `58e40c27...` complete journal. It is 1792806478075 Unix milliseconds.
The root-issued `jetstreamer-epoch223-e70a-origin-clock-v1` must bind that actual
journal and the `f1aa68c4...` retained open-repair receipt. A task's new start time
cannot replace it. No original snapshot, partial archive or failure history is
reclassified or deleted.

## Two one-shot permissions

The control waiter looks only for `receipts/admission-ready.json`; its 100 ms
presence check is a local metadata rendezvous, not a fleet/resource observation.
Its fixed monotonic deadline is at most 120 seconds. The ready schema is
`jetstreamer-epoch223-demotion-control-ready-v1`; it binds a new
`jetstreamer-epoch223-demotion-control-grant-v1` to the actual runner, original
clock, genuine repair task, independent guard and complete accounting context.
The producer remains at MemoryHigh 14 GiB / MemoryMax 16 GiB with swap zero.
This permission authorizes only read-only input hashing. It cannot authorize
native execution or a native memory allocation.

After exact shared input hashing completes, the consumer writes a genuine
`receipts/spawn-request.json` carrying its actual actor, fixed control grant and
original epoch clock. It then waits once for `receipts/spawn-ready.json`, under a
separate maximum 120-second deadline. The root spawn issuer must issue a new
`jetstreamer-epoch223-demotion-spawn-grant-v1` after that actual request. Its
allocation proof must bind the separately qualified corrected accounting helper,
current complete fleet and real kernel allocation. The native bracket envelope
is MemoryHigh 150,000,000,000 / MemoryMax 225,000,000,000 bytes, page-rounded,
swap zero. The separate guard and issuer each add a full 1 GiB obligation.

The original control grant is never renewed or reused as a spawn grant. It need
not remain younger than 120 seconds during slow input hashing. Only the new
post-hash grant must be fresh at its one permitted consumption. The original
epoch clock never resets. Later safety checks retain the immutable consumed
spawn token and actual actor identities; long execution does not age-expire the
consumed grant. Replacement tokens, repeated spawn, malformed data, actor changes
or expired one-shot waits close the invocation gate.

Issuer commands are separately bound:

`EXE issue-epoch223-demotion-control SPEC --spec-sha256 SHA --self-sha256 ELF_SHA`

`EXE issue-epoch223-demotion-spawn SPEC --spec-sha256 SHA --self-sha256 ELF_SHA`

The independent guard command remains:

`EXE guard-epoch223-demotion PLAN --plan-sha256 SHA --self-sha256 ELF_SHA`

The native supervisor still requires source completion.
Every new role, including the guard, remains unbuilt and unqualified. Their interface types are not
execution evidence. The current patch implements two root-only metadata
capture commands in the private utility binary:

`EXE capture-epoch223-origin SPEC --spec-sha256 SHA --self-sha256 ELF_SHA`

`EXE capture-epoch223-task SPEC --spec-sha256 SHA --self-sha256 ELF_SHA`

Origin capture derives the old start from the uniquely pinned PID1 journal.
Task capture independently verifies the live manager/PID/start ticks/cgroup/ELF,
plan and small control kernel envelope before issuing no-clobber launch and task
receipts. Both authenticate their own actual root systemd actor and immutable
executable/spec bytes. They read metadata only and perform no native/R2 operation.
The task receipt alone grants no execution or dashboard publication authority.

The private guard role now has concrete source. Its exact plan also binds
`guard_unit`, `ready_output` and `stop_output`. It captures an independent root
actor, verifies its 768 MiB high / 1 GiB max / swap-zero envelope and exact target,
and holds the original cgroup directory FD. Startup opens both original freeze
and kill controls without writing them before claiming stop capability. Its
15-second local protection checks cover filesystem floor, bounded physical root
and scratch usage, and per-process VMA headroom. A fault first fsyncs a no-clobber
stop intent, then freezes/kills through FD-relative original cgroup controls,
preserving every file. It exits when that original cgroup empties and never
follows a new target invocation. No service has been launched or stop exercised.
The guard pins the original run-root directory FD/device/inode for its lifetime,
rejecting a same-owner replacement before/after every physical measurement. It
reuses the shared reviewed scratch walker (whose default profile limit and output
are unchanged) with the exact root envelope. Only child-disappearance ENOENT may
retry, at most twice, against that same pinned root; other errors fail closed.
Compaction, exhausted retry and replaced-root fixtures are source-only, unrun.
If stop-intent persistence fails, the guard exits without performing an unrecorded
root stop. The producer independently re-observes its original guard every 15
seconds and closes native permission on an exit/identity error. The shared
natural-root runner then sends SIGCONT/SIGKILL only to its unreaped owned child
group before attempting failure-receipt writes, backed by ChildGroup Drop. A
disposable child/receipt-failure fixture covers that backstop; it remains unrun.

Consumed root metadata must be readable through the runner's reviewed sandbox.
Root metadata captures and guard/control-ready outputs use no-clobber root-owned
mode0444 files in an exact original private parent. Deployment must still ensure
that every configured ancestor is readable through the intended sandbox; preserve
root-private originals and publish separately bound copies of approved non-sensitive
evidence where necessary. Do not loosen preserved private evidence. Every
metadata handle is no-follow, bounded, immutable and checked before/after reads.
The existing 15-second protective cadence stays separate from the single
30-minute campaign observation.

## Proof, ownership and status interfaces still to qualify

`NativeProof` requires the new sealed harness `a280b1f4...`, worker `0f8cc22a...`,
worker source `551728fd`, original source-QA binding, exact test name, actual
launch/result/journal and an immutable issuer receipt, successful zero-restart
manager completion, exactly one passed/zero ignored tests and the complete
canonical bootstrap tuple. The capitalization is an exact `u64`, never a float.
Replay entries/bootstrap writes must both be zero, and every replay/root/repair
closure/publication authority is false. The genuine old `526448fa...` harness
proof cannot be renamed into this schema.

`RepairTask` requires an actual actor-launch capture, original clock, static
admission policy and sidecar-inclusive ETA-policy binding. Its launch stage is
`admission-rendezvous`; the status publisher must use wire phase `verification`.
Only actual observed transaction execution permits wire phase `replay`. Native
issuer, complete-fleet context qualification, task/status
publisher and independent guard must be implemented and source/runtime-qualified
in separate exact-223 branches. This consumer does not issue their evidence or
extend the exact-204 recovery contract. Do not advertise a live repair merely
because this plan exists.

The ETA retains the old epoch clock and includes native input, the bracket, new
full-root worker qualification, full cold restart/root, prefix reread, native
handoff or source-correct restart, suffix, assembly, independent checks, upload,
readback and sidecar. No ETA or status is issued here. Genuine lifecycle events
are immediate; routine refresh remains once per 1,800-second replay observation,
with the user-requested out-of-band exception.

The existing conservative memory/floor minima remain unchanged. They are not a
fresh resource fit or permission to retain an obsolete floor; reconcile them with
the current century's evidence and complete fleet before runtime qualification.

The worker still rejects entries from 96544589 onward. Bracket success at
96544588 is not canonical root 96767522 or a complete epoch. Both real Bank gates,
original parent transaction 432 and original Vote remain mandatory. A separate
full-root semantic worker/parent qualification and fresh cold restart remain
explicit, followed by every reread/handoff/477-slot suffix/assembly/publication
gate. No canonical sidecar or R2 authority is introduced.

## Next source QA

After explicit main-target lease transfer, run the new private
`bounded::readiness::tests` and `bounded::readiness::spawn::tests` filters (fixture-only, no native/manager/worker calls),
the original full runner Clippy selection, and a representative unchanged
default bounded profile typecheck. Preserve the previous cumulative artifact
charge, source/lock/tool/native closure pins and every failure. No successful
native or replay qualification is implied by parsing, tests or Clippy.

## Issuing custody contract

Every new control/spawn issuing path must acquire exclusive bounded custody of
`/run/lock/jetstreamer-horizon-admission.lock`: root-owned regular mode0600,
no-follow, single-link, stable device/inode before and after acquisition and at
commit. Keep it through actual actor/fleet/kernel revalidation, any kernel cap
change, durable grant/receipt creation and final identity checks. Never hold it
while waiting for long read-only input hashing. Do not unlink/recreate it to
recover a presumed stale holder: kernel flock releases when a terminated holder
closes its descriptor. Bounded-contention and replacement-inode fixtures remain
unrun. This source helper has not created the real lock.

The current legacy admission helpers do not participate. A new lock does not
serialize them: root must keep all nonparticipating admission paths quiescent
during an exact223 transaction, and all new issuing paths must join this custody
protocol before concurrent admission is permitted. No transaction is authorized
by this document or the existence of the helper.

## Concrete control issuer source

`issue-epoch223-demotion-control` now implements the control half. The static
`IssueSpec` adds `issuer_unit`, `accounting_basis`, `accounting_directory`,
`maximum_lock_wait_millis` and `maximum_acknowledgment_wait_millis`. It no longer
pre-binds a future capacity result: that would create a circular digest through
the actual issuer's ExecStart/spec digest. The static accounting basis binds the
accepted observer/fleet, full protected-guard map and separate qualified driver/
guard receipts. It explicitly requires root's quiescence of nonparticipating
legacy admission helpers; the lock does not establish that fact by itself.

After immutable self/spec/native/original-clock validation, the actual root
issuer takes host custody, rechecks all actors and the small control kernel
envelope, constructs its actual complete context, and executes only the separately
qualified corrected accounting ELF, bounded to90 seconds. Its original root0400
result remains in a pre-existing root-private accounting directory. A byte-for-byte
root0444 copy is created no-clobber in the runner's private receipts. The final
grant binds that result and the actual issuer; the consumer independently checks
the exact helper qualification, complete-accounting result/actor context, fresh
clock and18GiB full candidate budget. No old399 capacity is authority.

The issuer validates the same closed consumer interfaces before publishing the
control grant, custody evidence and ready token. It retains host custody through
final actor/kernel checks and durable publication, then releases it before its
separate bounded local acknowledgment wait. This control command authorizes read-only hashing only. It does not raise target
caps, execute native inputs, renew an old grant, publish status, perform R2
operations or issue the later spawn grant.
This source is formatted but has not been compiled, tested, sealed or executed.

## Concrete post-hash spawn issuer source

`issue-epoch223-demotion-spawn` now implements a separate issuing path. Its strict
static spec binds runtime plan, original control grant, actual post-hash request,
runner, native proof, original guard, issuer unit, accounting basis/directory and
bounded lock/acknowledgment waits. It deliberately does not pre-bind its future
allocation proof. It requires the original runner's consumed-control receipt and
hash-complete request, unchanged original epoch clock, exact native proof, live
original guard and a separately qualified fresh complete-accounting calculation.
No control-grant age reset, repeat spawn or second request is allowed.

Under shared host custody it recalculates the full225,000,000,000-byte producer
plus two1GiB independent actor caps while the producer still has the small
hashing envelope. It rechecks actual disk fit and identities, opens the original
cgroup directory FD, and raises only that target's kernel caps to the closed
native envelope. The immutable allocation proof, separate fresh spawn grant and
ready token bind actual kernel limits, actual helper/result/qualification,
request, custody and live actors. The consumer separately reopens the real
capacity receipt and compares its entire capacity/context, not merely a boolean.
The issuer retains custody through durable publication and final checks, then
releases it and waits for the one bounded actual spawn acceptance.

A failure after a cap increase must preserve that reservation and every receipt;
never blindly lower caps after publishing a grant that the runner may already
have consumed. Root must reconcile the actual target/guard and interrupted
transaction before another admission. Existing nonparticipating paths remain
quiescent throughout. This source remains unbuilt/unexecuted, grants no present
launch authority, and does not substitute for new native-input proof, runtime
qualification, original Bank/transaction gates, full-root work or R2 gates.
