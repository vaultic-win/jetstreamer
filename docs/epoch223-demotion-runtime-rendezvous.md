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

Actual control/spawn issuers and native supervisor still require source completion.
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

Consumed root metadata must be readable through the runner's reviewed sandbox.
Root capture outputs currently remain root-private; deployment must supply a
separately sealed readable copy of approved non-sensitive evidence or an exact
reviewed traversal capability. Do not loosen preserved private evidence. Every
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
