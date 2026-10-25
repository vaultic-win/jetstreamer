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

The new outer schema is `jetstreamer-epoch223-demotion-runtime-plan-v2`. It contains
the unchanged private v1 `plan`, a `mode`, and `prerequisites`. Capability mode
requires no prerequisites; bracket mode requires all of:

- `native_input`, `origin_clock`, `admission_policy`, `guard_executable`, and
  `issuer_executable`, each an actual immutable root-owned path/SHA-256 binding;
- `maximum_wait_millis`, a positive integer no larger than 120,000.

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

## One bounded handoff

The one-shot waiter looks only for the metadata event
`receipts/admission-ready.json`; its 100 ms presence check is not a fleet/resource
observation loop. Its monotonic deadline is fixed once. Timeout, malformed data,
clock rewind in the state machine, a replacement token, repeated admission or
repeated spawn permanently closes this invocation's gate. Manager identity
commands have an independent two-second bound. Evidence reads and final checks
cannot grant admission after the monotonic deadline.

A reviewed root capture/issuer must verify the real start receipt and live actor,
capture a genuine repair task, arm a separately qualified guard, then issue fresh
admission and publish a root-owned read-only ready file atomically. The ready
schema is `jetstreamer-epoch223-demotion-rendezvous-ready-v1`; it binds the actual
runner, runtime plan and the exact late-created admission file/SHA. The waiter
hashes and parses bytes from one stable no-follow file handle, checks metadata
before and after, and rejects symlinks, hardlinks, writable evidence and drift.

Admission schema v2 binds the actual runner and independent live issuer, native
proof, original clock, admission policy, accepted observer/fleet/context proof,
real repair-task capture, actual guard, and requested/effective kernel limits.
It is at most 120 seconds old. No hand-written optimistic JSON, queued plan,
sleeping stand-in, or previous e70a IID can supply these interfaces. Both guard and
issuer must have separate PIDs/IIDs and exact sealed executable/command bindings.
The issuer's command is:

`EXE issue-epoch223-demotion-admission SPEC --spec-sha256 SHA --self-sha256 ELF_SHA`

The independent guard's command is:

`EXE guard-epoch223-demotion PLAN --plan-sha256 SHA --self-sha256 ELF_SHA`

Their closed spec/plan types are `IssueSpec` and `GuardPlan`. Root helpers beneath
private user-owned ancestors need their reviewed sandbox traversal capability;
do not relax those directories. The issuer must remain genuinely active through
ready-file acceptance and wait for `admission-accepted.json` with its own bounded
acknowledgment policy, then may terminate. No helper implements those commands in
this patch: their exact source/capability/ownership qualification remains required.

All consumed root-owned metadata must be readable through the runner's reviewed
sandbox. Use separately sealed readable copies of approved non-sensitive evidence
or the already reviewed exact traversal capability; do not loosen the original
private evidence tree merely to make a read pass.

The runner independently compares live manager identity, PID start ticks, cgroup,
boot, command, immutable executable bytes and zero restarts before/after capture.
The root-issued guard receipt is responsible for actual `/proc/PID/exe` capture;
the unprivileged runner does not assume it can dereference a root guard's proc
symlink. Ready/admission/task/guard files must bind each other without circular
hashes: task capture binds the static admission policy, while final admission
binds the task capture. The issuer spec binds the already captured actor launch.

Acceptance writes a local non-authorizing receipt. Only then can the existing
input validation run. Immediately before spawn, the runner repeats freshness,
actor/guard identity, ready/admission byte bindings and actual kernel limits,
then consumes the admission exactly once. Later guard checks use the fixed
accepted token and actual guard identity; they do not renew admission or treat
the original admission's age as a 36-hour lease. Identity failures close the
gate. The existing 15-second safety cadence remains separate from the single
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
issuer, actor launch capture, complete-fleet context qualification, task/status
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
`bounded::readiness::tests` filter (fixture-only, no native/manager/worker calls),
the original full runner Clippy selection, and a representative unchanged
default bounded profile typecheck. Preserve the previous cumulative artifact
charge, source/lock/tool/native closure pins and every failure. No successful
native or replay qualification is implied by parsing, tests or Clippy.
