# Epoch 225 bounded replay resource runner

`jetstreamer-epoch225-bounded-resource` measures a private replay prefix. It does
not qualify the full cold-epoch peak, promote a runtime, import an archive, or
authorize a canonical checksum sidecar or R2 publication.

The target-stop/capture mechanics are shared with a distinct compile-time
[epoch 203 profile](epoch203-bounded-resource-runner.md). Neither binary accepts
the other profile's plan, unit, private root, snapshot or target. Already-sealed
runner and guard deployments are unchanged.

The exact bootstrap is slot `97,199,617`, accounts hash
`HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi`. The unchanged v1.6.20 worker
and snapshot SHA-256 values are compiled into the runner. Replay stops when the
immutable parent's progress reaches slot `97,202,500`; the underlying focused
plan retains the independently specified canonical root at `97,631,459`.
Stopping at the measurement target does not prove that root.

The bounded runner enables the unchanged worker's historical trace. If a
transaction returns `Custom(2)`, preserve the voted slot/hash, parent Bank
slot/hash, and `SlotHashes` sysvar from the same invocation. This is diagnostic
instrumentation only; it must not normalize a canonical-success/replay-failure
mismatch. The first real run failed during warmup at slot `97,199,878`, entry
165, transaction 189. Its failure and journal remain evidence, not a resource
qualification. Any traced reproduction needs a new sealed runner/plan, fresh
admission, isolated output, and a proven invocation-bound guard.

## Interface and scope

```text
jetstreamer-epoch225-bounded-resource PLAN --plan-sha256 HEX --self-sha256 HEX
```

The root-owned immutable plan uses schema
`jetstreamer-private-epoch225-bounded-resource-plan-v1` and these fields:

- `unit`: `horizon-qualify-225-bounded-resource-*.service`.
- `node`: exact immutable parent `path` and `sha256`.
- `worker` and `snapshot`: immutable paths matching the compiled exact digests.
- `ledger_directory`: immutable source for the digest-bound genesis archive.
- `epoch_hashes`: immutable `path` and `sha256`, containing exactly the bootstrap
  and canonical terminal snapshot filenames.
- `run_root`: an isolated direct child of `/home/ubuntu/.jetstreamer-private`,
  named `bounded-resource-225-*`.
- `target_slot`: `97202500`; `terminal_slot`: `97631459`.
- `minimum_free_bytes`: at least `3185678193366`. Fresh admission may require more.
- `maximum_runtime_seconds`: between 600 and 3600.

Pre-create the replay-user-owned mode-0700 root and its empty `scratch`, `output`,
`receipts`, and `ledger` children. The runner seeds only its private ledger with
a no-clobber copy of verified genesis. The parent runs in focused qualification
mode with explicit verification, checkpoint file, private output, and scratch.
It must not be launched with root-cohort/output-override flag combinations.

## Measurement and shutdown

Target detection is independent of optional throughput counters. Before sending
the controlled SIGINT, the runner freezes its own child process group, proves
all observed group threads stopped, measures the still-live scratch and unique
AccountsDb tree, and captures cgroup CPU, memory/events, pressure, and I/O.
It fsyncs `receipts/target-capture.json`, followed by a compact
`receipts/target-stop.json` binding the canonical JSON capture digest, invocation,
target, observed slot, child PID, and absence of an external signal. It then
resumes the group and requests shutdown.

Only exit 0 or 1 after this authenticated target stop, with no external signal
or measurement error, can produce `receipts/resource.json`. Pre-target failures
remain failures and preserve counters in `receipts/failure.json`. Unexpected
checksum sidecars are a failed gate. None of these receipts grants publication
or local-retirement authority.

## Required before operational launch

Source tests are not launch authority. Commit/push the reviewed source, seal the
runner and exact parent/checkpoint plan, prove the exact parent's focused-225
route and current archive capacity, and pass fresh whole-host admission.

Install and prove an invocation-specific reserve/VMA guard. A bounded-canary
guard must reject zero/multiple/unreadable workers before the target. Its only
zero-worker exception is a short, hash- and invocation-bound post-target drainage
interval backed by the durable target-stop and capture receipts. The ordinary
standalone assembly guard's unconditional zero-worker allowance is insufficient
for this role. Use its separately sealed optional `bounded_canary` profile:
`expected_uid: 1000`, the exact private `target_stop_intent` path, and
`maximum_drainage_seconds` between 60 and 180. It authenticates both the compact
intent and the matching capture; absent, malformed, stale, substituted, or
wrong-invocation evidence cannot excuse zero workers. Do not launch this runner
until the exact deployed sandbox and first real guard fire are qualified.
The first accepted intent and capture are pinned in the root-private guard
directory; replacing either file or moving the timestamp cannot renew drainage.
Do not combine this profile with the separate generic `bounded_measurement`
profile used by older performance runners.

Keep the existing 30-minute coordinated observation cadence; guard and target
events are safety/lifecycle handling, not an additional routine replay poll.
