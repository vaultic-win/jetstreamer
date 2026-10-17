# Horizon host utilization

Use this guidance whenever choosing replay concurrency, resuming a host, replacing a completed
lane, or deciding whether the machine can safely do more work. The objective is verified,
upload-ready epoch throughput per wall-clock day, not a high instantaneous CPU or RAM percentage.

## Establish the operating point

Inventory exact live producer/controller invocation IDs, zero-restart state, managed epoch claims,
scratch paths, guards, and authenticated R2 ready pairs before making a capacity decision. Exclude
duplicate or already-complete work. Record the host totals and the effective limits that can block
another lane:

- controller CPU arithmetic and per-lane quota;
- protected memory, memory reserve, scheduling admission, `MemoryHigh`, and `MemoryMax`;
- physical scratch use, evidence-backed remaining-growth claims, candidate incremental peak, and
  the current century floor computed as twice the mean canonical `.jet` size;
- live worker VMA counts, `vm.max_map_count`, the configured VMA stop, and credible VMA growth;
- I/O pressure, major faults, memory pressure, and any current verifier, uploader, or snapshot
  activity that materially contends with replay.

The safe target is the minimum capacity allowed by all of those limits, further bounded by runtime
compatibility, non-overlapping work, and available invocation-bound guards. Free RAM, free disk, or
low load alone never establishes the target. Conversely, do not let conservative static CPU or RAM
estimates strand capacity when exact multi-window evidence supports a fresh sealed admission
generation under unchanged hard ceilings and reserves.

Call the highest concurrency demonstrated by a clean coordinated observation under equivalent
runtime, lane shape, reserve policy, and guard settings the **proven operating point**. A valid
sample binds every live invocation and scratch tree before and after measurement, reports zero
restarts, preserves the century `.jet`-derived filesystem floor, and remains below the VMA stops.
Do not transfer a proven count between materially different machines or lane shapes without new evidence.

## Keep the host work-conserving

- Maintain one disjoint next candidate in a dormant, no-trigger state whenever missing compatible
  work remains. Preflight its manifest, immutable package, cached input, isolated GCloud identity,
  controller configuration, hashes, and capability evidence while current lanes run. Preparation
  is not launch authority.
- When a lane completes cleanly or leaves the fleet, treat that terminal transition as an event,
  not a reason to wait for the next routine poll. Recompute fresh admission and backfill promptly up
  to the proven operating point. The 30-minute cadence limits routine sampling; it does not require
  an avoidable 30-minute idle slot after an authenticated completion event.
- Do not start a producer until its exact invocation can be guarded. If invocation IDs exist only
  after launch, start the dormant controller under observation, immediately bind and prove its
  reserve/VMA guard, and do not leave it unattended before the first real sandboxed guard fire.
- If current concurrency is below the proven operating point and every gate passes, launch the
  staged replacement. If it does not launch, record the exact binding limiter or missing evidence;
  “waiting for utilization” is not a blocker.
- Overlap independent full verification, plugin verification, authenticated R2 upload, and remote
  readback with replay. Keep their receipt gates independent, and account for their measured I/O,
  CPU, and memory pressure when admitting another replay lane.
- Prefer independently replayable and publishable singleton epochs. Keep as many disjoint,
  root-verifiable singletons parallel as fresh admission and the proven operating point allow, and
  promptly fill every safe lane. Reuse sealed snapshot inputs where possible, but do not trade away
  per-epoch completion, verification, upload, and sidecar latency merely to avoid setup work.
  Preserve already-healthy legacy multi-epoch replays rather than restarting them.

Use event-driven systemd dependencies or timers for completion, guard, verifier, and uploader work
instead of frequent polling. Routine coordinated observations remain at least 1,800 seconds apart.

## Scale beyond the proven point

Increase beyond the proven operating point by exactly one replay lane at a time; capacity at or
below the proven point should be filled concurrently as soon as each singleton passes admission.
Before an experimental increase, require a fresh clean
coordinated sample of the current fleet taken at least 1,800 seconds after the preceding routine
sample, current no-trip guard receipts, complete admission arithmetic, and a dormant candidate with
disjoint work. Keep hard cgroup ceilings, the century `.jet`-derived filesystem floor,
evidence-backed remaining-growth protection, and VMA stops unchanged.

After launch, capture exact controller and producer invocation IDs, install and manually prove the
invocation-bound guard immediately, and require its first real sandboxed timer fire to succeed.
The new count is not the proven operating point until a later clean coordinated sample covers the
entire expanded fleet for a stable window. Do not admit another experimental lane before that
sample. On a guard trip, pressure event, restart, identity mismatch, or reserve erosion, stop
scaling, preserve evidence, and follow the normal guarded recovery path.

## Decide from throughput, not appearance

At each coordinated sample, report both resource headroom and useful work:

- aggregate and per-lane transactions, account updates, or equivalent replay progress per second;
- physical scratch and VMA growth per unit of useful work;
- effective CPU, memory current/peak/events, major faults, pressure, and I/O;
- verification/upload backlog and ready-pair completion cadence;
- the current proven point, live count, staged candidate, and the exact limiter on another lane.

Compare settled incremental windows at equivalent work. A new lane is beneficial only when fleet
completion cadence improves without unacceptable per-lane collapse, pressure, reserve risk, or a
growing delivery backlog. If added concurrency reduces verified-and-uploaded throughput, return to
the last proven point through the guarded controller path; do not stop arbitrary unbound workers.
