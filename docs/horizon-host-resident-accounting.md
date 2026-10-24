# Horizon resident-memory concurrency planning

The coordinated v2 observer records `host_resident_memory.before` and `.after`
alongside each invocation-bound lane's RSS census. This is part of the existing
30-minute observation, with no additional polling loop. It reads every visible
cgroup process once by PID, verifies its start time and membership, and rejects
an incomplete or changing census. Kernel threads have zero process RSS only
when their kernel-owned `PF_KTHREAD` flag is set. An unavailable host census is
explicit diagnostic evidence and does not invalidate otherwise valid replay
progress or authorize an increase in concurrency.

`MemAvailable` includes reclaimable resident file mappings. Subtracting summed
lane RSS from `MemTotal - MemAvailable` can therefore produce negative apparent
non-lane usage. The capacity report instead uses a consistent resident planning
basis: host process RSS plus `Slab`, `KernelStack`, `PageTables`, and `Percpu`.
Slab children such as `SReclaimable` are not added again. Unmapped file cache is
excluded; shared pages can still be counted in more than one process's RSS.
This is a scheduling estimate, not a measurement of unique physical pages.
`MemAvailable`, pressure, cgroup memory events and existing hard limits remain
separate admission and protection evidence.

The report matches each stable lane process to the same host census by PID and
start time. It subtracts those exact host-census RSS values once to obtain
non-lane resident usage, including kernel allocations. Duplicate controller and
producer coverage counts each process once; a process claimed by two lanes or
a missing/reused PID invalidates the target. With `R` the sum of current lane
RSS, `L` the executing lane count, `N` non-lane resident usage, and `T` total
memory, the marginal lane estimate is `ceil(R / L)` and desired concurrency is
`ceil(max(0, floor(9*T/10) - N) / marginal)`. Disk and CPU do not lower this
memory-selected target. The century maximum from independently valid lane RSS
observations still sets the separate `floor(3*maximum/2)` reservation ceiling.

The implementation applies this target to the 101–200 control cycle and the
201–300 fleet ledger. The latter also counts settled private prefix/root
qualifications as comparable replay lanes when the same accepted sample proves
their stable invocation, zero restarts and useful execution. A repair, restore
or delivery owner consumes separate measured RSS and does not enter the replay
size average. Every live fleet owner must have matching coordinated telemetry;
a newly admitted owner absent from the older sample makes its target unavailable
until that owner's RSS is included. No extra resource poll is taken to fill the gap.
Each campaign uses its own century RSS history and reservation ceiling. Active
private diagnostics use the same PID/start-time matched host census, count shared
controller/producer processes once, and subtract their RSS separately from the
remaining production-memory budget. Their transient RSS does not enter the
production marginal-size average or its current maximum comparison. With `D`
the private RSS and `P` the number of private lanes, the production target is
`ceil(max(0, floor(9*T/10) - N - D) / marginal_production)`; the reported total
desired count adds `P`. Missing private RSS, a changing process census, or a live
fleet owner absent from diagnostic telemetry makes the target unavailable.
Retained admission/launch profiles are history, not evidence of a live lane.
Only current invocation-bound observations and the authenticated fleet census
can contribute live owners.

Older samples without the host census produce an unavailable target;
they are never retroactively populated from a later resource read. A target
grants no launch, stop, restart, archive or R2 mutation authority. Fresh
invocation-bound admission, pressure relief where required, the century disk
floor, one experimental extra lane and a later clean expanded sample remain
independent requirements.

Each capacity decision also reports `expanded_fleet_window` while a private
experimental replay is live. It compares the current and hash-bound predecessor
v2 receipts at least 1,800 seconds apart. The complete production and private
owner sets must match; controller/producer invocations, worker processes and
scratch claims must remain stable, with useful execution progress, valid RSS,
bounded VMAs and no new hard-memory-limit or OOM events. An unavailable private
observation or a replacement with the same lane count cannot qualify the window.

A qualified window advances the next action to current guard/floor review and
explicit operating-point promotion. It does not itself promote the operating
point or admit another producer. This keeps a live diagnostic from causing an
indefinite “awaiting expanded sample” hold after the required evidence exists.
Guard receipts, protected remaining growth, the century floor and fresh candidate
admission remain separate checks. Both the comparison and the memory target use
existing accepted bytes and take no additional resource samples.
