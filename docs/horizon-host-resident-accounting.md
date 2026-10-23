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

The initial implementation applies this target to the 101–200 control cycle.
Active private diagnostics require explicit accounting before a target is
reported. Older samples without the host census produce an unavailable target;
they are never retroactively populated from a later resource read. A target
grants no launch, stop, restart, archive or R2 mutation authority. Fresh
invocation-bound admission, pressure relief where required, the century disk
floor, one experimental extra lane and a later clean expanded sample remain
independent requirements.
