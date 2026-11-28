# Observed hard limits and RSS planning

The century RSS reservation ceiling is a scheduling estimate. It is not the
existing lanes' `memory.max`, and multiplying it by the live lane count does not
reconstruct their admitted hard obligations.

The coordinated observer now captures `memory.max`, `memory.high` and
`memory.swap.max` from each observed cgroup at both endpoints. Its additive
`observed_cgroup_memory_limits` report counts identical controller/producer or
cohort owners once, binds their invocation and cgroup, and uses the lower current
allocation when calculating remaining hard growth. The RSS-based desired lane
count remains independent and unchanged.

Missing, malformed, conflicting or changing limits produce an unavailable
limits report. An explicit kernel `max` is unlimited, represented by `null`;
it never becomes zero or a finite aggregate. Nested cgroups require a separate
hierarchy-aware calculation rather than double counting parent and child limits.
Unobserved diagnostics are counted explicitly. This report covers configured
observed cgroups only: it omits host reservations and unobserved auxiliaries and
grants no admission, limit change, reservation release or replay authority.

## November 19 correction

The 10:56 cycle's operator summary and epoch-211 review incorrectly used the
223,779,342,336-byte RSS ceiling as every live lane's hard cap. The deployed
units instead set epochs 247–250 to 251,041,591,296 bytes each and epoch 251 to
128,000,000,000 bytes: 1,132,166,365,184 bytes in total. The accepted fifth-lane
admission also retains 68,719,476,736 bytes of host reserve and 1,610,612,736 bytes
of launcher allowance, for an original obligation of 1,202,496,454,656 bytes.
The 1,212,136,964,096-byte host then has 9,640,509,440 bytes, booked as the 7 GB
epoch-205 audit plus the 2,640,509,440-byte auxiliary envelope. There is no
unbooked full-hard-growth capacity for another replay.

No lane was admitted using the mistaken summary. The original receipts remain
unchanged; the correction binds their hashes, the accepted admission and all
five deployed unit files in
`/home/ubuntu/.codex/diagnostics/horizon-hard-memory-accounting-20261119-v1/capacity-correction.json`.
These deployment/admission records do not substitute for current effective
limits and ownership checks during a future admission.

The new observer passed 94 unit tests and Clippy with warnings denied. Its
isolated native systemd test read actual 256 MiB hard, 128 MiB high and zero-swap
limits, bound the genuine invocation, and counted the shared controller/producer
cgroup once. Its new telemetry runs within the existing observation cadence;
qualification did not perform an extra production fleet/resource poll.
