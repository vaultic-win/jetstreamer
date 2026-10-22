# Observer configuration preflight

Before arming a new coordinated observation, run the exact sealed observer's
`jetstreamer-horizon-observe /absolute/sealed/config.json --check-config`.
Older observers without this option must not be assumed to implement it.

This mode uses the same static schema, range-disjointness, invocation-ID shape,
path and minimum-interval validation as sampling. In particular, an old terminal
diagnostic and its live replacement must not both appear with the same range.
Keep terminal diagnostic history in the fleet ledger, not as duplicate resource
claims. Preserve the failed config and seal a distinct corrected config.

The JSON report binds the input SHA-256 and explicitly denies live-resource,
cadence/predecessor, launch and publication verification. It reads no predecessor,
systemd state, cgroups, worker maps or scratch contents, takes no resource sample,
writes no sample, and mutates neither producers nor R2. Success is static
preflight only: normal sampling still enforces the scheduled time, predecessor
interval, live identities, restart counts and before/after resource race checks.
It does not permit an early retry after a failed routine observation.

Qualify and seal a new observer build before operational use. Do not replace or
restart a healthy replay, controller or already-armed observation merely to add
this mode.

## Optional host-global pressure

New observer builds accept `"host_global_pressure": true` (default false). This
adds bounded reads of `/proc/pressure/{cpu,memory,io}` and the host boot ID before
and after the existing coordinated scan, never a second loop. The v2 receipt
reports integer cumulative microsecond totals, within-observation deltas, and
cross-sample deltas only when boot, counter set and monotonic timestamps agree.
The first enabled sample has no cross-sample baseline. Missing/malformed inputs,
counter resets, or a host reboot yield explicit unavailable evidence, never zero
pressure or a failure of otherwise healthy replay/status observation. Static
`--check-config` does not read these proc files.

These counters distinguish host-global contention from pressure caused by a
lane's deliberately low `MemoryHigh`. They do not authorize additional lanes,
relax existing guards, or replace full multi-window admission review. Enable only
in a newly sealed future observer configuration, preserving the single existing
30-minute cadence and all replay identities. Existing armed owners stay intact.
