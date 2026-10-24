# Private diagnostic replay measurements

The v2 observer config optionally accepts `diagnostic_replays`, using the same
identity-bound fields as `replays`. Leave private bounded experiments out of the
ordinary `replays` list: they are not public replay or sidecar claims. All ranges
must be disjoint, including partial intersections between the two lists.

Both lists run inside one cadence-gated observation. Each successful diagnostic
uses the same stable before/after invocation and worker checks, two race-tolerant
non-symlink-following physical-block scans, counters, and progress windows as an
ordinary replay. The output `diagnostic_replays` list wraps each result with
`status: "observed"` and its `observation`. Only those successful diagnostic
observations participate in diagnostic cross-sample deltas; they never enter the
ordinary replay census consumed by status publication or fleet replay claims.

An inactive, terminal, identity-changing, unreadable or otherwise failed
diagnostic produces `status: "unavailable"`, an explicit error and no observation.
It is not proof of success, failure cause, terminal identity or resource fit, and
does not suppress the healthy ordinary sample. Inspect the bound service and its
durable evidence in the same control cycle before deciding the next action.
Every diagnostic result explicitly denies ordinary replay, valid sidecar ETA,
replay launch, publication and R2 mutation authority. Reserve/VMA guards remain
independently required and are unchanged by this read-only sampling.

For a standalone bounded runner, bind both controller and producer fields to its
same exact service/invocation, and bind scratch to its actual `--replay-scratch`
directory, not a parent containing output or snapshots. A collected attempt or a
replacement invocation cannot silently inherit its resource history.

Seal the updated observer and config before switching the existing pending
observation service. Preserve its one 1,800-second cadence and next deadline;
never add a second timer or run an extra early sample to enable diagnostics.
