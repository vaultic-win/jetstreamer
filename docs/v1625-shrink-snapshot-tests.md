# Epoch225 shrink-candidate snapshot tests

Build `jetstreamer-horizon-ram-snapshot-test` with the opt-in
`epoch225-shrink-snapshot-tests` feature. The default v1.6.16 profile is unchanged.
This profile pins the selected epoch225 test executable (`18adc9c5…`), snapshot
97199617 (`094d3b28…`, 10,177,204,112 bytes), and mainnet genesis (`133f7eae…`).
It executes exactly the existing v1.6.25 load/verify and initialize/freeze ignored
tests, sequentially, with a test-only 128-MiB stack and 16 Rayon threads. It never
replays entries, generates an archive, promotes a runtime or authorizes publication.

Use the existing RAM supervisor sandbox described in
[the v1.6.16 test guide](v1616-ram-snapshot-tests.md): two CPU cores, 112/128-GiB
memory limits, zero swap, 512-GiB private tmpfs, minimal four capabilities with
an unprivileged child, no network, and only the exact receipt directory writable.
The complete 128-GiB diagnostic cap is reserved above the unchanged 448-GiB host
stop reserve. Maximum child runtime is 1,800 seconds. A 15-second guard can stop
only the diagnostic child group. Kernel counters and actual child outcome are
captured before cgroup teardown. Failure is not snapshot qualification.

Plans use `jetstreamer-private-v1625-ram-snapshot-test-plan-v1`, unit namespace
`horizon-v1625-snapshot-test-*.service`, and receipt directories named
`ram-snapshot-test-225-*` under the normal private snapshot-test root. Capability
mode proves the sandbox and credential drop but does not run the tests.

Test mode additionally requires a fresh, hash-bound routine v2 observation and
matching complete 201–300 fleet ledger. The profile admits only the exact existing
220–223 replay/controller, bounded203 shrink diagnostic, and 216–219 delivery
invocations. It rejects duplicate, foreign, inactive or restarted active claims,
revalidates all active unit commands/identities before and after input hashing,
and preserves the six-sample century floor. A fleet change requires new admission;
do not falsify or rewrite the ledger to pass this gate. Inputs must remain singly
linked, root-owned and immutable. The larger selected-profile debug test binary
has a separate 256-MiB input bound; the legacy profile retains its 64-MiB bound.

Successful snapshot tests still leave bounded resource comparison, full canonical
root/natural completion, independent archive reread, current plugin, publication
and authenticated R2 readback gates outstanding. Epoch226 remains private.
