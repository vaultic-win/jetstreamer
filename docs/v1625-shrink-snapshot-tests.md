# Epoch225 shrink-candidate snapshot tests

Build `jetstreamer-horizon-ram-snapshot-test` with the opt-in
`epoch225-shrink-snapshot-tests` feature. The default v1.6.16 profile is unchanged.
This profile pins the selected epoch225 test executable (`2d878b5a…`), snapshot
97199617 (`094d3b28…`, 10,177,204,112 bytes), and mainnet genesis (`133f7eae…`).
It executes exactly the existing v1.6.25 load/verify and initialize/freeze ignored
tests, sequentially, with a test-only 128-MiB stack and 16 Rayon threads. It never
replays entries, generates an archive, promotes a runtime or authorizes publication.

The first selected-fixture attempt with test digest `18adc9c5…` failed during
tar extraction before native checkpoint verification, without memory/OOM/guard
events. The new test digest adds only nested OS-error reporting and a regression;
it does not relax extraction, hash or checkpoint checks. Preserve that failed
attempt and use a separately sealed diagnostic generation to identify the cause.

The nested error identified inode exhaustion, not a byte or memory limit: the
512-GiB tmpfs exposed 409,600 inodes, while the snapshot contains 416,712 tar
members and extraction failed at member 409,596. Only this epoch225 profile now
requires `TemporaryFileSystem=/tmp:rw,size=512G,nr_inodes=1048576,nosuid,nodev,mode=1777`
and independently checks the mounted filesystem's exact inode limit. Keep the
filesystem byte size and cgroup limits unchanged; the default v1.6.16 mount
options and inode policy remain unchanged.

Use the existing RAM supervisor sandbox described in
[the v1.6.16 test guide](v1616-ram-snapshot-tests.md): eight CPU cores, 112/128-GiB
memory limits, zero swap, 512-GiB private tmpfs, minimal four capabilities with
an unprivileged child, no network, and only the exact receipt directory writable.
The complete 128-GiB diagnostic cap is reserved above the unchanged 448-GiB host
stop reserve. Maximum child runtime is 1,800 seconds. A 15-second guard can stop
only the diagnostic child group. Kernel counters and actual child outcome are
captured before cgroup teardown. Failure is not snapshot qualification.
Eight cores follow the earlier snapshot-test comparison: the two-core run reached
the initialization checkpoint but exhausted its shared time limit. This is a new
diagnostic allocation, not a change to any live producer or its guard.

Plans use `jetstreamer-private-v1625-ram-snapshot-test-plan-v1`, unit namespace
`horizon-v1625-snapshot-test-*.service`, and receipt directories named
`ram-snapshot-test-225-*` under the normal private snapshot-test root. Capability
mode proves the sandbox and credential drop but does not run the tests.

Test mode additionally requires a fresh, hash-bound routine v2 observation and
matching complete 201–300 fleet ledger. The profile admits only the exact existing
220–223 replay/controller, bounded203 shrink diagnostic or the separately sealed
canonical-root203 invocation `748ffa40e0a2408da0a10fc9e160cf0a`, and 216–219 delivery
invocations. It rejects duplicate, foreign, inactive or restarted active claims,
revalidates all active unit commands/identities before and after input hashing,
and preserves the six-sample century floor. A fleet change requires new admission;
do not falsify or rewrite the ledger to pass this gate. Inputs must remain singly
linked, root-owned and immutable. The larger selected-profile debug test binary
has a separate 256-MiB input bound; the legacy profile retains its 64-MiB bound.

Successful snapshot tests still leave bounded resource comparison, full canonical
root/natural completion, independent archive reread, current plugin, publication
and authenticated R2 readback gates outstanding. Epoch226 remains private.
