# Isolated v1.6.16 snapshot tests

`jetstreamer-horizon-ram-snapshot-test` runs only the two existing ignored
86,831,488 snapshot load/verify and initialization/freeze tests. It pins the
default-feature test binary `bfa7aadf…`, snapshot `348cba57…` and mainnet genesis
`133f7eae…`. It does not replay entries, generate an archive, qualify a cold
epoch peak, promote a runtime or create a sidecar. The shrink-budget bounded
comparison and full canonical checkpoint/independent/plugin gates remain.

The root supervisor is sealed separately from its hash-bound plan. Use only
`CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL`, including their
effective/ambient set in the systemd sandbox. The supervisor reads existing
private observer/fleet receipts and writes only its exact pre-created root-only
receipt directory under `/var/lib/jetstreamer/horizon-ram-snapshot-tests/`.
The test and its listing command drop to UID/GID 1000 with no supplementary
groups; a real self-probe proves zero effective child capabilities and writable
private `/tmp`. No private receipt permissions are relaxed.

Require `Type=oneshot`, `Restart=no`, `KillMode=control-group`, `Delegate=no`,
`MemoryHigh=112G`, `MemoryMax=128G`, `MemorySwapMax=0`, `TasksMax=512`, and
`CPUQuota=200%`. Set `OOMScoreAdjust=1000` and `OOMPolicy=kill` so a resource
failure stays within this diagnostic. The runner independently requires the
actual cgroup `memory.oom.group` value to be `1`; the host's native
`OOMPolicy=kill` sets it. Do not use unsupported `MemoryOOMGroup=` assignments.
Use `TemporaryFileSystem=/tmp:rw,size=512G,nosuid,nodev,mode=1777`,
`TMPDIR=/tmp`, `ProtectSystem=strict`, `ProtectHome=read-only`,
`ProtectControlGroups=yes`, `PrivateNetwork=yes`, and `NoNewPrivileges=yes`.
Make only the exact receipt directory writable outside tmpfs. A 35-minute
oneshot timeout bounds the supervisor's maximum 30-minute child execution.

Every newly allocated tmpfs page is charged to the 128-GiB cgroup, with no swap.
Even at that cap, at least 384 GiB of the 512-GiB filesystem remains free,
above the current 231,874,716,783-byte century floor. This is not new root-disk
capacity or permission to spend another lane's disk reservations. Keep the
epoch-203 component-reserve correction and all existing guards intact.

`capability` mode verifies the exact sandbox, tmpfs geometry and credential
drop, fsyncs a private receipt and runs no snapshot test or host-memory poll.
It does not verify the fixture inputs. `snapshot-tests` mode additionally
requires a separately hash-bound, no-more-than-30-minute-old routine v2 sample
and matching complete fleet ledger: the exact four existing producer/controller
identities, ten active epoch claims and unchanged six canonical century
samples. It hashes every input, requires at least 576 GiB `MemAvailable`
before and after hashing, proves the exact two-test census, then launches the
unchanged test binary with `RUST_MIN_STACK=134217728`,
`SOLANA_RAYON_THREADS=16` and one libtest thread.

During these tests only, a 15-second safety guard checks the private tmpfs
floor and a 448-GiB host-memory reserve. It stops only its own child process
group, after a durable stop intent, on a trip, timeout or external signal.
An error path also reaps that owned group. Existing producers, controllers and
guards are never signaled. This diagnostic safety guard is not another replay
observation loop; the campaign keeps its single 30-minute cadence.

Capture this diagnostic's own cgroup CPU, memory events/statistics/peak,
pressure and I/O counters before the child and before the supervisor exits.
Store raw bounded counter contents in the intent/result and a best-effort
pre-kill snapshot in any stop intent. Terminal capture failure preserves the
actual child outcome but fails qualification closed. Do not infer memory
throttling from a peak alone: terminal cgroups can disappear before external
inspection. This capture never samples or changes another replay's cgroup.

The 128-GiB envelope is a separate diagnostic generation, not an in-place
change to either prior sandbox or any campaign replay. The 56-GiB soft-threshold
measurement recorded 6,874 high events in five minutes. The subsequent
60/64-GiB measurement (`12f7f0076ee6483b9ab13ea8e042112d`) still timed out:
18,993 high events, 192.6 seconds of full memory pressure, approximately
65.36 GB peak, and no hard-limit/OOM event. Its pre-kill capture contains
37.8 GB anonymous memory plus 26.7 GB RAM-backed snapshot pages. This motivates
a bounded envelope of roughly twice that observed footprint, not a claim
that qualification fits or passes. The unchanged 448-GiB host stop reserve
plus the complete new 128-GiB cap requires a 576-GiB startup minimum; the
worst-case tmpfs free space remains above the century floor. Require a new
immutable executable/plan, exact sandbox capability proof, and fresh matching
observer/fleet admission before launch. Preserve either timeout or OOM as
failure evidence. Never apply these limits to existing campaign replays.

A successful child exit, unchanged input identities and no guard trip produce
a private result, never a publication receipt. Preserve a failing invocation
and its journal/intent; OOM or sandbox failure is not canonical divergence and
must not be called a passing snapshot test. Tmpfs cleanup is confined to the
service's private mount namespace. Do not relabel another snapshot as this
86,831,488 fixture, and do not use live AccountsDb scratch.

## Reserve-stop CPU diagnostic (opt-in only)

`ram-snapshot-eight-core-stopped225` builds a distinct eight-core supervisor.
The 128-GiB, two-core attempt reached the matching native initialization/freeze
checkpoint, but its shared 30-minute test limit expired. Its actual terminal
capture has zero memory high/max/OOM events and 16,030 CPU-throttled periods;
this is not a snapshot-test pass. Keep the same two tests, 128-GiB hard cap,
112-GiB soft threshold, 576/448-GiB host gates, swap prohibition and time bound.

The opt-in build requires the exact immutable epoch-225 launch digest proving
its old 16-core allocation, the exact guard-stop completion digest, and that
same unit still failed with no PID, cgroup or restart. It checks these before
capability proof and again after hashing inputs. A fresh routine observer must
retain the complete four-range census: three exact live producers and the
explicit unavailable epoch-225 diagnostic. Unavailability is not stop proof;
the independently hash-bound guard completion and actual unit check are required.
The matching fleet must contain exactly the nine remaining epoch claims, with
no replacement or foreign producer. Thus the new eight-core diagnostic uses
only part of an actually released 16-core budget; it does not add a replay or
increase the prior fleet operating point. Use `CPUQuota=800%` only with this
sealed feature build. Default builds retain their four-producer, two-core gate.
