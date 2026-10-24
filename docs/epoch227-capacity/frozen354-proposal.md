# Smaller repaired 227 canary: exact proposal derivation from cycle 354

This is a source-only derivation, not an admission, proposal to launch, live
measurement or completed resource proof. It uses only frozen cycle 354 and
preserved sealed sources. No Cargo, host poll, job change, archive scan, restore,
retirement or R2 operation was performed. Original guards and immutable packages
remain unchanged.

## Existing exact API permits a computed floor

`canary227_admission::run` reads a strict admission spec naming observer, fleet,
canary plan, actual no-worker capability, resource proposal and every protected
guard. It computes growth through `prefix223_live_peer::disk`, then
`native228_admission::protected_floor`, and requires the proposed floor to be
at least that computed floor. `candidate()` requires matching floor/required
free in the plan and proposal; it does not require 2.35 TB.

Preserve the exact repaired selection-v2 identity and actual successful
capability: parent `79963ff4...`, runner `81a804e3...`, worker `d01adb19...`,
guard `90e6fe78...`, canonical checkpoints 98063464/98495291 and bounded target
98091122. Capability proves only the no-worker planning barrier. Its original
capability plan is independently bound; `canary227_capability::scope` does not
require its old resource threshold to equal the new run plan threshold. A new
run plan/proposal therefore need not rerun a Bank or alter the frozen capability.
Keep its actual original receipt, PID1 proof and hashes unchanged.

The candidate is a **300,000,000,000-byte whole-root cap**, including scratch
and output, plus 16,777,216 external control metadata bytes:
300,016,777,216 incremental bytes. Keep memory max 225,000,000,000 requested
bytes, memory high 150,000,000,000, CPU 8 cores and runtime 21600 seconds.
Do not substitute full 210's 471.8 GB envelope, expand this root cap, treat the
target as a checkpoint, grant full-epoch authority or weaken any existing guard.

## Complete frozen disk derivation, including live park 213

Evidence is the accepted 09:13 UTC fleet SHA256
`4dd9ff836bbf4624e496388e085222eb222eb4ee70d7cc53b6e74c73c63fd9f3`
and observer SHA256
`3bc6fb20ac0aa0972bc173038b8071d0ba84799c26b1b1fedc126d2821cbbecb`.
Recorded free is **2,323,934,646,272 bytes**. The 14 ready lengths sum to
1,717,682,084,320; century floor C is **245,383,154,903 bytes**.

The next table preserves complete original growth reservations and exact
allocation scopes. O204/O205 are still-missing, identity-stable physical output
allocations, each capped by the source API at 128 GiB. They are not logical file
sizes or archive-status payload sizes. D209/D223 are nonnegative deficits
between each coordinated whole-root allocation and the minimum of that value
and a qualifying same-invocation guard allocation. A guard must be no earlier
than the accepted observation and meet its existing 1800-second age bound.

| Existing owner | Frozen physical sample | Remaining incremental growth, bytes |
| --- | ---: | ---: |
| 225–226 | Scratch 215,663,988,736; original baseline 179,696,549,888 | 651,227,328,512 |
| 204 | Scratch 156,957,847,552 | 314,840,844,288 − O204 |
| 205 | Scratch 168,103,198,720 | 303,695,493,120 − O205 |
| Full 209 | Whole root 139,918,577,664 | 331,880,114,176 + D209 |
| Native 223 | Whole root 118,010,724,352 | 353,787,967,488 + D223 |
| Live 213 park | Existing source already allocated; no restore copy admitted | 33,554,432 bounded metadata reserve |

The 225 expression is its original 640 GiB remaining reservation less growth
since the authenticated same-invocation baseline. No baseline output credit
was captured; do not add one now or replace this claim with 300 GB scratch.
Full 209/native 223 allocations are whole-root, while 204/205/225 samples are
scratch-only. Their credits are not interchangeable.

Park unit `horizon-foundation-prefix213-park348-v2.service`, original invocation
`e855cc495d17446b983bc98771d357e8`, PID 545547, is explicitly live in cycle
354's **unit census**, even though `auxiliary_diagnostics` is empty and it is
not one of the five replay rows. Its pinned helper is f55b78c3 with SHA256
`1ae341e3ae27e05e8149fe89781704aa58b01359206e98f64d27401bdcb87d69`.
The park has a 6 GiB hard-memory envelope, 256 tasks, one CPU and a four-hour
oneshot start timeout. Its known local 125,316,500,795-byte prefix is already
occupied space; parking uploads/reads it without creating another local full
copy. It supplies **no reclamation credit** until actual custody, retirement
and a new accepted sample prove that. Reserve the source's full two-phase
32 MiB metadata allowance without crediting bytes that may already exist.
That source bounds each receipt to 8 MiB and keeps before/after evidence.

Writing O = O204 + O205 and D = D209 + D223:

```
G, including park metadata = 1,955,465,302,016 − O + D
C + G                     = 2,200,848,456,919 − O + D
P                         = max(C + G, every still-effective guard/internal floor)
required initial free     = P + 300,016,777,216
maximum P fitting 354     = 2,023,917,869,056
```

The effective native 223 floor remains 2 TB. Thus, assuming no stronger other
floor and every other gate passes, concurrent disk fit requires exactly:

**O − D ≥ 176,930,587,863 bytes.**

At the best possible P = 2 TB, headroom is 23,917,869,056 bytes. With no output
credit, the conservative requirement is 2,500,865,234,135 and does not fit.
The frozen evidence does not supply O or qualifying same-sample guard deficits,
so it does not prove concurrent fit. Earlier status payloads record logical
sizes only (and are timestamped 08:42); they cannot fill this missing proof.
A hypothetical later 213 retirement would improve free by its real reclaimed
allocation, not automatically by logical length, and must be assessed from the
later sample rather than booked here.

`frozen354.rs` reproduces this checked-integer arithmetic without accessing the
host, archives or R2. Three `rustc --test -D warnings` regressions passed: no
credit fails, the exact threshold fits and one byte less fails, and original
caps/guard deficits/park claims remain conservative. It is diagnostic arithmetic,
not wired into or accepted by the production admission API.

## Concurrent park memory and follow-up ownership cannot be omitted

The frozen host has 1,212,136,972,288 total bytes and 958,355,189,760 conservative
available bytes. The 227 cap is below the observed century 1.5× RSS reservation
ceiling of 251,041,591,296. Reserve the **full 6,442,450,944 park bytes** when
there is no identity-bound sampled/current cgroup charge; never substitute its
small application RSS or treat unit-census membership as a memory reservation.
Future admission must bracket the actual park caps, kernel memory charge,
zero restarts, original PID/start/cgroup/command and remaining timeout, and add
its remaining hard-cap growth to the existing auxiliary memory model exactly
once. Memory cap accounting uses kernel page-rounded limits where appropriate.

Native 223 also has a separate in-process available-memory floor of 480 GiB;
that remains effective along with its 2 TB disk floor. Existing canary admission
checks the 90% host target and native-peer hard-memory growth, but a future
concurrent-owner proposal must preserve actual older in-process memory
constraints too, rather than assume only ceil(total/10) matters. Keep protected
caps, VMA limits, CPU/task envelopes and pressure checks in the admission; do
not infer all those gates from nominal free RAM.

The current canary API's peer/growth routines model replay and specific native
owners, not this live park. Merely copying the park's unit-census row into a
proposal, or adding an unconsumed JSON field, does not extend those routines.
A concurrent path needs an explicitly typed/bound park auxiliary adapter in
proposal, admission, capture and subsequent peer accounting, with fixtures for
omission, duplicate charge, changed caps/IID, terminal handoff and an attempted
restore. Until that exists, the old API must not be used to claim concurrent
park-inclusive admission solely because its numeric threshold could fit.

The existing Foundation `transition.lock` serializes park, restore and retire
commands for this state directory while the old park holds it. It prevents a
simultaneous same-helper restore now; it does **not** reserve the campaign
resources after the park exits. A future restore could add another full
125 GB copy and invalidate this proposal. Any new concurrent adapter must
therefore also enforce serialized follow-up admission: root's sole dispatcher
must not arm restore/retirement/import work from an old fleet while the canary
claim is outstanding. Each handoff needs a fresh complete-owner census and new
admission including the canary, its metadata and the proposed maintenance owner.
Where an old sealed reader cannot model the new canary it must fail closed,
not omit the owner. A mutual-exclusion claim must bind actual persistent lock
ownership/lifetime or equivalent qualified dispatch guard; a boolean promise
in a proposal is not proof. No lock transfer, service change or new restriction
was installed by this source review.

## Precise next admissible operational action

Keep healthy park/replays unchanged. Prepare a **new plan/proposal derivation**
from the next already-authorized coordinated sample with fresh complete guard
bindings and actual identity-stable 204/205 output physical allocations. Compute
G/P with the shared existing growth functions and park adapter, then write the
same computed P into `resource-plan.json.minimum_free_bytes` and
`resource-proposal.json.guard_minimum_free_bytes`, and P + 300016777216 into
`required_initial_free_bytes`. Bind/seal the actual new plan hash in the proposal;
preserve the old capability and its separate origin plan. Do not copy 2.35 TB.
The complete actual admission still brackets capacity, old owners/caps and
fresh guards; the arithmetic writer must grant no launch authority itself.

For the smallest operational path with currently qualified readers, first let
the park reach its real terminal/custody and complete any separately authorized
retirement handoff under the existing serialized route. Then use a later
accepted sample proving the resulting owner set and actual free space to derive
the smaller 227 plan and run its exact admission/capture/guard gates. Do not
credit retirement in advance. If root instead needs overlap while the park is
live, implement/qualify the typed park accounting and follow-up serialization
above before invoking admission. No native 223 floor reduction or healthy
producer restart is necessary for either smaller-canary path.
