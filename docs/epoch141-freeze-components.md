# Bounded epoch141 frozen-Bank component diagnostic

The opt-in v1.4.25 worker feature `epoch141-freeze-component-diagnostic` adds
read-only evidence after `Bank::freeze` and before squashing at slots 60911999
and 60912004. Default workers compile these hooks out; healthy deployments keep
their existing sealed worker. The diagnostic accepts only the cold bootstrap
60911751, checking both the archive filename and the loaded Bank slot. It
rejects a transition that skips the diagnostic terminal. After freezing
60912004 it returns an explicit diagnostic-stop error before constructing any
later Bank or executing any later entry. This bound is enforced in the worker,
independently of parent prefetch/progress, archive recording and stdout timing.

Each stderr JSON record has schema
`jetstreamer-private-epoch141-frozen-bank-components-v2` and reports:

- Bank, parent and account-delta hashes; signature count; final blockhash;
  registered hard forks and the exact optional eight-byte hash extension.
- An independent reconstruction of the pinned Bank hash formula. A mismatch
  fails the diagnostic rather than emitting a successful-looking record.
- Account-delta statistics, collector, capitalization, tick heights and Clock.
- Reward count, totals by reward type, and a SHA-256 fingerprint of the full
  typed reward list, rendered in base58. The byte encoding is bincode1.3.1
  `Vec<(Pubkey, RewardInfo)>`, sorted by `(Pubkey, RewardType, lamports,
  post_balance)`. Legacy `RewardInfo` has no commission field. A fixed byte
  fixture supports independent comparison tooling.

All authority fields remain false: the records are neither verified epoch
output nor runtime/publication/remote-mutation permission. A diagnostic stop is
not a repaired epoch. The intended first comparison is against the reproduced
60912004 Bank hash `5TAhovjU9KPhDWsb7Aqugeh2RaACSNkwp7aPMxxe4AGf` and the vote's
expected hash `GtE6AijvzVgK1UKQ5HyVEZMGisDddVWRQkBnM74sjABf`, preserving the
separate original-entry/PoH evidence described in `epoch141-bounded-trace.md`.
The pinned validator already logs the same hash inputs internally, but the
worker does not install a general logger. This narrow diagnostic emits only
the two selected frozen-Bank records.

Qualification on dev-samjohnson used exact Rust1.46.0, offline locked builds,
jobs2, debug0, the existing legacy build-cache child, CPU200%, MemoryHigh12GiB/
Max16GiB, no swap, 512 tasks, read-only source and PrivateNetwork. The full
initial candidate suite passed51tests with2ignored; four refined diagnostic
tests passed, including read-only observation, real hard-fork hash
reconstruction and the legacy reward encoding fixture. Default runtime tests
passed19 with1ignored. The release worker is
`e5600e93710cda7bb2b8cf691c2e6707d307e7957b7023f0551d744b6e240605`.
Its separately sealed actual release HELLO/PING/SHUTDOWN test passed with no
snapshot extraction, Bank initialization, replay or publication.

The sealed worker/source/test package is
`/usr/local/lib/jetstreamer/horizon-epoch141-freeze-worker-20261023-v1`. The
cohesive parent package
`/usr/local/lib/jetstreamer/horizon-epoch141-freeze-parent-20261023-v1` combines
the unchanged original-entry parent with that exact worker. The parent retains
its fixed advertised qualification end61328765; the worker's earlier60912004
stop must be separately explicit in every freeze-component plan, admission and
launch. This package cannot complete that parent qualification or produce a
canonical epoch141 sidecar. Its preparation/guard/fleet namespace must be
distinct from both failed141roots. Fresh protected-growth/floor admission,
actual invocation-bound guard and first timer proof, and full census handoff
remain separate requirements before an unattended diagnostic run.

The first actual run on dev-samjohnson used invocation
`412f43b5db1046a2822efe3aeff95162` from13:10:25 to13:20:35UTC on2026-10-23.
It terminated with the explicit bounded-stop error before constructing a
Bank after60912004. Parent prefetch advertised60912045; that was not executed
progress. The pre-boundary60911999 Bank hash was
`AYzJ6h8BcyraPHeypjd4uhj4L99y7WdMkmeb1L93id7L`, matching that parent in the
earlier failed trace. The frozen60912004 Bank hash was
`GtE6AijvzVgK1UKQ5HyVEZMGisDddVWRQkBnM74sjABf`, matching the later vote's
expected hash, whereas the old sealed worker produced
`5TAhovjU9KPhDWsb7Aqugeh2RaACSNkwp7aPMxxe4AGf` there. This is evidence of
differing executions, not an identified causal fix or full epoch recovery.

The separately sealed Rust `jetstreamer-epoch141-reward-reference` tool issues
one bounded finalized `getBlock(60912004)` request with rewards. It requires
the parent slot and both PoH hashes to match the sealed original-entry index,
retains exact response bytes, and computes the same legacy reward digest.
RPC uses PascalCase reward types; the first collector retained its successful
response but rejected those types. The corrected collector analyzed a sealed
copy of that response in a PrivateNetwork sandbox without another RPC request.
All2640rewards, including exact signed lamports and unsigned post-balances,
matched the diagnostic digest
`23o38tWzJYjLEqcwtGeKRRC1HmeBqGqMHcAHQWDb4AGL`. Totals were fee485000,
staking226821948373 and voting40720061049lamports. RPC does not supply a Bank
hash, and rewards equivalence alone cannot qualify the runtime.

The collector requires a hash-bound immutable plan and separately supplied
self digest. Plans use schema`jetstreamer-epoch141-reward-reference-plan-v2`
and bind curl, an empty root-private output directory beneath
`/var/lib/jetstreamer/horizon-epoch141-reward-reference-*`, and an optional
`retained_response` path/digest. The retained-response path authenticates both
the wrapper and its raw response digest; it performs no network request.
Three tests cover anchored metadata, legacy reward bytes and integers above
2^53, and retained-response corruption. Strict clippy also passed.

Capture native journals with `journalctl --all -o json`: without`--all`, a
large vote/SlotHashes message can be represented as null. Preserve complete
native MESSAGE strings before extracting evidence, and keep consensus counters
as exact Rust integers or original strings. The full earlier trace was
recaptured separately; its original sealed journal remains unchanged.

Static inspection of the exact old and new worker binaries found the builtin
label`solana_bpf_loader_upgradeable_program` only in the new worker. The old
worker came from the retained20261011deployment; it must not be assumed to
implement the current source's corrected additional-builtin table. The source
correction is commit`53947c6d`, and its explicit upstream-table regression is
already present. String presence is a provenance lead, not complete proof of
the old table or the causal difference in execution.

A distinct opt-in follow-up feature`epoch141-vote-prefix-diagnostic` depends
on the frozen-component diagnostic, retains bootstrap60911751, and stops
after freezing60912005. It therefore includes the formerly failing vote at
60912005entry388transaction378, but creates no later Bank. It records the
pre-boundary60911999, transition60912004, and terminal60912005 components;
each record names its worker terminal and whether this follow-up feature is
enabled. Existing sealed60912004deployments are unchanged. Four targeted
diagnostic tests passed under exactRust1.46.0 with one sealed-release probe
ignored pending a separately sealed follow-up binary. This feature is not
launch authority: distinct input/package/profile, guard, admission and fleet
handoff remain required.

The follow-up release worker is
`8f61690a486c5c0322857b25980ec681ec58cfd870b3425cba4bb892e2f4eb9b`,
sealed in`horizon-epoch141-vote-prefix-worker-20261023-v1`; its cohesive parent
is`horizon-epoch141-vote-prefix-parent-20261023-v1`. A separately built and
sealed test harness selected that exact worker path and digest and passed
actual HELLO/PING/SHUTDOWN without loading a Bank. The original60912004profile
also passed its four targeted tests after the optional follow-up was added.

Its separately closed R2 profile uses the unit
`horizon-qualify-141-original-entry-vote-prefix-20261023-v1.service` and root
`/home/sol/.jetstreamer-private/epoch141-original-entry-vote-prefix-20261023-v1`.
It retains the256GiB whole-root stop,1800second runtime bound, CPU2,
MemoryHigh128GiB/Max192GiB, zero swap, and3500000worker-VMA stop. The plan,
admission and launch explicitly bind worker terminal60912005, while the parent
retains advertised end61328765. Every runtime/publication authority stays false.
The routine handoff replaces only the authenticated terminal60912004observer
owner, retains144and all historical fleet claims, and includes the separately
sealed predecessor result in subsequent repair evidence.
