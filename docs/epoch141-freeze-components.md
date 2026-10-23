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
