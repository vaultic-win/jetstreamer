# v1.6.15 capped-shrink candidate

The v1.6.15 worker's optional `capped-shrink-candidate` feature caps accumulated
shrink debt to `ACCOUNTS_SHRINK_RECOVERY_PER_ROOT` after storage maintenance.
This follows that exact pinned runtime's `AccountsBackgroundService`, which
caps the returned budget to `SHRUNKEN_ACCOUNT_PER_INTERVAL`. The default build
retains its original uncapped behavior. Already deployed workers keep their
original digests and invocations.

From `historical-runtime/v1_6_15`, qualify the code with the pinned toolchain:

```sh
SOLANA_RAYON_THREADS=2 RAYON_NUM_THREADS=2 CARGO_BUILD_JOBS=2 \
  cargo +1.51.0 test --offline --locked \
  -p jetstreamer-historical-worker-v1-6-15 \
  --features capped-shrink-candidate -- --test-threads=2
```

Also run the `runtime::tests::` group without that feature and with bounded
threads. Unbounded parallel Bank tests can exhaust the service's task ceiling;
`ThreadPoolBuildError` with `EAGAIN` is a test-resource failure, not successful
qualification. The debt regression checks small and extreme prior debt and
preserves the account write cursor, balance, capitalization, last blockhash,
and frozen Bank hash. The worker handshake remains explicitly `Candidate`.

Those tests do not qualify epoch 186 inputs, a cold replay, a smaller scratch
budget, canonical checkpoints, or publication. A private resource experiment
needs a distinct sealed worker/node package, actual input capability, fresh
invocation-bound admission, bounded private output and scratch, reserve/VMA
protection, and its first real guard timer fire. Bind the feature and exact
worker digest in every plan and receipt. Retain the century floor and all live
remaining-growth claims; do not transfer the 200–300 century's 300 GB planning
assumption to epoch 186. Ordinary archive verification, current-plugin checks,
R2 readback and sidecar gates remain independent.

The modern utility feature `epoch186-shrink-root-prefix-resource` builds
`jetstreamer-epoch186-shrink-root-prefix-resource`. Its initial enabled command
is `PLAN --plan-sha256 HEX --self-sha256 HEX --storage-capability`; replay
without that flag is denied pending separate admission and guard qualification.
The capability path rehashes the exact sealed parent, capped worker, bootstrap,
genesis and two checkpoint names, writes a private receipt, and returns before
resource measurement, worker spawn, snapshot restoration or archive creation.
It binds `/home/sol/.jetstreamer-private`, bootstrap 80351283 and terminal root
80783539. The prospective 431540-slot output starts at 80352000 and excludes the
remaining 460 epoch slots. The experimental scratch stop in the profile is not
a qualified full cold-epoch budget. A capability receipt grants no replay,
runtime promotion, complete-epoch, sidecar or R2 authority.

The 101–200 routine coordinator reports `capped186_budget` alongside its memory
target and expanded-fleet window. The prospective whole-root stop is 512 GiB,
including output; this remains an experimental stop rather than a demonstrated
full cold-epoch peak. The report retains the five production growth claims and
their earlier scratch maxima, checks current scratch against those claims, and
adds the live capped 141 run's remaining growth separately. It credits only the
smaller of that run's two physical scratch measurements against its 512 GiB stop;
indices and archive output receive no consumption credit. It never removes an
existing reservation or changes a running guard.

At the accepted 2026-10-23 14:56 sample, the five-lane baseline was
3,572,465,819,078 bytes, capped 141's conservatively remaining growth was
531,032,023,040 bytes, and the prospective 186 stop added 549,755,813,888 bytes.
Against 4,175,301,214,208 free bytes this left a477,952,441,798-byte deficit.
Recompute this from each accepted sample; do not omit 141 because its current
scratch is small. A disk-fit result is still planning evidence only. Fresh
admission must revalidate current guards, floor, growth, source capability,
claims and resource sharing, with a sealed invocation-bound launch and capture
path before replay. Verified offload or a separately admitted bounded resource
experiment can resolve a missing execution envelope while preserving the
memory-selected concurrency target.
