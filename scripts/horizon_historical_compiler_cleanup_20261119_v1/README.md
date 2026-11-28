# Historical-runtime compiler output cleanup

Source-only successor to the completed focused169 partial compiler cleaner.
No builds, service changes, Git mutations, resource reservations or deletion
were performed by this package's author. Rustfmt parses the sources.
The source defines **35 tests**: the inherited 31 plus historical profile
isolation, terminal-owner census validation, generated/fingerprint retention,
and preservation of top-level historical workers and all their hardlink aliases.

## Closed profile

All paths below are under
`/home/sol/workspace/jetstreamer/historical-runtime/`.
All five profile directories are device 64512, uid/gid 1001, mode 0775.
The selected profile list and order cannot be supplied at runtime.

| Relative profile | Inode | Observed total allocated bytes |
| --- | ---: | ---: |
| `v1_4_25/target/debug` | 346823437 | 3,663,683,584 |
| `v1_4_25/target/release` | 346816537 | 875,458,560 |
| `v1_0_8/target-epoch11-probe/debug` | 346896733 | 3,572,957,184 |
| `v1_0_8/target-epoch11-probe/release` | 347211139 | 756,273,152 |
| `v1_6_20/target/debug` | 345244526 | 3,083,104,256 |

Total profile allocation: **11,951,476,736 bytes**. This is not selected,
reclaimable or promised capacity. Native check must compute selected allocation,
and a separate current free-space observation after successful retirement must
fund the next admission. Every ancestor and every directory inode remains.

The existing shared mutation lock is
`/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock`,
dev64512 ino101135013 uid1001 gid1003 mode0600 nlink1.
The nine Cargo locks below are dev64512 uid/gid1001 mode0664 nlink1.

| Relative lock | Inode |
| --- | ---: |
| `v1_4_25/target/debug/.cargo-lock` | 346823441 |
| `v1_4_25/target/release/.cargo-lock` | 346816542 |
| `v1_0_8/target-epoch11-probe/debug/.cargo-lock` | 346759925 |
| `v1_0_8/target-epoch11-probe/debug/.cargo-build-lock` | 346759924 |
| `v1_0_8/target-epoch11-probe/debug/.cargo-artifact-lock` | 346759926 |
| `v1_0_8/target-epoch11-probe/release/.cargo-lock` | 346816567 |
| `v1_6_20/target/debug/.cargo-lock` | 345244528 |
| `v1_6_20/target/debug/.cargo-build-lock` | 345244527 |
| `v1_6_20/target/debug/.cargo-artifact-lock` | 345244529 |

Locks are acquired without creation, replacement or truncation. All Cargo,
rustc and sccache processes must be absent throughout the transaction.
Coordinate the audit's legitimate reader builds; do not stop healthy replay.

## Selection and preservation

The copied cache, mount, staged-reference and process modules retain the
predecessor's conservative behavior. Only recognizable ELF, ar, Rust metadata
or LLVM bitcode at Cargo compiler-output positions can qualify. All top-level
executables and every hardlink alias of their inode remain. Unknown files, generated source,
Cargo fingerprints, dependency manifests, logs, all lock files, all directories,
symlinks and external-hardlink groups remain. Cross-profile hardlinks are
external to each profile and remain. This is deliberately not `cargo clean`.

Before unlink, a complete unchanged census is required under held locks.
Each inode group is retained open, every parent is opened without following
symlinks, and descriptor-relative unlinks require stable identity/link counts.
Only the witnessed one-link decrement permits changed ctime. Parents are fsynced.
Postcheck requires selected names absent, preserved members unchanged and
identical directory paths/device/inode/owner/mode/link count. File-backed
receipts use fsync of their own descriptor and parent, never syncfs.

Root-private, immutable consumer review is mandatory. A grep with no matches
is not an indirect-dependency proof. Runtime scans process command lines,
environments, relative paths, cwd/root/exe, maps, descriptors and staged
systemd/user-systemd/cron files. The inherited process reader handles disappearing
PIDs only after positive absence, and its tested kernel/terminal-task exceptions
preserve identity and remaining reference scans.

## Reproduction source

There is no old focused169 fixture or rebase coupling. The cleaner binds its
current committed and remotely contained revision, exact deployed source map
and ordinary deployment seal. It also rehashes the committed source closure for:

- the three historical-runtime trees, including local vendors;
- shared `historical-runtime/protocol-schema` and `historical-runtime/fixtures`;
- root `.cargo`, Cargo.toml, Cargo.lock and rust-toolchain.toml.

The targeted read-only source census found 325 tracked files / 7,798,464 bytes,
with ordinary single-link sol-owned files. Sources must remain byte-identical
to HEAD, and uncommitted/untracked source changes in these roots fail.
The retained historical Cargo.lock files are additionally pinned by inode,
mode and SHA256:

| Runtime | Cargo.lock inode | SHA256 |
| --- | ---: | --- |
| v1_4_25 | 346816680 | 039f82f6f484f133fec7c7acd561ed46feee81ec9bdae0f589a37c23c8d40998 |
| v1_0_8 | 346620151 | 2ae7ba4775bf88870800dcb1161043f9687c726bab810fbe5470b841e13418a8 |
| v1_6_20 | 345243963 | 9838a00bc2ed81771ac0e8c887b81cfd09b29cdd47da9bfbf12387682388e40d |

These are dev64512 uid/gid1001 mode0664 nlink1. Old compiler objects are not
claimed to have been built from the current source revision. Their original
depfiles, fingerprints, generated sources and build records remain, along with
Git history. Source preservation does not establish absence of a current user;
that is a separate required consumer gate.

## Parent qualification

Reuse the existing isolated target; do not create private-root siblings or run
from a selected cache. Through the parent's funded build/guard workflow:

```text
CARGO_INCREMENTAL=0
TMPDIR=/home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1/tmp
/home/sol/.cargo/bin/cargo test --locked --offline --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_historical_compiler_cleanup_20261119_v1/Cargo.toml --target-dir /home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1 -j1
```

Run strict Clippy with the same paths plus `--all-targets -- -D warnings`,
then build using the same paths/jobs. Use the parent's current envelope
(previously serial 1 CPU, 1 GiB, no swap, TasksMax128, 15 minutes).
Do not add another builder between accepted check and retirement.

Commit/push the complete package to account-updates and verify containment.
Seal a new immutable deployment using the normal Rust sealer to:

`/usr/local/lib/jetstreamer/horizon-historical-compiler-cleanup-20261119-v1`

Required members:

- `cleanup`, mode0555, actual qualified executable;
- `artifact-proof.json`, mode0444, with actual `source_commit`,
  `production_sha256`, `tests_passed: 35`,
  `clippy_all_targets_passed: true`, and `sources` mapping every committed
  file in this package to its actual SHA256.

Bind actual test/build receipts and the native review in deployment evidence.
The runtime validates the deployment seal, artifact proof and exact source map.

Create root-owned0700 receipt directories:

```text
/var/lib/jetstreamer/historical-compiler-check-20261119-v1
/var/lib/jetstreamer/historical-compiler-retire-20261119-v1
```

Seal a check plan with exactly:

```json
{
  "schema": "horizon-historical-compiler-partial-cleanup-plan-v1",
  "source_commit": "ACTUAL_40_HEX_COMMITTED_PUSHED_HEAD",
  "cargo_lock_sha256": "ACTUAL_ROOT_CARGO_LOCK_SHA256",
  "indirect_review": {"path": "/SEALED/consumer-review.json", "sha256": "ACTUAL_SHA256"},
  "output": "/var/lib/jetstreamer/historical-compiler-check-20261119-v1/check.json",
  "prior_check": null
}
```

The execute plan changes output to the fixed retire directory's `check.json`
and binds the exact positive check as `prior_check: {path,sha256}`.
Invoke the fixed image as `PLAN --plan-sha256 SHA --self-sha256 SHA`.
Check performs no removal. Execute writes check and no-clobber intent, repeats
all gates, then removes only selected groups. An interrupted intent needs
explicit reconciliation; do not overwrite output or retry blindly.

## Required consumer review

Use schema `horizon-historical-compiler-consumer-closure-v1`, owner `/root`,
exact ordered absolute `targets` from the table, and:

```text
no_current_or_staged_consumer: true
no_reopen_until_completion_reconciled: true
terminal_owners_inspected: true
retired_units: [actual historical producer/guard service, timer and path names]
indirect_dependencies: [actual cache-dependent immutable input bindings]
```

Both arrays must be explicit. Empty arrays are acceptable only when the actual
sealed inspection evidence establishes none. Every declared retired unit must
be not-found/inactive/dead, have no command, PID, queued job or trigger.
This is parameterized by the reviewed historical owners; no focused169 unit
is hard-coded. Preserve terminal evidence before the parent closes an owner.

The `classes` array must contain exactly seven rows:

```text
producer-controller
libraries-and-relative-inputs
sealed-launch-plans
timer-path-cron
future-builds
recovery
live-accounting-and-witness-roots
```

Every row requires `class`, `no_local_outputs_required: true`, a specific
evidence-based `reason` and nonempty `inspected_inputs: [{path,sha256}]`
binding root-owned immutable evidence outside selected profiles. Inspected
plans are evidence; actual cache-dependent inputs belong separately in
`indirect_dependencies` and are themselves scanned for live/staged readers.

In particular, inspect and bind the **current166 admission/guard/fleet**,
prepared167 and170 accounting/launch closure, current audit config and its
reader artifact/library closure, recovery/reproduction plans, and any ancestor
witness that accounts these historical targets. Prove the preserved ancestor
directories suffice and no live digest/count witness requires the removed
members. No direct process reference does not prove this. The old staged
grep found no exact target strings in /etc/systemd/system, /run/systemd/transient
or /etc/cron.d; that is merely preliminary evidence, not a current review.

Require a sandbox that can read process state/root-private evidence, and
writable bindings at suitable ancestors: a mount directly on a selected
profile or any descendant is rejected. Do not hide positive references or
weaken permissions. Keep source/receipts outside selected profiles and preserve
all live DATA witness ancestors. Native check, actual cleanup completion,
actual free-space remeasurement and fresh epoch167 admission are separate steps.
