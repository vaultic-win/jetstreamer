# Historical replay portability qualification

The v1.6.25 isolated probe exercises the pinned native snapshot serializer and
the worker's hardened loader against a small synthetic ledger. It compares an
uninterrupted replay, a separately restored bank, and replay in a fresh process.
The original synthetic replay objects and their storage are dropped before the
fresh process starts. The probe compares complete wire transaction outcomes,
account writes, write versions and the final checkpoint, including bank/accounts
hashes and cursors. An equal balance alone would be insufficient.

Run this explicitly with the exact historical toolchain, from
`historical-runtime/v1_6_25`:

```sh
cargo test --release -p jetstreamer-historical-worker-v1-6-25 \
  runtime::tests::isolated_native_checkpoint_archive_restore_probe \
  -- --ignored --exact --nocapture
```

The test is opt-in because it launches the pinned native packager (including its
system `tar` subprocess) and a second test process. Require one executed parent
test; zero tests selected is not qualification. All files are disposable private
test fixtures. This is a native serialization/restore feasibility result, not a
mainnet runtime, full epoch, partial `.jet`, or R2 qualification.

The worker protocol still rejects `ExportSnapshot`. Before using this path for
pressure relief, implement a candidate export operation bound to the immediately
preceding complete checkpoint, validate unchanged consensus hashes and cursor,
qualify the actual mainnet bootstrap and builtins, and demonstrate recovery of
the partial `.jet` writer. Then qualify authenticated holding transfer and
interrupted lifecycle recovery. Preserve healthy workers while doing so.

The native `bank_to_snapshot_archive` helper squashes, flushes, cleans, updates
accounts hashes and rehashes the bank. It also purges older archives in its output
directory. It must therefore run only in an isolated private staging directory;
it cannot be pointed directly at campaign archives or a holding namespace.
Successful synthetic serialization does not authorize those mutations on a live
producer, replace a checkpoint's evidence, or justify deleting its scratch.

The v1.7.15 worker also rejects `ExportSnapshot`. Its isolated probe is now
published in `worker/src/checkpoint_portability_tests.rs`, included only in the
worker's test module. Select
`runtime::tests::isolated_native_checkpoint_archive_restore_probe` explicitly
with `--ignored --exact --nocapture` on a qualified v1.7.15 test executable.
It freezes the real worker checkpoint before invoking serializer housekeeping,
then requires unchanged bank/accounts hashes, the complete checkpoint tuple,
and write cursor. It compares complete transaction outputs and account writes
after both same-process and fresh-process restoration, deleting the original
fixture state before the latter. This deliberately cannot pass merely because
the serializer and loader agree on a checkpoint changed during export.

Native v1.7.15 execution passed at 2026-11-19 00:22:36 UTC. Build
evidence is retained at
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-portability-v1715-20261119-v1`.
The exact historical Rust 1.52.1 build is isolated from the running workers and
the epoch-205 reader audit. A target-selection error, an intentionally stopped
LTO-inconsistent attempt, a missing shared protocol source, and a compiler
cgroup OOM are retained separately. The source copy now includes and rehashes
both the v1.7.15 subtree and shared protocol schema against published `2e7224fd`.
The v5 attempt also exceeded its 2 GB compiler limit while rebuilding crypto
dependencies. Both failed profile overrides are preserved. The successful v6
build used the workspace's default release profile with no overrides, one Cargo
job, the same 2 GB hard limit and no swap. It reused the original crypto cache
and completed normally in 2m48s with 1.2 GiB peak memory. Its invocation is
`ccffcbcca2d8442593c63393d5fe79ae` in
`horizon-v1715-checkpoint-probe-build-20261119-v6.service`. Actual Cargo evidence
records a test artifact with empty features, optimization 3 and the genuine
`--test -C embed-bitcode=no` compiler invocation. The complete source manifest
was revalidated after the build.

The Rust-sealed test executable is
`/var/lib/jetstreamer/horizon-v1715-checkpoint-probe-2e7224fd-20261119-v1/probe-tests`,
SHA-256 `c7533b3869d406f86bf7286351a9d0712faf3f181881b8ab5cd3a52f114276b7`.
The native unit `horizon-v1715-checkpoint-native-20261119-v1.service`, invocation
`e6619c17368d4a24bdbed2324d2a0bcf`, executed exactly one selected ignored test:
one passed, zero failed, with normal completion in 0.62s. That parent test
requires a clean child-process exit and matching complete restored outcomes.
Its journal is retained as `native-v1.jsonl` in the evidence directory above,
SHA-256 `50479df35a3dca11c230cd5c754b0b5f7d9449f00e9da112c0096e99e394db87`.
The deployed production worker still rejects `ExportSnapshot`; this pass
establishes synthetic native feasibility only.

The next candidate source implements one-use, checkpoint-bound v1.7.15 export.
It binds the complete frozen checkpoint and entry/write cursors, consumes the
seal on every attempt and invalidates it on intervening protocol requests or
batch processing. Export errors terminate the IPC session because storage
housekeeping may already have begun. The packager uses the native v1.7.15 bank
serializer with an in-process sparse tar writer. It checks checkpoint equality
before and after housekeeping, hashes and fsyncs the staged archive, then uses
no-clobber publication into an existing canonical private directory. It does
not invoke system tar or remove older archives. An additive storage accessor
exposes the written prefix and logical mmap capacity for lossless sparse export.

The new ignored `checkpoint_export_archive_restore_probe` exercises the actual
worker export response, archive digest and permissions, duplicate rejection,
unchanged checkpoint, full same-process continuation and fresh-process restore.
Negative tests cover malformed/stale requests, changed checkpoint fields,
intervening Ping/Hello/batch requests, unsafe output directories and existing
symlinks.

Published candidate `335af895` built normally in 2m53s at a reported 1.2 GiB
peak under the same 2 GB cap. Both production worker and test artifacts use
empty package features and optimization 3; the production worker retains the
workspace's LTO/codegen settings. The Rust-sealed deployment is
`/var/lib/jetstreamer/horizon-v1715-checkpoint-export-335af895-20261119-v1`.
Worker SHA-256 is
`8275e240f40a8ce6cbba95bf16266df4e2cd2c8fb398c4ae3a20b02e707966c3`;
test SHA-256 is
`5b177530199ced75930bf5631761b21e65bc862b5b581a075ad2dec71b2081e7`.
The source manifest remained unchanged after compilation. Use the complete
build journal captured with `journalctl --all`: JSON output without that flag
omits long compiler commands. The initial incomplete journal is retained, but
the sealed package contains the complete journal and both genuine rustc commands.

Native unit `horizon-v1715-checkpoint-export-tests-20261119-v1.service`, invocation
`a0c42c32f20f4a0087a36dfa249e3b55`, passed 51 tests with zero failures and seven
explicitly ignored tests. The separate export/restore unit, invocation
`f9cf77e6aa7b4ed9a7ddb5fa7e360e2e`, ran exactly the selected ignored
`runtime::tests::checkpoint_export_archive_restore_probe`: one passed, zero
failed, normal completion in 0.62s. Journals are retained under
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-export-v1715-20261119-v1`.
This qualifies synthetic export/restore behavior, not live worker replacement,
mainnet initialization, archive continuation or pressure admission.

The next opt-in integration probe is
`worker/tests/checkpoint_export_mainnet.rs::epoch265_actual_worker_export_and_fresh_restore`.
It pins the actual sealed worker above and the independently retained epoch-265
bootstrap SHA/size. It uses framed IPC to initialize mainnet, checkpoint and
export; after clean source-worker shutdown and removal of its scratch, it
starts a second actual worker, restores the exported snapshot with the normal
mainnet builtins, and compares the complete checkpoint and cursor. It independently
hashes the export before and after restore and writes a no-clobber fsynced native
evidence tuple. It sends no replay entries and grants no canonical-root or
archive-continuation authority. A bounded synthetic pass does not authorize
its large mainnet restore: prepare a separate full-resource admission first.

Even a successful synthetic probe leaves protocol export, actual mainnet
checkpoint/restore, partial `.jet` continuation and idempotent pressure recovery
unqualified. Before oversubscribed admission, select a genuinely resumable
victim and bind the tested checkpoint, pressure trigger and recovery path.
Preserve the five healthy replay producers and their hard limits while building
that route. The retained inventory also has a one-epoch 265 cohort, in addition
to 252–256, 257–260 and 261–264; prepare disjoint alternatives rather than
depending on the five-epoch cohort alone. None has new admission authority.
