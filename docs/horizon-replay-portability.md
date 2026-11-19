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

Native v1.7.15 execution remains pending as of 2026-11-19 00:14 UTC. Build
evidence is retained at
`/home/ubuntu/.codex/diagnostics/horizon-checkpoint-portability-v1715-20261119-v1`.
The exact historical Rust 1.52.1 build is isolated from the running workers and
the epoch-205 reader audit. A target-selection error, an intentionally stopped
LTO-inconsistent attempt, a missing shared protocol source, and a compiler
cgroup OOM are retained separately. The source copy now includes and rehashes
both the v1.7.15 subtree and shared protocol schema against published `2e7224fd`.
The current build uses the normal binary test target, one Cargo job, a 2 GB
hard memory limit, no swap, optimization level 3, 16 codegen units and no LTO.
Its invocation is `1074721553ba4d3592d0801573c8ba05` in
`horizon-v1715-checkpoint-probe-build-20261119-v5.service`.

Even a successful synthetic probe leaves protocol export, actual mainnet
checkpoint/restore, partial `.jet` continuation and idempotent pressure recovery
unqualified. Before oversubscribed admission, select a genuinely resumable
victim and bind the tested checkpoint, pressure trigger and recovery path.
Preserve the five healthy replay producers and their hard limits while building
that route. The retained inventory also has a one-epoch 265 cohort, in addition
to 252–256, 257–260 and 261–264; prepare disjoint alternatives rather than
depending on the five-epoch cohort alone. None has new admission authority.
