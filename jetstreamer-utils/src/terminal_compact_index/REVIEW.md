# Terminal compact-index retirement: source review and admission plan

This is a source proposal. No build, test binary, production helper or retirement
has run under this proposal. The saved inventory establishes possible recovery,
not capacity credit or authorization to remove every listed file.

## Genuine cache provenance

Base source: `b8e1f583cc0ac6288ede3d23316dbfa3faa5c18b`.
`jetstreamer-node/src/main.rs::resolve_compact_index_urls` derives two mainnet
index filenames from the epoch CAR root CID. `ensure_compact_indexes_cached`
creates `ledger_dir/compact-indexes` and downloads those indexes when needed;
`ensure_slot_index_cached` also downloads adjacent-epoch slot indexes.
`download_with_ripget` uses a temporary file before publishing a completed cache
member. The default source is `https://files.old-faithful.net` in
`jetstreamer-firehose/src/epochs.rs`.

These downloaded indexes are lookup aids. They are not accounts databases, Bank
checkpoints, replay continuations, `.jet` archives or publication evidence. The
new helper has no downloader, archive reader, remote client or producer-control
route. Regeneration means downloading the same deterministic source URL; this
proposal has not probed source availability and makes no current availability
claim. The admission reviewer must accept that documented reconstruction route
or require separately authorized small remote metadata evidence first.

`jetstreamer-firehose/src/index.rs::parse_compact_index_header` and
`parse_metadata` define the genuine `compiszd` v1 header. The retained actual
epoch-202 fixtures contain `epoch`, `rootCid`, `network` and `kind`, with value
widths 36 and 9. Only the complete 119/130-byte headers were copied, not index
bodies. The helper checks the original header against the exact filename, epoch,
CID and kind. This does not certify index payload correctness, nor is payload
correctness necessary to retire a positively closed, non-authoritative cache.
No invented cache-verification receipt is used.

## Exact scope and preservation

The closed epoch allowlist is 202, 203, 206, 207, 209, 213, 216–222 and 225.
The private owner-root allowlist is explicit in the helper. Both are upper
bounds: an operational plan must list every selected file, actual inode/device,
size, allocated blocks, UID/GID/mode/link count, timestamps, original real header,
source URL and existing canonical readback receipt. Adjacent files outside the
allowlist, epoch 223, old/live epoch-237 state, and every other file are excluded.

Cycle-740 saved metadata is at
`/home/ubuntu/workspace/horizon-cycle740-compact-index-candidates-v1/`:

- `targeted-index-metadata.json`: stat-only expanded candidate inventory.
- `ready-index-files-with-preserved-headers.json`: same inventory with bounded
  real headers for ready members. Non-ready adjacent rows remain present and
  must be excluded using `allowed_ready_epoch`, not the top-level label.
- `preserved-jets-stat-only.json`: preserved original 225/206/207/209 archive
  metadata for the separate cold-holding review; no archive bytes were read.

The expanded ready-only set is 31 files and 114,202,918,912 allocated bytes.
A conservative first subset is ready-202 selected output (4,737,146,880),
ready-213 selected output (7,801,004,032), checkpoint-continuation-203
(4,799,807,488), and ready-216–219 lane-b output (36,136,333,312): together
53,474,291,712 bytes. These figures are saved observations, not a fresh disk
sample. Select only roots with independently pinned retained archives, original
terminal actors and current complete closure. Do not broaden to unfinished
cohorts or roots concurrently used for cold archive upload.

Each owner requires metadata-bound retained `.jet` files and explicit original
actor invocation IDs. Retained files include original ctime and nanoseconds.
Canonical R2 receipts must use the existing
`jetstreamer-horizon-r2-receipt-v1` schema with the exact epoch, bucket, root keys,
positive archive length, lowercase SHA-256 and full remote readback evidence.
The receipt proves the canonical epoch was durably delivered; it does not claim
that an old diagnostic/through-root `.jet` equals that canonical object. Both
archives and all checkpoint, source, compiler, log, metadata and receipt files
remain untouched.

## Closure and interruption behavior

The `staged_body` and `maps_reference` function bodies are copied unchanged from
the independently reviewed old237 helper at the base commit; only visibility
changes. No old237 operational scope is imported. Staged symlink bodies,
systemd masks and device/inode mmap aliases retain that reviewed behavior.
The source checks for this proposal compare those bodies against the base.

All bound actors must be terminal with no PIDs, restart, queued job or changed
invocation. Referencing staged recipes fail unless they are the exact original
direct inert actor entries with pinned bodies. Enabled links, timers and foreign
recipes fail. Full process command, maps, descriptor, cwd/root/exe checks fail
closed, including permission failures and renamed inode aliases with closed
descriptors. The deliberately conservative owner-root match also blocks cold
uploaders using a preserved archive in that root. Choose another root instead
of weakening that closure.

One Root-0700 same-filesystem state directory owns a nonblocking exclusive lock,
global intent, original headers and retained-file bindings. Exact per-file
intent precedes `renameat2(RENAME_NOREPLACE)` quarantine; fresh closure and
preservation checks precede a durable closure receipt and exact fd-relative
`unlinkat`. Parent directories are fsynced using their own descriptors. No
directory is removed, no recursive removal exists, and no filesystem-wide sync
is used. Existing per-file receipts must bind the exact operation and index
before either resumed check-only success or mutation. Missing source and
quarantine are accepted only with the complete durable per-file chain. Changed
tool, plan, source or receipt identity fails rather than resetting anything.

The runtime admission review still must establish the intended host mount and
PID namespace, inspect selected source/quarantine parent mount topology for
nested/bind aliases, pin exact original actor/recipe evidence, and prove there is
no outside relaunch authority. This source does not assert a global atomic
snapshot of process and manager state. Its complete scans repeat before each
custody transition; the immutable launch must retain the reviewed administrative
closure for the duration of retirement. Do not infer those runtime gates from
the saved candidate inventory.

## Bounded build and test proposal — not admitted

Use installed Rust 1.98.0 only after Main independently admits compiler/toolchain,
disk and RAM leases. Do not reuse, clean or modify any original target, b8 target,
Main interpreter state, toolchain map or frame. Allocate a new exact target and
execution leaf, include both in cumulative retained accounting, and preflight
their access with the actual compiler identity and final sandbox properties.

Proposed ceiling: one Cargo job, 8 GiB memory, 1 GiB guard, 16 GiB new disk,
45-minute `TimeoutStartSec` for each phase. These are requested reservations,
not claims that the compiler will necessarily fit; stop without deleting
evidence if a ceiling is reached. The full package dependency graph still
applies when building a single binary. Preserve source, compiler logs and failed
outputs for review; never make room by deleting old targets.

After admission, use a dedicated absolute `CARGO_TARGET_DIR` and independently
bound Cargo/rustc/rustdoc images with the repository lockfile:

```text
cargo +1.98.0 test --locked --offline -j 1 -p jetstreamer-utils --no-default-features --bin jetstreamer-horizon-retire-terminal-compact-index
cargo +1.98.0 build --locked --offline -j 1 --release -p jetstreamer-utils --no-default-features --bin jetstreamer-horizon-retire-terminal-compact-index
```

There are 12 prepared tests: actual header binding and corruption, exact source
scope, receipt rejection for partial/holding/unreadback evidence, original inode
receipt binding, reviewed mmap aliases, staged external recipes, custody
interruption states, and no-clobber rename with a preserved dummy archive.
They have not run. Source-only rustfmt validation is not compilation evidence.

Required later sequence: independent source review; admitted isolated tests and
build; exact artifact/toolchain proof; normal immutable deployment sealing;
Root-owned hash-bound operation plan and source review; metadata-only check-only
closure; independent approval of that concrete closure; admitted exact execution;
then fresh independent free-space/cumulative-root observation. Neither candidate
bytes nor helper completion grants lane capacity before that final observation.
No change to replay/publication qualification follows from index retirement.
