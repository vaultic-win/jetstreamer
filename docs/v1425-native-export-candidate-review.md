# Native export candidate: source review only

Base:7106e8db. Isolated worktree:
`/home/sol/workspace/jetstreamer-v1425-native-export-20261023`, branch
`codex/v1425-native-export-candidate-20261023`. The qualified fixture source and
its immutable binaries remain in their original lineage. No worker, test or
dependency was compiled, executed, downloaded or deployed for this candidate.
No live worker, campaign resource observation or R2 operation was performed.

The patch implements the approved design in v1.4.25 only:

- Dispatches the existing ExportSnapshot request and response without editing
  protocol enums, ordering, version, route bounds, builtins or initialization.
- Tracks a one-use Bank/full-checkpoint/raw-cursor/rooted-cache seal. Every
  non-export request and replay path invalidates it; every export attempt
  consumes it, including argument/I/O failures. Cache eligibility errors are
  retained for the next export attempt while the original checkpoint response
  and already-drained writes still return normally; they cannot be silently lost
  through an added fallible check after checkpoint draining.
- Pins and flushes only selected native storage Arcs; checks the original source
  inode/metadata across copy, hashes/revalidates bytes, packages native1.2.0 Bank,
  rooted cache, version and selected AppendVecs using in-process tar/bzip2.
  The private bincode manifest binds the full Bank tuple, raw cursor, source
  identities/lengths/hashes, archive members and persisted archive digest.
- Preserves private staging on both success and failure, fsyncs files/directories
  and publishes by renameat2(RENAME_NOREPLACE). It never invokes host tar, archive
  retention, live hardlinks, overwrite or cleanup.
- Adds unconditional lifecycle/filesystem/error tests for future default and
  capped builds, plus a separately ignored actual-dispatch/fresh-process fixture.
  Existing hash/cursor/cache/signature/output equality assertions remain intact.

## Bounded metadata and remaining qualification gap

The original public native metadata helpers checked32GiB only after streaming.
The separately approved vendor change is exactly `pub(crate)` to `pub` on
`serde_snapshot::bank_to_stream`; its body, NEWER layout, bincode options and
standard helper behavior are unchanged. Export now calls that exact serializer
with `BufWriter<MaximumWriter<File>>`. The file-owning writer refuses a crossing
write before forwarding it and latches failure so buffered-drop retries cannot
write a rejected suffix. Status-cache metadata uses the identical pinned
`bincode::serialize_into(stream, &[BankSlotDelta])` encoding through the same
bounded file writer. Partial files and their directories are fsynced and retained
on error. The runtime's one-use export attempt is consumed before these writes.

Production uses the native32GiB per-file maximum, with no protocol/environment
limit selector. Only cfg(test) state can choose a smaller cap. The ignored API
fixture uses512MiB per metadata file alongside its512MiB selected-storage and
10GiB whole-root experiment limits. Source tests prove a crossing write and drop
retry cannot grow a file beyond its cap, compare bounded Bank/cache bytes against
the unchanged native helpers, and force a one-byte API limit to require an error,
consumed seal, retained bounded partial file and no SnapshotExported response.
These tests are still unexecuted pending admitted compilation.

The visibility-only source hash changed from
`482df258dbcd2930e21c8c40a82300cebeb28858ac9141ecf0149869c6035121` to
`9a6ca01b166b247f6dc5a3d973b641c72ac1a4167d98ab5daaacca32559b8985`.
In this lineage, `snapshot_clock.rs` actually includes and fingerprints
`serde_snapshot/future.rs`, whose unchanged SHA256 is
`4baee9ce91616985b8872b6f77fc3358cce5ca44ef95a7d337d235598d7148db`.
Therefore its LAYOUT_SHA is unchanged. No existing clock/fixture deployment or
the separate f908-based terminal candidate receives a new fingerprint claim.

The synthetic actual-dispatch test injects RuntimeState into Worker entirely
under cfg(test), then calls the real Hello/FreezeCheckpoint/ExportSnapshot
dispatcher. Its fresh child uses the normal native archive loader in the exact
hashed test executable. It does **not** claim an end-to-end production worker
stdio/Initialize test: normal mainnet genesis and snapshot-range validation are
unchanged and intentionally reject this synthetic fixture. Testing that complete
production initialization path requires a separately reviewed, trusted bounded
mainnet-compatible input, or a separately approved test-only process seam.
No synthetic production initialization selector was introduced.
The read-only snapshot-clock binaries also include runtime tests but do not
contain Worker. The actual-dispatch tests are therefore enabled only without
those three diagnostic feature flags; normal default and capped worker profiles
include them. Read-only diagnostic wrappers retain the native helper tests and
cannot acquire an artificial worker dispatcher through this test seam.

## Validation performed and still required

Only source inspection, Rust formatting/parser checks and git diff whitespace
checks were performed. The added tests have not run; default/capped Rust1.46
compilation and all runtime, filesystem, legacy discriminant, native restore and
actual-dispatch fixture tests remain for the parent's admitted build stage.
The ignored fixture retains the existing512MiB selected-storage/10GiB root
experiment limits; generic exporter ceilings mirror the loader and are not a
mainnet resource-admission claim. Unit export artifacts also remain under the
admitted TMPDIR for review.

Before any execution, review these source changes, budget compilation and
retained/staging/archive/restore bytes, seal a new immutable candidate and bind
the exact unit, executable and input hashes. Reuse the qualified pre-exec guard
barrier and exact invocation-bound release lifecycle. Passing a bounded API
fixture would still not authorize a live export, route promotion, writer append,
epoch-specific suffix plan, canonical checkpoint, publication or retirement.
