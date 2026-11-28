# Disposable descriptor-anchored ext4 tree fixture

The fixture tests descriptor traversal and unique physical-extent observation on
disposable trees. It grants no live allocation credit, admission or freeze authority.
The existing `allocation_freeze_fixture_bin.rs` remains independent.

The new `jetstreamer-allocation-tree-fixture` binary has one fixed disposable
root:

`/home/ubuntu/.jetstreamer-private/allocation-tree-fixture927-v1`

Its sole CLI is `--fixture-case NAME`, where NAME is one of six compiled case
names. It cannot accept a root path, epoch, service, cgroup, reservation or
admission plan. All successful observations explicitly report zero capacity
credit and false admission, replay and quiescence authority. It contains no
freezer, process-controller, deletion, network or R2 route. Native test helpers
can create and mutate only the fixed disposable cases; they are absent from
the release binary.

## Mechanics and bounds

The Linux x86_64 profile pins `/` and opens the fixed case through
`openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV)`. There is no fallback.
This intentionally rejects any intervening mount or bind mount, including a
same-device bind at the case/root or an ancestor. `fstatfs` requires the ext-family magic and 4096-byte blocks; a bounded
`/proc/self/mountinfo` parse additionally requires the exact descriptor mount ID
and device to identify `ext4`, since ext2/ext3 share that magic; `statx(AT_EMPTY_PATH, STATX_MNT_ID)` binds every node to the
same mount as the anchor.

Directory traversal uses bounded `getdents64` parsing and descriptor-relative
child opens. O_PATH first classifies entries without opening FIFO/device data.
Regular-file readable opens are checked against that exact initial metadata.
Every inode is globally unique by device/inode; regular files require one link.
Symlinks, devices, sockets, FIFOs, foreign devices/mounts, duplicate inodes and
unexpected Root ownership/modes fail the whole observation. File/directory
fingerprints include every Linux MetadataExt stat field except atime and its
nanoseconds. Atime changes from metadata traversal cannot invalidate the scan.

All discovered file and directory descriptors remain held together through
mapping and final validation. The final pass checks each pinned fingerprint,
mount ID, root-anchored namespace lookup and complete directory membership.
It catches replacement/removal of a pathname even if an old open descriptor
still points at its original inode. It never treats an uninspectable or changed
entry as an empty or unallocated entry.

Each regular file is mapped in chunks of16 FIEMAP extents. Query header/count,
cursor progression, checked logical/physical ends, filesystem bounds, alignment,
reserved fields and LAST placement are validated. A short non-LAST response
continues from the last logical end; zero returned extents proves only the
remaining requested sparse range for that query. The requested range ends at
the file length rounded to a block boundary. Extents crossing that boundary
are rejected, including preallocation beyond EOF; no partial guess is credited.

Only LAST and UNWRITTEN flags are allowed. Unwritten ext4 extents describe real
allocated physical blocks; all UNKNOWN, DELALLOC, ENCODED, ENCRYPTED,
NOT_ALIGNED, INLINE, TAIL, MERGED, SHARED and unknown flags fail. A single global
physical-interval registry rejects overlap across both chunks and files, while
allowing adjacent distinct intervals. `st_blocks` is used only as a consistency
ceiling. Neither it nor a directory upper walk contributes capacity credit.

Hard limits:

| Limit | Value |
|---|---:|
| Regular files |64|
| Directories, including selected root |16|
| Depth |8|
| Total entries |128|
| Parsed directory records across both passes |512|
| Component / complete relative path |255 /1024 bytes|
| One file logical length |64MiB|
| Total file logical length / mapped unique bytes |128MiB /128MiB|
| FIEMAP chunk / total extents |16 /4096|
| FIEMAP calls / checked syscall-loop steps |1024 /4096|
| Monotonic loop deadline |2500ms|

At most80 node descriptors plus the anchor and temporary probe/reopen
descriptors are held. A128-descriptor service limit leaves room for standard
streams and the native harness. Allocation failures, bounds and deadline expiry
return errors without a successful observation. The deadline is checked between
syscalls; it cannot interrupt a blocked kernel operation. A production freeze
window would require an independently qualified outside rescue/watchdog and
its actual native negative controls, never this loop deadline alone.

## Why this is not an allocation lower bound for live work

**An open FD pins an inode, not its allocated extents.** A separate writer can
truncate it, punch holes, relocate extents or change its directory namespace.
Stable metadata and final namespace checks detect many changes, but cannot
establish a common point in time across all files, exclude ABA changes, prevent
post-check mutations or close external writers. There is also a classification
to readable-open race; metadata comparison rejects a changed result, but does
not replace an actually quiescent namespace.

This tool therefore always emits `quiescence_proven:false`,
`fd_pinning_prevents_truncate:false`, `capacity_credit_bytes:0`,
`admission_authorized:false` and `live_replay_authorized:false`, even for its
stable fixture. No output can reduce an existing replay/guard growth claim.

Future live use requires a separately reviewed profile proving every writer
and namespace mutator is quiescent for the entire coherent extent/free-space
witness and its decision interval. It must bind actual owners, cgroups,
namespaces, FDs, original invocations, complete current guards and filesystem
semantics, and prove outside rescue under wrong/reused owners, missing rescue,
expired deadlines, partial freeze and deactivating-original-owner cases. The
925 rescue prototype's active/running requirement is not that production
profile. No live freeze or admission promotion follows from these tests.

## Tests and native cases

Twelve ordinary tests cover actual ext4 mount identity, syscall ABI shapes and closed namespace; metadata
rejection; genuine variable-length dirent parsing and malformed/truncated
records; multi-chunk FIEMAP and sparse termination; unsafe flags/alignment;
query/reserved fields and LAST placement; global physical overlap across files;
checked overflow/bounds; and registry/deadline exhaustion.

Six separately ignored native tests create unique case directories with
no-clobber mkdir/create. They retain all fixture files on completion or failure
and refuse to reuse an existing case. They do not touch the925 root or its
completed lease paths:

1. `stable`: nested sparse file with more than16 extents and an empty file;
   require multiple actual FIEMAP calls and all zero-authority output fields.
2. `symlink`: an outside symlink must be rejected without following it.
3. `hardlink`: two names for one regular inode must be rejected.
4. `fifo`: a FIFO must be rejected without a blocking read/open.
5. `bind-mount`: an actual same-filesystem disposable bind must be rejected;
   normal and RAII emergency unmount are limited to that fixture mount.
6. `pin-mutation`: retained descriptors demonstrably permit actual truncate and
   hole punch; the tree's final validation must reject the changed snapshot.

## Shortest next qualification step

First independently review and freeze the complete source graph. Keep Cargo.lock, feature
selection, toolchain/linker closure and the existing925 source/evidence intact.
This utility has no new dependency or feature. Do not use the unverified RAM
cache or a similarly named rlib as an equivalent dependency graph.

Then separately admit LIST, ordinary tests and release using the existing native
compiler guard workflow. Proposed one-job caps are8GiB memory,16GiB new disk and
45minutes per phase; they are requested bounds, not current admission. Keep `DOCS_RS` unset and bind the qualified sealed ClickHouse input through
`JETSTREAMER_CLICKHOUSE_BINARY` and `JETSTREAMER_CLICKHOUSE_SHA256`, as in the
accepted925 build. Also bind `CARGO_INCREMENTAL=0`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0` with empty Cargo features and the exact qualified compiler/linker flags. Full source,
logs, state and output accounting must precede launch. Use the guarded, offline and locked release test/build commands for
`-p jetstreamer-utils --bin jetstreamer-allocation-tree-fixture`; run ordinary
tests with `--test-threads=1`. A successful ordinary run leaves all six native
controls ignored. Native execution requires its own admission.

After test/build success, attest the actual artifact and Rust-seal it with the
test harness, source and exact native-case plan. Admit six independent bounded
native invocations, preserving each real PID1 identity, stdout/stderr, exit,
deadline and zero-authority result. Use one harness thread and fresh case paths.
The native bind test needs CAP_SYS_ADMIN in a private mount namespace; all
other native tests need only actual Root/private traversal and fixture writes.
Preserve evidence and explicitly verify the disposable bind is absent after
that test, including after any interrupted control.

The from-`/` NO_XDEV profile is intentionally incompatible with an added bind
mount on a fixture ancestor. Do not use `ProtectHome`/`ReadWritePaths` projections
that create such a bind, then weaken the scanner to make it pass. A proposed
native fixture sandbox is `ProtectSystem=full`, `ProtectHome=no`,
`PrivateTmp=yes`, `PrivateDevices=yes`, `PrivateMounts=yes`, no network,
`NoNewPrivileges=yes`,128MiB memory,128 FDs and an8second outer start deadline.
The fixture paths themselves stay Root0700 and the frontend remains fixed-root.
Main must inspect the effective mount topology and capabilities in the actual
admitted sandbox. A projection/topology rejection is a valid failed gate.

No native service should retry automatically: existing case directories make
retries non-equivalent. Capture any failure, retain its exact files and qualify
a separately named fixture generation if another run is needed. Do not clean
the old tree or overwrite a sealed deployment to reset a test.
