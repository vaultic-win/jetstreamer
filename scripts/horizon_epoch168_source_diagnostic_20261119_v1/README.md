# Epoch 168 source diagnostic

This isolated workspace makes the retained epoch 168 capture and local
extractor source buildable through explicit Cargo packages. It does not
implement a replay correction. Root owns publication, builds, native
qualification, resource admission, source capture and replay.

The initial 13 copied source/fixture files were byte-identical to the reviewed
`/tmp/root-terminal168-next-executable-diagnostic-source-20261111-v1` packet.
`SOURCE_COPY.json` and `SOURCE_MANIFEST.json` preserve that initial inventory.
Later capture changes and qualification are recorded in
[`QUALIFICATION.md`](QUALIFICATION.md). The original flat extractor
layout is retained under `extractor/src`, so its module declarations and all
seven fixture references resolve without source edits. The target remains
epoch 168, slot 72,728,191, entry 433, within-slot transaction 532 and the exact
original signature. Capture, parsing, strict source success, transaction
signature verification, bounds, private output custody and negative authority
fields are unchanged. No old funding template, executable hash, native ID or
resource grant is carried into this workspace.

## Packages and dependencies

`capture` builds `capture168` and contains 16 existing tests. It is the default
workspace member, allowing qualification before compiling Firehose. Its five
direct dependencies are pinned to versions in the current account-updates
checkout's lockfile: reqwest 0.13.3, Tokio 1.52.3, serde_json 1.0.150, SHA-2
0.10.9 and libc 0.2.189. Reqwest has default features disabled and `rustls`
enabled for HTTPS; Tokio explicitly enables `rt`, `net` and `time`.
`Response::chunk()` is available without reqwest's `stream` feature. The
original capture API inspection used cached reqwest 0.13.5; this package
instead selects the parent lockfile's cached 0.13.3. Its required retry,
timeout, HTTPS, HTTP/1, chunk and decompression-disable APIs were inspected
in that exact source. This is a dependency selection, not a claim of native
transport equivalence or prior artifact acceptance.

`extractor` builds `epoch168-source-extract` and retains all 53 existing tests:
28 parser, four writer and 21 normal status-decoder tests. It consumes the
current checkout's real `jetstreamer-firehose` path dependency rather than a
stub or reconstructed parser. Its enabled `epoch168-source-diagnostic`
feature selects Firehose's `verify-transaction-signatures` and
`solana-transaction/verify`. Cargo's selected graph confirms transaction
`bincode`, `blake3`, `serde` and `verify`, and signature `verify`. Every direct
registry version comes from the parent lockfile. The standalone workspace
repeats the parent's three local patches for `solana-program-runtime`,
`solana-svm` and `solana-runtime`; an external path dependency does not inherit
the parent's patch table.

`Cargo.lock` was seeded from the checkout lock and resolved with offline Cargo
metadata. Every retained registry package version and checksum matches an
entry in the parent lockfile. The only new package identities are these two
local diagnostic packages. Cargo pruned unrelated packages and optional
dependency edges. There is no claim that this selected feature graph equals
an existing accepted binary's graph.

`DEPENDENCY_BASIS.json` records the checkout and cached remote ref, selected
repository metadata/source hashes and exact cached API sources. No fetch or
remote containment check was performed. Root must publish these sources and
bind current source/dependency provenance through the normal campaign gates.

## Checks completed without building

Offline `cargo metadata` resolution and locked `cargo tree` selection passed.
Both package targets resolved to files in this directory; all copied files
matched their retained originals and all literal fixture includes existed.
`CARGO_RESOLUTION.json` and `DEPENDENCIES.*.txt` retain that metadata. No Rust
compiler build, Clippy invocation, unit test, native control, network capture,
runtime service or replay was run during this initial packaging stage. All 69
tests were then unrun; this paragraph describes the historical source handoff.

The metadata closure in `CARGO_RESOLUTION.json` includes workspace-wide feature
resolution and is not a count of the objects a package-only build will
compile. The package-specific trees are the relevant selection references.
Capture's displayed normal/build graph has 101 distinct package rows,
including itself; extractor's normal/build/dev graph has 855. These are
source dependency counts, not resource measurements.

## Next command for Root

After Root has booked and guarded an isolated HOME build scope, the smallest
actual test command is:

```sh
/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --offline --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_epoch168_source_diagnostic_20261119_v1/Cargo.toml --package horizon-epoch168-capture --bin capture168 --target-dir /home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1/target -j 1 -- --test-threads=1
```

This names the existing toolchain and real package; it has no placeholder
artifact identity. The target path is a proposed new HOME build location,
not an existing allocation or admission. Root should supply a HOME `TMPDIR`
inside the same admitted scope for build tools and later tempfile tests.
The repository's existing `RUST_MIN_STACK=67108864` Cargo configuration remains
effective when invoked from this checkout. A different build working
directory must retain that configuration explicitly. Serial test execution
avoids multiplying that stack reservation by the host CPU count.

Use the same target, selected graph and explicit one-job limit for strict
production/test Clippy and the accepted production build. The workspace
disables debug information and incremental output for dev/test, and disables
release LTO. These declared profiles are build inputs; do not claim reuse of
an older cache artifact without matching its actual flags and features.

The subsequent extractor test command is:

```sh
/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --offline --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_epoch168_source_diagnostic_20261119_v1/Cargo.toml --package horizon-epoch168-source-extractor --bin epoch168-source-extract --no-default-features --features epoch168-source-diagnostic --target-dir /home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1/target -j 1 -- --test-threads=1
```

Start with the named capture package rather than `--workspace`. Its TLS
backend still includes native AWS-LC and may need C/CMake build output.
The extractor's unchanged Firehose graph additionally includes RocksDB,
Protobuf and other native dependencies. Cached source availability and an
offline metadata pass do not prove a reusable compiled target. No compiled
cache, source copy, build memory, temporary-space or final target allowance
has been measured or reserved here; Root must charge the actual selected
phases and preserve every existing fleet obligation.

## Remaining runtime gates

Passing unit tests will not qualify the native HTTP/TLS/deadline/fsync
controls listed in the retained packet's `RUNTIME_QUALIFICATION.json`.
That adversarial transport harness remains separate work. The retained
`BUILD_AND_NATIVE_QUALIFICATION.md` supplies its required controls, but its
old proposal amounts and placeholder compiler/extern recipes are not current
admission inputs.

After successful qualification, use normally sealed capture and extractor
images with fresh, hash-bound plans and actual guard evidence. Capture's
completion marker alone is not acceptance. Authenticated original target
bytes, historical source linkage, authentic pre-target state, raw VM failure
and a canonical checkpoint-proven correction remain necessary before an
epoch 168 replay recovery. This workspace grants no runtime launch, resource
credit, archive publication or R2 mutation authority.
