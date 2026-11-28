# Exact-epoch download and playback capacity

This follow-up is source-only. No build, commit, sealing, configuration or service
change was performed by this repair. The earlier split-scratch artifact and its
qualification do not qualify this new source. Rustfmt and diff whitespace checks
pass; the new tests still require the parent's admitted build slot.

## Why epoch73 was incorrectly waiting

The 05:18 UTC observation supplied by the parent recorded 53,100,396,544 root
bytes free and a 59,378,472,961-byte download requirement. The frozen inventory
gives epoch73 as 13,978,437,633 bytes. The old policy added the full unused
source/build allowance (11,040,296,960 bytes), even though playback can reuse its
sealed current reader.

The repaired non-building requirement for that observation is:

```text
32 GiB existing root floor             34,359,738,368
exact epoch73 archive                 13,978,437,633
bounded log and JSON metadata            167,772,160
total                                 48,505,948,161
historical observed headroom           4,594,448,383
```

This historical arithmetic is not a new capacity observation or launch proof.
The maximum archive size remains a hard acceptance ceiling, not a disk charge.
The existing 16 GiB ceiling still rejects epoch74 (17,431,722,097 bytes); the
parent may admit and seal a larger ceiling while the per-object gate continues
to require only that actual object's size. No blanket 360 GiB reservation is
created by this source change.

## Bounds retained

The next operation's bounded growth is the larger of the configured log limit
and Cargo metadata's 32 MiB limit, plus two 16 MiB JSON slots. With current
configuration this is 160 MiB. This covers one subprocess log, its native report,
and an atomic controller JSON publication. Each subsequent subprocess rechecks
its own log/metadata headroom; it does not assume this one allowance pays for
unlimited retries. Existing accumulated logs and source/build files stay charged
to the unchanged 16 GiB working-allocation ceiling.

Controller JSON publication now enforces the existing 16 MiB reader bound before
creating its temporary file, so the metadata allowance has a matching writer
bound. During download, each chunk preserves the filesystem floor plus the two
JSON slots; there is no compiler or playback child during transfer. Existing
periodic free-space, working-allocation, timeout and maximum-log guards remain.

Reader qualification still fetches the branch and proves exact source,
dependency, feature and toolchain equivalence. A matching sealed reader returns
without reserving unused build growth. A genuinely changed reader enters
`required_reader_build`, which checks the entire remaining source/build budget
before Cargo can create build scratch or start. If an archive is already
resident, its allocation already reduces `statvfs` free bytes: it is neither
added again nor credited back. Insufficient rebuild capacity remains a persistent
reader wait and does not mark the archive corrupt. A post-qualification download
capacity recheck also waits rather than committing a failed archive result.

No config schema, reconfigure contract, exclusive ownership, remote operation,
reader compatibility check, full playback acceptance or cleanup gate changes.

## Playback disk path

`src/bin/horizon_pipeline.rs` selects `JetSource::local` for the supplied scratch
directory. `--verify-only` disables ClickHouse and disallows benchmark/preload
flags. `jetstreamer-plugin/src/horizon.rs` invokes `firehose_horizon`, whose
local stream (`jetstreamer-firehose/src/firehose_horizon.rs`, `open_jet_stream`)
opens the canonical archive with `tokio::fs::File::open`, seeks/reads compressed
buckets and decodes them through bounded in-memory channels and `BucketDecoder`.
There is no disk extraction, ledger replay directory or AccountsDb. The pipeline
persists its terminal verification report after clean full-epoch completion.

## Parent qualification and handoff

Use the existing isolated target and the parent's already established serial
qualification envelope: one Cargo job, 1 CPU, 3 GiB memory, no swap, 256 tasks,
1800-second timeout, at most 2 GiB incremental root allocation. Establish the
current root fit before opening the build. Run, in separately retained units:

```text
env RUSTC=/home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc /home/sol/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/cargo test --locked --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_r2_chronological_plugin_audit_20261118_v1/Cargo.toml --target-dir /tmp/horizon-r2-chronological-audit-build-20261118-v1 -j 1
```

Use the same manifest/target/compiler for all-target Clippy with `-D warnings`
and a production release build. Expected ordinary suite is 34 tests, with the
existing native storage test still ignored by default; report actual results.
New tests reproduce the epoch73 capacity failure, prove archive/build ceilings
do not become per-object reservations, keep metadata/cap rejection, check a
resident-archive rebuild boundary, reject a real build entry before creating
scratch when space cannot fit, and retain old evidence on oversized JSON.
Rerun the ignored two-filesystem test in the existing admitted root/DATA fixture
parents because the common subprocess and metadata-capacity checks changed.

After successful native qualification, parent publishes exact source to
`account-updates`, verifies containment, seals a distinct successor runner plus
source/build proof, and preserves the existing v3 state and config. A handoff
at the genuine capacity wait has no active playback to discard; verify native
state and absence of download ownership before stopping only the audit controller.
Use the existing state lock and unchanged config, or the normal `reconfigure`
procedure if changing the maximum archive ceiling. Preserve original service
and failure evidence. Activate one successor, then verify epoch73's complete
download/current-plugin playback/receipt/cleanup before claiming recovery.
Live epoch166 and all generation reservations remain outside this handoff.
