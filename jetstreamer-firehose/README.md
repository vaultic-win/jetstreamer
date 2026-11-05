# jetstreamer-firehose

A utility that allows replaying Solana blocks (even all the way back to genesis!) over a geyser
plugin or the Jetstreamer plugin runner.

Based on the demo provided by the Old Faithful project in
https://github.com/rpcpool/yellowstone-faithful/tree/main/geyser-plugin-runner

## External Geyser plugins

Normal streaming and Jetstreamer's built-in plugins work with default features and
need no Cargo patches. The external Agave plugin loader, `firehose_geyser`, and the
`jetstreamer-firehose` binary require the optional `geyser` feature. Existing users
of these two entry points must enable that feature when upgrading.

From this repository, run an external Geyser plugin with:

```sh
cargo run --release -p jetstreamer-firehose --features geyser -- 800 /path/to/plugin.json
```

The loader uses Agave 4.3.2's unstable internal APIs and plugin ABI. Build external
plugins against the same release. Agave's ledger crate requires methods that are
absent from crates.io RocksDB 0.24, so this workspace pins Anza's RocksDB fork.
Cargo ignores a dependency's `[patch]` table. To enable the loader in another
project, add the feature and both patches to that project's workspace root:

```toml
[dependencies]
jetstreamer-firehose = { version = "0.9.0", features = ["geyser"] }

[patch.crates-io]
librocksdb-sys = { git = "https://github.com/anza-xyz/rust-rocksdb", rev = "4dba80dfe9434e595a971f5b2985ff9ba4fb31e7" }
rocksdb = { git = "https://github.com/anza-xyz/rust-rocksdb", rev = "4dba80dfe9434e595a971f5b2985ff9ba4fb31e7" }
```

The top-level `jetstreamer` crate forwards its `geyser` feature to this crate.
`--all-features` also enables the loader and therefore requires these patches.
Default library consumers and default package verification do not build the ledger
or RocksDB. Rust 1.97.1 or newer is required in either configuration.

## Configuration

### Environment variables

- `JETSTREAMER_ARCHIVE_BACKEND` (default `http`): set to `s3` to force the new S3 transport
  even when the base URLs still point at `https://`.
- `JETSTREAMER_HTTP_BASE_URL` (default `https://files.old-faithful.net`): base URL or
  `s3://bucket/prefix` for CAR data.
- `JETSTREAMER_COMPACT_INDEX_BASE_URL` (default `https://files.old-faithful.net`): override for
  slot index artifacts; also accepts `s3://` URIs when mirroring Old Faithful into private
  storage.
- `JETSTREAMER_FORCE_LEGACY_INDEX`: set to `1` to skip the per-epoch slot-ranges index
  (`{epoch}/epoch-{epoch}-slot-ranges.raw`, ~5 MB) and resolve slot offsets with the legacy
  compactindex pair (`slot-to-cid` + `cid-to-offset-and-size`) instead. The legacy indexes are
  deprecated upstream; without this flag they are only used as an automatic fallback when a
  mirror does not serve the slot-ranges file.
- `JETSTREAMER_ARCHIVE_BASE`: shortcut that applies to both CARs and indexes when the more
  specific knobs are unset.
- `JETSTREAMER_S3_BUCKET`, `JETSTREAMER_S3_PREFIX`, `JETSTREAMER_S3_INDEX_PREFIX`,
  `JETSTREAMER_S3_REGION`, `JETSTREAMER_S3_ENDPOINT`, `JETSTREAMER_S3_ACCESS_KEY`,
  `JETSTREAMER_S3_SECRET_KEY`, `JETSTREAMER_S3_SESSION_TOKEN`: credentials and addressing
  details used when the S3 backend is active.
- `JETSTREAMER_NETWORK` (default `mainnet`): network identifier appended to legacy index
  filenames so you can point the replay engine at other clusters (for example `testnet`).
- `JETSTREAMER_NETWORK_CAPACITY_MB` (default `1000`): assumed network throughput in megabytes
  per second when sizing the firehose thread pool. Increase or decrease to match your host's
  effective bandwidth.
- `JETSTREAMER_TURBO` (default `false`): when truthy, runs at full speed instead of the polite
  default. See `jetstreamer_firehose::pace`.
- `JETSTREAMER_SPAWN_PENDING` (default `4`, `24` in turbo mode): maximum not-yet-green threads
  in flight during the health-gated thread ramp; `1` reproduces a strict one-at-a-time ramp.
- `JETSTREAMER_SPAWN_GRACE_SECS` (default `30`): how long the launch gate waits for sluggish
  (never stalled) threads before spawning anyway; `0` disables launch gating entirely.
- `JETSTREAMER_RECYCLE_PCT` (default `50`): connection-recycle threshold as a percent of the
  best observed p90 per-thread rate; threads persistently below it reconnect. `0` disables
  recycling.

### Adaptive connection management

The threaded firehose actively manages its HTTP connection fleet to cope with CDN throttling
(burst allowance followed by a sustained per-connection clamp):

- **Health-gated launch**: threads spawn one batch at a time, only while the running fleet is
  healthy; a stalled (red) thread freezes the ramp until it recovers.
- **Paced reconnects**: every stream open and seek waits for a process-wide permit, 250 ms
  apart by default and 15 ms apart in turbo mode.
- **Exponential restart backoff**: failed threads wait 2s → 120s by default and 1s → 32s in
  turbo mode (reset on progress) before reconnecting, so throttling events decay instead of
  amplifying into reconnect storms.
- **Connection recycling** (🧊): threads running persistently below the fleet's demonstrated
  rate reconnect cleanly (no backoff, no error counting) to shed throughput-clamped
  connections. Sweeps run every 2 min by default and every 15 s in turbo mode, and rotation is
  capped per sweep so a uniform clamp is probed gradually.
- **Work stealing** (🐾): a thread that finishes its slot range messages the least-progressed
  thread's steal inbox to request half of its remaining work; the victim answers at a
  quiescent point (between block batches) and computes the split from its own authoritative
  position, so handovers can never race in-flight emission. This keeps every connection busy
  until the entire range completes; threads only retire when no stealable work remains.

### Integrity guarantees

- **Premature-EOF detection**: a cleanly closed HTTP stream is ambiguous — it can mean the
  genuine end of an epoch's data or a connection the CDN cut mid-transfer. On EOF the reader
  consults the slot-ranges index; if any present slot remains in the thread's slice, the
  stream was truncated and the range restarts instead of silently completing short.
- **End-of-run coverage audit**: every completed assignment journals the interval it
  processed, and after all threads finish the union is verified against the requested range
  (gaps are checked against the slot index, so genuine leader-skip regions pass). A clean
  run logs `coverage audit passed`; any hole containing real slots is reported loudly with
  the exact slot range to re-run.
Notes:

- `JETSTREAMER_HTTP_BASE_URL` and `JETSTREAMER_COMPACT_INDEX_BASE_URL` accept both full HTTP(S)
  URLs and `s3://bucket/...` URIs; the latter automatically activates the S3 transport layer.
- Changing `JETSTREAMER_NETWORK` also alters the in-memory cache namespace, so you can switch
  networks without cross-contaminating cached offsets.
- Sequential-mode ripget buffering is configured via the `buffer_window_bytes` parameter on
  `firehose::firehose(...)`. If you run through the top-level `jetstreamer` binary crate, that
  layer exposes `JETSTREAMER_BUFFER_WINDOW` and forwards it to firehose.
