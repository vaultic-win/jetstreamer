# Epoch 250 compact-index capability check

The `check-251 PLAN PLAN_SHA256 SELF_SHA256` subcommand checks a separately
sealed epoch 251 cache: its two indexes and the epoch 250 predecessor slot
index. It verifies the running image, immutable plan and deployment receipt,
all file digests and identities, exact epochs, root CIDs, index kinds and
bucket bounds. Its root-private, no-clobber receipt accepts structural input
only; a production reader probe and fresh replay admission remain required.
The original no-argument epoch 250 route retains its exact accepted bindings.

This isolated Rust checker reads the exact accepted epoch 250 input-custody
receipt and the sealed index cache. It authenticates the seal and every cache
member, then parses the compact-index metadata and all bucket spans. It requires
the exact epoch, kind, and root CID in the epoch 250 indexes. The deployed node
does not expose a read-only `--probe-successor-boundary` route, so this check
does not claim native replay capability or launch authority.

A separate sealed source node at
`/var/lib/jetstreamer/horizon250-successor-boundary-probe-20261117-v1/jetstreamer-node`
subsequently ran its read-only `--probe-successor-boundary=108432000` route.
The exact result was parent slot `108431999` and first successor block slot
`108432004`, recorded in
`/home/ubuntu/.codex/diagnostics/horizon250-sealed-boundary-probe-20261117-v1.json`.
That diagnostic does not qualify the deployed replay node, a producer unit, or
fresh admission for epoch 250.

The accepted sealed diagnostic output is
`/home/ubuntu/workspace/horizon250-readiness-20261117-v1/index-capability/capability-v4.json`.
The output is created once with no clobber and fsynced. Its SHA-256 is
`d158bc2593702a552b9db6edf16b98481cfc169ee949f352ec935a0edeabef73`.
The sealed release executable used for that diagnostic run has SHA-256
`a19ef46c3adaad33bb15c43b27632048d62b3a6b3550705578753ecf1a7d36b0`.
Its deployment is
`/var/lib/jetstreamer/horizon250-cache-capability-20261117-v1`, bound by
plan SHA-256 `d40f00ed091a1f9623e0cf3556e1ea81a03f23f5fcfcd764c79499c26b830e87`
and seal receipt SHA-256
`bb4157d602afee51567bb827bc3628113ec3de76e98418247463366864940980`.

Checks completed with `cargo test --offline --locked`,
`cargo clippy --offline --locked --all-targets -- -D warnings`, and
`cargo build --offline --locked --release`. The executable ran successfully
under low I/O and CPU priority against the exact sealed files. Nothing was
started in systemd or changed in R2. A distinct native replay qualification,
fresh Main admission, sealed producer and guard, and guarded launch remain.
