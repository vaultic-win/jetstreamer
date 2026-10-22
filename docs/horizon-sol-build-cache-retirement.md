# dev-samjohnson debug-cache retirement

The Rust `jetstreamer-horizon-dev-cache-check` tool accepts the distinct
`jetstreamer-horizon-sol-dev-cache-check-plan-v1` profile. Its only target is
`/home/sol/workspace/jetstreamer/target/debug`, owned by UID1001. It cannot select
release tools, historical runtime targets, replay scratch, snapshots or archives.
Existing other-host profiles keep their original paths and owner checks.

Seal the exact executable and a root-private plan with `source_commit`,
`cargo_lock_sha256` and an absent `output` ending in `check.json` directly under
`/var/lib/jetstreamer/horizon-dev-cache-check-NAME`. Run the initial plan without
`retirement`. It requires a clean tracked source revision and preserved lockfile,
an ignored cache, a bounded same-device tree census without archive/snapshot
members, a complete process reference scan and a staged systemd definition scan.
This profile additionally refuses any Cargo, rustc or sccache process and holds
the existing Cargo profile lock exclusively and non-blockingly. It never creates
a replacement lock or invokes Cargo.

Only a separately sealed plan with `retirement: {prior_check: {path, sha256}}`
may remove the cache. It must reproduce the complete initial tree and source
bindings and repeat all checks. The tool fsyncs the new check and a no-clobber
intent, repeats the builder and exact-tree process scans, then removes only the
same device/inode cache tree without following child symlinks. It fsyncs the
parent and a separate completion proving absence. Keep builds and build-launch
automation quiescent throughout both invocations. A failure or intent without
completion requires evidence review, not an automatic retry.

Cache physical bytes are not a promised free-space delta while replays allocate.
Record actual free space separately; retirement does not grant replay admission,
lower protected floors, or mutate R2. Cargo can reproduce the removed artifacts
from the retained revision and lockfile.
