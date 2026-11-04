# dev-samjohnson build-cache retirement

The Rust `jetstreamer-horizon-dev-cache-check` tool accepts the distinct
`jetstreamer-horizon-sol-dev-cache-check-plan-v1` profile. Its only target is
`/home/sol/workspace/jetstreamer/target/debug`, owned by UID 1001. It cannot select
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

## Separate release dependency cache

The distinct `jetstreamer-horizon-sol-release-deps-cache-check-plan-v1` profile
selects only `/home/sol/workspace/jetstreamer/target/release/deps`. It keeps the
UID 1001 ownership, preserved clean revision/lockfile, builder exclusion,
complete process/staged-unit reference scans, positive prior census, no-clobber
intent and fsynced completion gates. It does not broaden the debug profile or
authorize deleting the complete release directory, top-level executable tools,
native build outputs, historical targets, sealed deployments or Horizon data.

Hold the existing parent `target/release/.cargo-lock` throughout both censuses
and removal. The lock file remains outside the deleted subtree, so a new Cargo
invocation cannot acquire a replacement inode while retirement still owns the
profile lock. Resolve absolute and relative references to this exact subtree at
path boundaries; a `deps-sibling` path is not a reference. Any genuine live or
staged reference stops reclamation. Seal and execute the checker and its tests
outside the selected cache, and verify their runtime libraries are outside it.
The two invocation plans still grant no archive deletion, R2 mutation, reduced
reserve or replay admission. Rebuilding dependencies later consumes space again:
account for that growth before starting builds beside a tightly admitted lane.

## Separate private debug dependency cache

The closed `jetstreamer-horizon-sol-private-debug-deps-cache-check-plan-v2`
profile selects only
`/var/lib/jetstreamer-builds/readback-progress-20261022-v1/debug/deps`.
This private build root is outside the source checkout; the checker does not
claim that the unrelated ignored workspace target is selected. Bind the clean
tracked source revision and Cargo.lock as usual. Check, intent and completion
receipts use v2 schemas and cannot borrow proof from another cache profile.

Keep `debug/.cargo-lock` outside the removal subtree and hold its existing inode
exclusively. Scan the entire exact private debug profile for live or staged
references, including executables outside deps that could load dependencies
later. Repeat the staged scan as well as the builder and process scans before
removal. Active release tools and unrelated workspace debug targets are distinct
paths, never exclusions from an otherwise matching reference.

The runtime sandbox needs write access to the cache's parent to remove the deps
directory itself. A mount directly on deps cannot be removed. The conservative
reference scanner also treats literal debug-profile paths in sandbox properties
and launcher command lines as references. Use the fixed private build-root
ancestor as the writable mount, with the sealed tool still restricting removal
to the exact deps device/inode; never hide, encode or ignore a matching reference.
Keep all builds quiescent, preserve the profile lock, and grant write access to
only the other required private receipt directory. Run the initial check with
the cache read-only. A rejected invocation before the intent is written performs
no removal; preserve its diagnostic before correcting the sandbox.

The qualified 2026-10-23 removal censused 12,223,606,784 physical bytes and 7,094
entries. Its durable completion is
`/var/lib/jetstreamer/horizon-dev-cache-check-private-debug-deps-retire-20261023-v1/completion.json`.
Measure filesystem free space at the next coordinated observation; this cache
size is not a promised free-space delta or authority for replay admission.
