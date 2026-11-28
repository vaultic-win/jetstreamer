# Epoch 227 compressed bootstrap preparation

`jetstreamer-epoch227-bootstrap-prepare PLAN PLAN_SHA256 SELF_SHA256` acquires
only the fixed generation-pinned 10,261,480,487-byte snapshot at slot 98,063,464.
It does not unpack a snapshot, restore a Bank, admit a replay, create an archive
or sidecar, or mutate R2. Epoch 227 uses its separately staged v1.6.20 runtime;
the adjacent epoch-225 diagnostic's v1.6.25 runtime is not a substitute.

The shared Rust engine retains epoch 223's original source identity, hash,
bounded process-group cleanup, staging, credential, capacity and receipt gates.
Existing sealed 223 deployments are unchanged. The 227 profile additionally
requires the exact protected 203, 223 and 225–226 fleet, including complete
ordinary and diagnostic observer censuses, stable zero-restart before/after
identities, matching fleet PIDs, roles and sample timestamps, and a hash-bound
root-owned immutable fleet receipt. Changed, added or missing claims require
fresh review, not a reduced reserve. Its fixed inventory profile is 13 ready
pairs and zero anomalies in epochs 201–300.

The strict plan fields are `schema`, `gcloud_sha256`, `observer`,
`observer_sha256`, `fleet: {path, sha256}`, `minimum_free_bytes`,
`staging_directory`, and `receipt`. Schema is
`horizon-epoch227-bootstrap-prepare-plan-v1`. The v2 observer must be no older
than 1,800 seconds at transfer admission. Minimum protected free space is
3,615,543,542,675 bytes: full older replay growth claims of 3,367,254,360,064
bytes plus the thirteen-sample century floor of 248,289,182,611 bytes. Both
observed and actual admission require the complete compressed object plus
64 MiB above that protected amount. A larger plan reserve is allowed, never a
smaller one. This bound is for compressed acquisition, not cold replay.

Seal the executable and plan with the native deployment sealer. Separately
seal a root-owned, singly linked mode-0400 `transfer.lock` member at
`/var/lib/jetstreamer/horizon-bootstrap227-transfer-lease-v1/transfer.lock`.
The executable holds an exclusive nonblocking flock on its read-only descriptor
through final receipt publication; do not replace the shared lock inode.
The staging parent must be canonical, root-owned mode 0711; the receipt parent
root-owned mode 0700. Both attempt directory and receipt must be absent.

Run in a persistent non-restarting root service with narrowly scoped staging
and receipt writes and effective DAC traversal, UID/GID-drop, process-kill and
ownership capabilities. Keep home read-only except the operator's exact
`/home/ubuntu/.config/gcloud` configuration, which needs refresh writes. The SDK
child drops supplementary groups and runs as UID/GID 1000; account, billing
project, SDK launcher path and configuration are fixed, with credential output
suppressed. Qualify the process cleanup under the equivalent sandbox before
real acquisition. Do not change a live replay's isolated GCloud configuration.

The 227-only optional final `--check-only` argument exercises those same input,
lease, SDK metadata, credential-drop and free-space gates under the installed
sandbox, then returns before creating a staging directory or downloading bytes.
Capture its clean terminal journal and invocation identity as capability
evidence; it does not write a preparation receipt or authorize replay.

The transfer-only safety guard checks actual protected free space, staging
size/file count and a two-hour runtime bound. It is not another replay polling
loop. Preserve the existing coordinated 30-minute campaign observation cadence.
After download, kill the owned SDK process group before reaping, freeze the
file and directory, fsync, and recompute full CRC32C, MD5 and SHA-256. Recheck
exact GCS metadata and immutable file identity before the no-clobber receipt.
The receipt binds the fleet digest and explicitly denies restore, replay,
publication and remote-mutation authority. Preserve a verified cache until a
reviewed retirement profile applies; do not fabricate another tool's scan state.

Bootstrap preparation still leaves input/package attestation, exact-node cache
capability, full cold-resource qualification, fresh replay admission and a
proven invocation-bound guard outstanding. It does not supersede older repair
priority or authorize skipping compatibility, canonical-root, full-verification,
current-plugin, upload or authenticated readback gates.
