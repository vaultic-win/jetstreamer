# Private snapshot 60,911,751 acquisition

The separate Rust binaries `jetstreamer-epoch140-snapshot-metadata` and
`jetstreamer-epoch140-snapshot-download` select only the compile-time object in
`epoch140_snapshot_profile.rs`: snapshot slot 60,911,751, generation
1634786631155900, compressed length 2,741,858,751 bytes, CRC32C `wif3BA==`,
and MD5 `bEVjbHoOexfklmZRKtsfSw==`. Plans cannot select another object or
borrow the ledger tools' metadata/admission identity.

The metadata observer and download engine are shared with the original fixed
epoch 141 ledger tools. Their old CLI, schema names, file identity and object
constants remain unchanged. Existing sealed binaries and active ledger census
are not replaced, restarted or modified by this source refactor.

Use each sealed binary with `--plan PATH --plan-sha256 HEX --self-sha256 HEX`.
The snapshot metadata plan has schema
`jetstreamer-epoch140-snapshot-metadata-plan-v1`, `gcloud_sha256`, and a
root-private no-clobber `output` receipt path. Its read-only generation lookup
runs through `/home/sol/.config/gcloud` as UID1001/GID1003, account
`sam.johnson@anza.xyz`, billing project `principal-lane-200702`. It writes a
`jetstreamer-epoch140-snapshot-metadata-receipt-v1` observation, not admission.

The download plan uses `jetstreamer-epoch140-snapshot-download-plan-v1` and the
same strict fields as the ledger download plan: `gcloud_sha256`, bound
`metadata_receipt` and `admission_receipt` path/SHA256 pairs, fresh
`staging_directory`, separate `output_receipt`, `stop_intent`,
`stop_completion`, `initial_guard_receipt`, `minimum_free_bytes`, and bounded
`maximum_runtime_seconds`. Paths must satisfy the existing canonical private
directory and no-overlap gates. The SDK staging parent is root-owned 0711;
the new attempt is initially UID1001-owned0700 and frozen root-owned after
the owned SDK group has stopped. Credential refresh may write the exact GCloud
configuration, so the systemd sandbox must permit that while granting only
the separate attempt/receipt paths other write access.

Fresh full admission must bind the exact downloader and snapshot metadata
receipt. Protect the current century floor and every older invocation's growth
claim; reserve the full object length plus 64 MiB independently above that sum.
Do not lower an existing guard to fit this diagnostic. The internal actual-free,
staging-byte and runtime guard remains active through transfer and full digest
verification and writes its initial private receipt. An observed trip records
intent before stopping only the owned SDK process group and preserves partials.
Use a persistent non-restarting unit with the proven minimal SETUID/SETGID,
KILL, CHOWN and DAC traversal capabilities, `KillMode=control-group`, bounded
resources, and a timeout covering the sealed internal runtime bound. Prove its
root-only SDK identity/drop/group-kill and same-filesystem freeze/digest tests
under an equivalent sandbox before actual transfer.

The SDK uses sequential no-clobber transfer, with slicing disabled. Rust
re-observes the exact remote metadata before and after transfer, independently
computes length/CRC32C/MD5/SHA256, binds inode/owner/mode/link count, revalidates
the file identity, fsyncs the frozen file/directory, and writes a no-clobber
private receipt. A valid compressed snapshot is **not** native Bank restore
proof, actual clock proof, a matched prefix tuple, continuation qualification,
or replay/publication authority. Do not reuse the epoch 213 restore probe for
this snapshot. Preserve the retained epoch 140 archive and require a dedicated
qualified 1.4.25 path before any suffix entry, assembly, canonical import or
sidecar.
