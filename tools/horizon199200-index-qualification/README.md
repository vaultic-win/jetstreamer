# Recover the epoch 199 and 200 slot-range indexes

From the repository root, run the following in a private directory on the home filesystem. The fetcher reads two 5,184,000-byte slot tables and 139 bounded Old Faithful CAR ranges totaling 205,729,899 bytes. It verifies the range coordinates and reuses completed, digest-checked captures after an interruption.

```sh
work="$HOME/horizon-index-199-200"
python3 tools/horizon199200-index-qualification/fetch.py "$work"
mkdir -m 700 "$work/repaired"
manifest_sha=$(sha256sum "$work/capture/RESULT.json" | cut -d' ' -f1)
cargo run --release --manifest-path tools/horizon199200-index-qualification/Cargo.toml -- \
  "$work/indexes" "$work/capture" "$manifest_sha" "$work/repaired"
```

The offline verifier checks each captured CAR section's CID, the physical block ancestry across each window, and the epoch-root-to-subset-to-block links. It requires unique canonical block CIDs, full consecutive block extents from the 59-byte CAR header to the footer and a matching block count across all 432,000 slots for each epoch. The per-epoch report records every changed row and its rooted block evidence. A failed window is recorded before a corrected table can be emitted for that epoch.

| Epoch | Corrected rows | Present slots | Corrected table SHA-256 |
| --- | ---: | ---: | --- |
| 199 | 75 | 319,922 | `ebabf661a7608e72169e85d3be3129a575ab8f5b1d2e67d2f10c95a8de79a1ae` |
| 200 | 67 | 318,235 | `d37e594b89638dac4fb8ca094bccce5c388f5c583472a592dec1ed811c749cd7` |

## Use the qualified inputs in the replay node

Install the two corrected raw tables and the exact [manifest](manifest.json) in a sealed, read-only package. Mount that package at `/home/sol/horizon-199200-qualified-index-v1` in the producer's mount namespace, with read access for the worker. Set the following variables in that producer's environment and leave `JETSTREAMER_FORCE_LEGACY_INDEX` unset.

```sh
export JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST=/home/sol/horizon-199200-qualified-index-v1/manifest.json
export JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256=cc4250c62eee9136933a87909891041c40bf5f2bc28fde36906e071a1b7156d0
export JETSTREAMER_COMPACT_INDEX_BASE_URL=https://files.old-faithful.net/
export JETSTREAMER_HTTP_BASE_URL=https://files.old-faithful.net/
```

Firehose loads the two pinned range tables locally and continues to stream CAR data from the public source. The node still fetches the separate slot-to-CID compact index. It checks each slot against the corrected table and accepts only the 72 and 63 historical false positives respectively, each inside a CID-rooted physical parent-chain gap. Any other discrepancy, or a changed compact or range table, fails this profile. Epoch 198 continues using its public inputs for the 717-slot warmup.

For the adaptive controller on this host, pass `--epoch199200-qualified-index` alongside the manifest-bound `--cohort-bootstrap`. The controller checks the sealed package and mounts it in that cohort's producer namespace. Launch and adoption use the same mount and environment. Use the separate import and receipt paths below so the legacy uploader watching `/home/sol/horizon` cannot publish the reconstruction.

```sh
--public-dir=/home/sol/.jetstreamer-private/epoch199200-reconstruction-v1/public
--public-private-root=/home/sol/.jetstreamer-private/epoch199200-reconstruction-v1/public-private
```
