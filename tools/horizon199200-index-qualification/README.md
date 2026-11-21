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
