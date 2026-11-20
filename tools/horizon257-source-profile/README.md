# Epoch 257 source ranges

This checker validates the two sealed Foundation source packets for the 256/257 CAR and compact-index prefixes, the complete 257 raw slot-ranges index, and the singleton bootstrap and terminal GCS generations. Run it locally with no arguments. The report distinguishes zero records, physical forward gaps and overlaps, and counts the compact bucket descriptors actually visible in each prefix.

    cargo run --locked --offline --manifest-path tools/horizon257-source-profile/Cargo.toml
    cargo test --locked --offline --manifest-path tools/horizon257-source-profile/Cargo.toml -- --include-ignored

The raw index contains 46,728 zero records. In 14,231 cases, consecutive *present* rows have physically contiguous bytes despite intervening zero rows. The 29 physical discontinuities comprise 28 holes and one 1,757,860,845-byte overlap.

## Reconstruct the candidate

The ordered 29 windows in `edge-windows.json` each extend from the start of an unaffected exterior block to the end of another unaffected exterior block. The exact 118,427,890 window bytes and two 4096-byte CAR-prefix brackets are already captured. The immutable download manifest is `/var/lib/jetstreamer/horizon257-edge-source-readback-20261120-v1/download.json` with SHA256 `91b0303d552386fcbaec36178259f2af33b09e2b06f2e2cdf92ad6778a223521`. The root-owned, read-only bodies are at `/run/horizon257-edge-source-20261120-v1/result/windows`. Preserve or normally seal them before losing that temporary filesystem if independent reruns are needed.

`fetch-windows.py NEW_ABSOLUTE_DIRECTORY` is the original bounded read-only HTTPS acquisition recipe. It requires exact response ranges and lengths, verifies the epoch's CAR header before and after all windows and captures the response evidence. A future acquisition is a separate generation with a different manifest and requires its own source review.

    cargo run --locked --offline --manifest-path tools/horizon257-source-profile/Cargo.toml -- repair NEW_ABSOLUTE_OUTPUT_DIRECTORY
    cargo run --locked --offline -p jetstreamer-firehose --bin epoch257-native-window-audit -- NEW_ABSOLUTE_OUTPUT_DIRECTORY/repair-candidate.json

The repair verifies section CIDs and parses every terminal Block and parent. It traces the unique parent chain between the two exterior anchors of each window. It checks anchor slot labels and original physical endpoint ranges, then reconstructs the rows from that chain. Both boundaries are inside the downlinked bytes. The original raw index stays intact. The independent comparator uses the normal Firehose `NodeReader::next`, `verify_sha256_cid` and `parse`, and checks every native terminal slot, parent, CID and byte interval against the repair and the actual emitted candidate row.

On the recorded windows, 225,181 CAR sections and 144 terminal blocks passed the native comparison. The candidate adds 28 previously omitted slots and moves the mislabeled slot 111226320 to 111226321 with offset 198347022188 and length 1155096. All 432,000 candidate records were scanned. The result has 385,300 present records and zero internal physical gaps or overlaps, with SHA256 `5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126`. The repair receipt lists every changed record and every decoded block CID.

Use the normal Rust sealer and the production firehose's digest-pinned local slot-ranges override manifest when binding this reviewed candidate to replay. Include both the manifest and its exact SHA in the selected node's environment. The current `--probe-local-slot-ranges=253-255` diagnostic uses 253–255 fixture slots. The ordinary `SlotOffsetIndex` loader selects an override by the manifest entry's epoch. This candidate covers epoch 257. It does not authenticate the full compact-index bodies, qualify native snapshot initialization or authorize replay or publication.
