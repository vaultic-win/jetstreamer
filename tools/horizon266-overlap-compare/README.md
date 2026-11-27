# Epoch 266 private overlap comparison

Use the native comparator after the guarded private segment reaches its
verified terminal checkpoint and the original invocation drains. Its
bootstrap is generation 1641767192954871 at 114,923,430. The new segment
covers 114,923,431–114,929,697 and must end at the independently identified
accounts root and finalized block for 114,929,697.

`retained` checks the dense endpoint against the matching frame of the
read-only stopped producer. It then decodes exactly the original 89 retained
overlap slots 114,923,431–114,923,519. The bounded reader reuses the existing
synthetic index and reads the selected buckets.

The `compare` command requires a root-owned, read-only JSON plan with these
fields. Populate it from the exact successful, drained invocation and the
node's native segment-validation receipt.

| Plan field | Data from the accepted invocation |
| --- | --- |
| `schema` | `foundation-epoch266-private-overlap-comparison-plan-v1` |
| `producer_invocation` | Exact 32-character systemd invocation ID |
| `launch_sha256` | SHA-256 of the guarded `cadence-registration.json` |
| `segment_manifest_sha256` | SHA-256 of the adjacent native `.jet.segment.json` |
| `segment_sha256` | Archive SHA-256 from the authenticated complete native source validation |
| `segment_identity` | Exact descriptor/path identity as integers `device`, `inode`, `bytes`, `mtime_ns`, `ctime_ns` |
| `producer_exit_status` | `0` from the terminal PID1 record |
| `producer_drained` | `true` after verifying the invocation has drained |
| `native_manifest_complete_verified` | `true` after the full native manifest and archive validation are accepted |
| `publication_authorized` | `false` |

Use integer-preserving JSON for the filesystem times and checkpoint fields.
The bound plan supplies complete-archive evidence. The comparator checks the
native manifest's content and the stable archive identity and measures the
89-slot decoded sample. Its archive read budget is 128 MiB per reader, plus
the original synthetic-index reconstruction's short header reads.

```sh
horizon266-overlap-compare compare /absolute/sealed/comparison-plan.json PLAN_SHA256
```

The visitor is derived from the SHA-pinned epoch 168 comparison used by epoch
167's extraction workflow. It preserves transaction metadata, account bytes,
event ordering, entries, skipped slots and block links. It normalizes each
validator-local write-version space independently and checks each raw range
for gaps and duplicates. The two raw ranges are recorded in the result.

The native manifest bootstrap tuple must match the lossless independently
executed restore of the same hourly snapshot, including its exact restored
cursor and zero startup writes. A verified predecessor tuple remains a
separate requirement for canonical continuation. It needs independently
authenticated predecessor execution tied to the original prefix and the
checkpoint at 114,923,430. That evidence must supply Bank hash, accounts hash
and kind, last blockhash, capitalization, transaction count, tick height,
complete-slot state and the predecessor-local write cursor. Full-prefix PoH
and the original cohort root at 115,343,448 remain separate gates.
