# Independent singleton preparation for epochs 209–212

The private `epochs209-212-singleton-qualification` node feature admits one of
four exact singleton profiles. It does not promote the ordinary compatibility
registry. Each profile retains its own canonical root and complete 432,000-slot
output, without requiring the next epoch's replay inputs.

| Epoch | Bootstrap slot | Canonical final root | Last output slot | Slots after root |
| --- | ---: | ---: | ---: | ---: |
| 209 | 90287519 | 90719638 | 90719999 | 361 |
| 210 | 90719638 | 91151575 | 91151999 | 424 |
| 211 | 91151575 | 91583512 | 91583999 | 487 |
| 212 | 91583512 | 92015419 | 92015999 | 580 |

All profiles use the capped v1.6.16 worker. Their exact generation, compressed
size, CRC32C and MD5 tuples are pinned in
`jetstreamer-node/src/singletons209_212_profile.rs`. The retained package paths
and binding-file digests are part of the same table. Those metadata bindings
are complete; epoch 207's unresolved root MD5 does not block this preparation.
Keep the separate [207 authentication incident](epoch207-root-metadata-unblock.md)
open and preserve its existing native-input proof.

## Offline metadata and command capability

Build, review and separately seal `jetstreamer-singletons209-212-prepare` and
the feature-specific node. As root, run the preparation helper with a fresh
precreated root-owned mode-0700 parent and the exact sealed helper digest:

```text
PREPARER 209 /var/lib/jetstreamer/horizon-singleton-209-UNIQUE/preflight209-singleton.json --self-sha256 PREPARER_SHA
```

The helper rehashes the immutable retained preflight and epoch-specific
snapshot-binding receipt, checks their original fingerprint and both complete
snapshot tuples, then writes a no-clobber v4 report and canonical fingerprint.
It does not reread snapshot bodies, observe resources, contact GCS/R2, restore a
Bank, start a worker or authorize replay. Seal its report into a readable
immutable package before using it with the unprivileged node. The same helper
supports 210, 211 and 212 with their own output directory and filename.

The feature-specific node requires one explicit `--verify`, candidate opt-in,
`--root-checkpoint-cohort`, the exact report and fingerprint, and an explicit
cached-bootstrap override matching that epoch. Its output must be a canonical
current-owner mode-0700 `output/` directory beneath its own
`/home/ubuntu/.jetstreamer-private/qualification-N-singleton-UNIQUE` root.
Recovery, inherited leases, focused end slots, directory loading and alternate
span/hash/scratch overrides are rejected. Other private qualification features
cannot be combined with this build.

Use `--singleton-preflight` for the offline command capability. It exercises
the actual CLI, runtime selection and cohort parser, validates every pinned
bootstrap/root field and rejects a successor checkpoint. It returns its
`jetstreamer-private-v1616-singleton-preflight-v1` result before input staging,
worker creation or Bank restoration. Bind the exact node/worker digests,
effective command/environment, report/fingerprint and captured stdout in the
private capability evidence. Run with networking disabled. This proves command
and planning capability only; it is not native-input or full-epoch qualification.

## Before actual replay

Prepare and qualify each new input/worker combination through its exact native
restore/checkpoint path. Existing complete-span focused receipts do not qualify
these shorter singletons. Use a fresh complete-fleet admission that includes
every active replay and auxiliary, the current century's twice-average `.jet`
floor, remaining scratch/output growth and measured memory reservations. Bind
an invocation-specific guard covering the entire private run root, and prove
its first actual sandboxed no-trip fire. Do not borrow another epoch's closed
native harness, guard, admission or fleet registry identity.

Preserve the canonical root check, native terminal and all post-root output;
require independent full/current-plugin verification and ordinary boundary
checks. Authenticated upload, whole-object readback, source revalidation and
sidecar commit remain separate publication gates. Preparation and preflight
open none of those gates. Register any actual work with its true owner and
publish status in the existing coordinated 30-minute cycle using only `replay`,
`verification`, `upload` or `readback`.
