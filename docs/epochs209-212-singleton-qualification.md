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

## Epoch 209 native input harness

The test-only v1.6.16 module `worker/src/native209_input.rs` supplies the ignored
`runtime::native209_input::native_epoch209_cold_input_matches_canonical_accounts_commitment`
gate. It admits only the exact retained 8,543,246,873-byte bootstrap and
20,144-byte genesis, rehashes both against their sealed SHA-256 values, and
requires empty current-owner mode-0700 scratch under its own
`native-input209-v1616-capped-*` namespace. It restores only slot 90287519,
freezes that bootstrap, requires its canonical accounts commitment, zero writes
and unchanged write cursor/capitalization/transaction count, and prints an
epoch-specific marker. No entries are replayed. The ordinary worker's runtime
semantics are unchanged; the module is compiled only for tests.

Build with rustc 1.51.0 from the v1.6.16 workspace root using `cargo +1.51.0
test --release --locked --offline -p jetstreamer-historical-worker-v1-6-16
--no-run`. Seal the optimized artifact separately, prove the exact ignored
listing, and run only its small non-native input-integrity regression before
actual admission. A build or listing does not qualify native restore.

The [dormant service template](epoch209-native-input-service.service) reserves
128 GiB hard/112 GiB high memory, 300 GB scratch, eight CPUs and 2,700 seconds,
with no network or restarts. Those are explicit preparation claims, not current
capacity evidence. Before launch the campaign owner must add the new exact
unit/root/harness-digest tuple to the separately sealed native MainPID guard and
fleet/admission/capture/status registry. Preserve the existing 207 and 227
tuples. Bind actual invocation/MainPID, fresh complete-fleet admission, canonical
clock and first sandboxed guard fire before publishing active `verification`
status. A successful native bootstrap will still leave the full singleton,
canonical final root, complete output and publication gates unqualified.
