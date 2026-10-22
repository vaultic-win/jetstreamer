# First-target raw-byte diagnostic

The genuine native acquisition completed for target60911776/parent60911771
with778present1228-byte data shreds and the original `is_connected=false`.
That is not connected recovery, a complete18283-target acquisition, or a PoH
boundary set. Its native-close/full retained-census rehash receipt remains the
input authority for one bounded diagnostic only.

`jetstreamer-epoch141-byte-diagnostic` reads the immutable sealed copy of that
exact receipt and an independently sealed finalized-target receipt. It binds
the original native invocation and checks its terminal success; it does not
reopen RocksDB, download source, copy an archive, infer a clock, execute PoH or
call the strict recovery planner. The original connected planner and assembler
continue to reject disconnected metadata.

The distinct byte helper validates all acquisition queries and values, uses the
existing legacy padded-batch assembler, matches every completed-data endpoint
against unchanged metadata, and applies the exact existing legacy entry decoder
with aggregate entry and claimed-work bounds. It reports entry/tick/transaction
counts, zero-work entries and claimed hash work as serialized observations only.
A comparison of the final serialized entry hash with finalized metadata is
reported separately. Matching that one hash is not verification of preceding
entry hashes, a runtime clock, canonical ancestry, hidden intermediate boundaries
or a runtime/publication route.

Seal the executable and a strict plan through the Rust deployment sealer. The
plan schema is `jetstreamer-epoch141-first-target-byte-diagnostic-plan-v1`, with
exact `acquisition` and `finalized_target` path/SHA bindings and a root-private
output named `diagnostic.json` beneath
`/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-UNIQUE`.
Only the fixed source receipt SHA785b52de… and finalized-target SHA3103bc31…
are admitted. Use `PLAN --plan-sha256 HEX --self-sha256 HEX --check-only` in the
intended sandbox first; it validates/traverses inputs but writes nothing and
performs no decode. Actual execution writes a no-clobber intent and explicit
result, both fsynced. A decode error or final-hash mismatch produces a durable
failed diagnostic and nonzero process result, not a success/recovery claim.
Never retry over that output namespace.

Root needs only DAC_OVERRIDE to traverse retained private inputs. Use a
non-restarting persistent oneshot, bounded CPU/memory/runtime, private network
and read-only filesystems except the exact output root. Do not use
`systemd-run --wait` with `RemainAfterExit=yes`: retain the unit identity and
inspect the actual terminal state/receipt instead of leaving a client waiting
after successful completion. The tool has no ordinary epoch claim or dashboard
ETA. Capture the short diagnostic's terminal identity/evidence in the repair
backlog without adding another resource-observation loop.

Before any later chained PoH diagnostic, independently authenticate the exact
runtime's clock from trusted retained genesis/runtime evidence. Never infer
ticks-per-slot or hashes-per-tick from these observed entry counts or select a
clock merely because its work arithmetic fits. Root marker presence and a
matching final hash do not repair the original disconnected ancestry bit.
Keep epoch141 failed-needs-repair until qualified complete recovery reaches
the actual verified ready-pair outcome; this diagnostic alone cannot close it.

## Explicit read-only PoH regression

The separately ignored test `retained_actual_first_target_poh_diagnostic` binds
the retained typed snapshot-clock receipt SHAf74aacd8… and native-restore
comparison SHA53f1aa88… for the same60911751 snapshot, the pinned Bank source
and unchanged clock inheritance, and the finalized target anchors. It executes
the existing bounded PoH verifier over the actual raw records without writing
a receipt or changing a runtime route. This is preliminary diagnostic test
evidence, not a production boundary bundle or promotion of the byte receipt.
A separately sealed PoH driver and its actual sandbox/output gates are still
required before durable diagnostic boundaries can be consumed by another stage.
The original connected recovery gate remains rejected before and after the test.
