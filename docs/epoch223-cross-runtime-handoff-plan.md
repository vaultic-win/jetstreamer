# Epoch223 metadata gate before cross-runtime assembly

The native20 prefix and existing native25 tail need **V3 cross-runtime**
provenance. The203/213 checkpoint-restart V4 mechanisms deliberately require
one exact runtime identity and reject this native20/native25 pair. Reuse their
checked normalization and the underlying multi-segment merger through
`merge_runtime_segments`; preserve V4's mixed-runtime rejection.

`jetstreamer-epoch223-handoff-plan` is a metadata-only preparatory gate. It
never opens an archive, restores a Bank, launches replay, observes current host
resources or contacts R2. Do not run it while the prefix is still active and do
not create an operational plan with predicted hashes, fabricated completion
receipts, synthetic test data or an older failed/native25 prefix.

After the actual native20 invocation
`e70aaf097e7c4583b216aba454145910` completes naturally, preserve and seal exact
root-owned copies of:

1. Its real `receipts/root-prefix.json` success receipt.
2. Its unchanged `output/epoch-223.jet.segment.json` producer manifest.
3. The new independent `jetstreamer-qualification-verify` full431,523-slot
   prefix reread receipt for this actual archive/manifest and native20 worker.
4. Original raw NDJSON journal evidence carrying the native20 terminal
   checkpoint at96767522 and the exact PID1 unit-success event. Preserve the
   original journal as well; a bounded original-row export is sufficient for
   the gate. Never reconstruct numeric checkpoint messages through float/jq.

This gate expects those four sealed regular single-link immutable files, each
no larger than4MiB. Terminal evidence must contain exactly one target-slot
checkpoint for the actual invocation and one PID1 clean-success event for its
exact unit, in increasing row/time order. Foreign PID/IID/unit markers,
duplicates, missing success and rounded tuple fields refuse the gate. Producer
success alone does not substitute for the independent prefix reread.

The tool also rehashes the fixed original prefix launch, sealed tail manifest
and exact corrected historical native25 input receipt:

`/var/lib/jetstreamer/horizon-223-tail-exact-capture-281b1ddd-v1/capture.json`

SHA256 `d79e374e95861e427239c9e0ba020ed5796fa6c1b076654115823965d7b96796`.

That proof preserves the earlier rounded terminal summary and explicitly
corrects capitalization to504095069290845150 at the handoff. It binds the
already successful native25 initialized cursor, snapshot/fork audit and
independent full477-slot tail reread. Do not rerun a Bank to format metadata.

Only once the four actual future inputs exist, author a root-owned immutable
request of schema `jetstreamer-epoch223-handoff-plan-request-v1`. It contains
`prefix_completion`, `prefix_manifest`, `prefix_reread` and
`prefix_terminal_journal`, each `{path, sha256}`, plus absolute `output` in a
root-owned0700 directory. There is intentionally no executable example plan
with fake hashes. Seal the tool and request with `jetstreamer-seal-deployment`.
Run as root with positional arguments `PLAN PLAN_SHA256 SELF_SHA256`.

The gate binds the completion's original supervisor/unit/invocation, worker,
node, snapshot and resource plan. It checks embedded typed manifest equality
and the SHA256 of the exact producer-manifest bytes. It verifies the independent
reader's archive digest/size, typed manifest-content digest, actual private
paths, native20 worker/revision, known-root span and restricted qualification
scope. The future prefix's terminal Bank hash, accounts hash, last blockhash,
capitalization, cumulative transaction count, tick height and completeness
must all equal the corrected native25 bootstrap. Bootstrap writes must be0.

Native20 terminal and native25 initialized raw cursors may differ. They belong
to independently restored validators. The library V3 validator binds each
side to its own raw interval and checks full consensus equality, while the
existing `WriteVersionNormalization` checked arithmetic plans:

| Segment | Slots | Validator-local writes | Planned archive writes |
| --- | --- | --- | --- |
| Native20 prefix | 96336000..96767522 | Actual manifest `[p_start, p_end)` | `[0, p_end-p_start)` |
| Native25 tail | 96767523..96767999 | `[107266983592, 107268320809)` | Immediately after prefix,1,337,217 writes |

The two slot spans cover432,000 slots without overlap. Checked subtraction and
addition reject inverted ranges and overflow. No artificial padding, cursor
equality, event dropping or archive truncation is permitted.

The result records **planned mappings and metadata consensus equality only**.
`all_event_contiguity_verified`, `no_event_loss_proven`,
`cursor_normalization_performed`, `assembly_performed`, `assembly_authorized`,
`handoff_qualified`, publication/runtime-promotion and repair closure remain
false. Structural V3 validation does not prove events inside unopened archives.

The subsequent separately admitted private assembler must use
`merge_runtime_segments` with both opened source handles, their actual
independently bound archive digests and terminal last blockhashes. Its existing
full decoder checks source SHA256, single-runtime V2 identities, output spans,
metadata semantics, PoH continuity, every raw write in all update phases,
per-slot permutations, gaps/duplicates/bounds/missing events and checked
normalization into adjacent archive intervals. It validates the completed V3
output and preserves each original producer identity. Neither a metadata gate
nor a merger success alone creates a canonical sidecar. Fresh resource/guard
admission, a private no-clobber output, independent assembled full/current-plugin
checks, adjacent-boundary obligations and authenticated upload/readback remain
separate requirements. Keep223 open through the ready verified R2pair.
