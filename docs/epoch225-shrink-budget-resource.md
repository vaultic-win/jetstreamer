# Epoch-225 shrink-budget candidate

The v1.6.25 worker's storage maintenance omitted the cap used by its pinned
upstream `AccountsBackgroundService`. A large shrink could therefore leave debt
that suppresses later cleanup for hundreds of roots. The correction caps returned
debt at the unchanged 250-account recovery allowance; it does not alter transaction
execution, PoH, checkpoint fields or write-version semantics.

The development regression reproduced the discrepancy: input debt 25,000 left
24,750 instead of the upstream-capped 250. Preserve its sealed baseline at
`/var/lib/jetstreamer/horizon-v1625-shrink-regression-baseline-20261021-v1`.
The regression also checks debt exhaustion and preservation of the write cursor,
balance, capitalization, last blockhash and frozen bank hash. These tiny-genesis
checks are not historical checkpoint or resource qualification.

Real-snapshot integration tests now select the build-profile bootstrap rather
than always asserting epoch 215's slot 93,311,535. For the epoch-225 qualification
feature the required anchor remains 97,199,617; epoch-224 builds require
96,767,522. The snapshot loader and runtime must still independently verify the
archive and accounts hash. Set `JETSTREAMER_V1_6_25_BOUNDARY_SNAPSHOT` and
`JETSTREAMER_MAINNET_LEDGER` to digest-bound immutable inputs; the legacy
`JETSTREAMER_SNAPSHOT_93311535` variable remains a fallback, not a slot override.
Run from the historical workspace root with rustc 1.51.0 and test-only
`RUST_MIN_STACK=134217728`.

Keep every current sealed worker unchanged. Before a new diagnostic deployment,
require source commit/push, real selected-profile snapshot integration, immutable
sealing and exact-package capability, fresh all-resource admission, an isolated
non-restarting run and a proved invocation-bound guard. A bounded measurement is
not a full cold-epoch peak bound. Epoch 225 still needs natural completion at its
canonical root, independent complete reread, current-plugin verification and
normal publication/readback gates. Its epoch-226 diagnostic tail remains private
and sidecar-free; no runtime registry or publication authority is granted here.
