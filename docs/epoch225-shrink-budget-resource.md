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

## Separately pinned bounded measurement

The opt-in `jetstreamer-utils/epoch225-shrink-budget-resource` feature builds
`jetstreamer-epoch225-shrink-budget-resource`. It reuses the reviewed bounded
runner without changing the default epoch225 profile or any live deployment.
It pins capped-shrink qualification worker `2dcc9b84…` built from the v1.6.25
workspace with `epoch225-v1-6-25-qualification`, and the existing diagnostic
parent `3915f578…`. The worker's wider internal bound grants no wider execution:
the runner retains target `97202500`, underlying root `97631459`, 256-GiB
terminal scratch gate, 3,185,678,193,366-byte minimum free space, 16 Rayon
threads, and one-hour maximum. The exact-parent/worker capability must still
prove this combination before launch.

Plans and results use distinct `jetstreamer-private-epoch225-shrink-budget-resource-`
schemas. Units begin `horizon-qualify-225-bounded-resource-shrink-budget-`, and
private roots begin `bounded-resource-225-shrink-budget-`. Preserve the same
snapshot, genesis, checkpoint names, controlled-stop evidence and bounded-canary
guard requirements. A passing bounded run cannot establish the full cold peak,
canonical root, complete epoch225, epoch226 tail, plugin or publication gates.
Source availability, a release build and sealing are preparation only; require
real selected-profile snapshot tests, exact-package capability, fresh admission,
fleet registration and the guard's first real sandbox fire before leaving a
new run unattended.

When reproducible build-cache space is needed, the read-only Rust
`jetstreamer-horizon-dev-cache-check` also accepts the distinct plan schema
`jetstreamer-horizon-selected225-dev-cache-check-plan-v1`. It selects only
`.codex/tmp-readiness/epoch225-shrink-budget-target-v1/debug`, never its release
sibling, snapshot inputs, deployed binaries or replay state. It retains the
clean source revision, root Cargo.lock digest and tracked v1.6.25 Cargo.lock
digest, rejects tracked cache members and archive/snapshot/sidecar files, and
requires empty live-process and staged-unit reference scans. Its receipt does
not authorize deletion: preserve a separate reviewed retirement intent, rerun
the check immediately before Cargo's dev-profile cleanup, and retain completion
evidence. Neither this cache profile nor cleanup relaxes any admission bound.
