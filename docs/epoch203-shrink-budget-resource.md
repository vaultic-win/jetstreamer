# Dormant epoch-203 shrink-budget comparison

For the separately scoped, not-yet-deployed RAM-backed experiment preparation,
see [epoch203-ram-resource-design.md](epoch203-ram-resource-design.md). Its offline
geometry checker does not make this disk-backed runner admissible or authorize
a replay launch.

The opt-in `epoch203-shrink-budget-resource` feature builds
`jetstreamer-epoch203-bounded-resource` with the reviewed bounded runner and
the v1.6.16 shrink-budget candidate worker `4aeca563…`. It pins parent
`025757b9…`, the same generation-bound 87,695,515 bootstrap, target
87,720,000 and terminal checkpoint 88,127,580 as the store 8 comparison.
The candidate caps returned shrink debt at the pinned upstream recovery
budget; it does not change transaction, PoH, checkpoint or cursor semantics.

Candidate plans/results and unit/run namespaces explicitly contain
`shrink-budget`. Combining `epoch203-single-thread-resource` additionally
selects one rayon thread and a separate `shrink-budget-r1` namespace.
Without that feature the comparison retains 16 threads. Do not compare
different thread settings as if shrink-budget were the only variable.

The six-hour, 256-GiB scratch measurement is not a full-prefix peak proof.
The startup minimum is only a rejection baseline: the existing six-sample
century floor plus a 416-GiB experimental envelope (256 scratch, 128 archive,
32 buffer). Fresh admission must recompute the canonical century floor and
protect every older invocation's remaining-growth claim, alongside CPU,
memory, VMA and I/O gates. It cannot authorize a fifth lane or replace a
full-prefix budget with this smaller envelope.

Keep this candidate dormant until real boundary-snapshot integration,
exact-package capability, candidate-specific fleet/guard bindings and fresh
resource admission pass. Existing profiles that pin worker `3f5e8efe…` do
not authorize this worker. Never relabel old receipts or hot-patch/restart a
healthy sealed producer. A bounded comparison still cannot promote the
runtime route, create a canonical sidecar or publish any archive.

## Fleet receipt contract (dormant)

The candidate fleet contract uses launch schema
`jetstreamer-private-epoch203-shrink-budget-resource-launch-v1`, the
`horizon-qualify-203-bounded-resource-shrink-budget-` unit namespace and
`bounded-resource-203-shrink-budget-` private-root namespace. It accepts only
the sealed 16-thread runner `d7b3f0c7…`, worker `4aeca563…`, parent
`025757b9…`, and unchanged generation-bound bootstrap. The separate
single-thread candidate remains unsupported by this fleet contract.

The receipt must explicitly record `storage_maintenance_changed: true`,
`upstream_shrink_budget_cap: true`, and `runtime_semantics_changed: false`.
It binds target 87,720,000, terminal root 88,127,580, 256-GiB scratch bound,
21,600-second runtime and 416-GiB experimental envelope. Every full-prefix,
full-peak, ordinary replay, runtime promotion, sidecar and publication claim
remains false. These fields document the bounded experiment; none establishes
fresh resource admission or real-data qualification.

Same-sample fleet reconciliation additionally requires the separately sealed
standalone guard `d039ddf0…`, its exact invocation-bound plan, one readable
worker, clean first sandboxed fire, and the exact private
`receipts/target-stop.json` handoff with 180-second maximum drainage. Baseline
guard/worker/runner receipts, a different target path and longer drainage are
rejected. The fleet checker is read-only and does not launch the experiment.
Keep both the current live metadata binary and running guards unchanged until
an independently qualified deployment transition is actually required.
