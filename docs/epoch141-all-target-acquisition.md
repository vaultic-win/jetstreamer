# Epoch 141 all-target native acquisition

The candidate `jetstreamer-epoch141-ledger-native-all-target-acquisition-plan-v2`
profile extends diagnostic raw acquisition to every target in the existing
independently finalized18,283-target census. It does not replace the strict
connected-metadata recovery planner or promote a runtime route.

All targets run inside one complete-source-bound, read-only native session.
The retained database membership and every member are rehashed before open and
after close, not reopened/rehash-scanned for each target. Each target first
reads its exact metadata, then uses the existing diagnostic planner to obtain
target/parent metadata and root/dead/orphan markers plus every data-shred key.
False connectivity and null/odd-length values are preserved. An explicit
metadata-planning rejection is recorded as that target's outcome and does not
silently remove it from the census. Native read errors, changed metadata/order,
guard trips and source-revalidation failures remain fatal.

Per-batch65,536-query/64MiB/1MiB-value limits remain unchanged. The new session
has bounded 36,566batches, 16,777,216queries and 32 GiB returned values. Durable
target output is capped at 24 GiB, including 8 MiB reserved for the final manifest;
fresh admission must retain the full 32 GiB output reservation above the existing
protected reserve. It cannot borrow the first-target256MiB output allowance or
1 GiB admission profile. Output or session exhaustion preserves useful partial
diagnostics and produces no final completed-session manifest.

Only after successful native close and complete source revalidation does the
tool rehash every provisional target receipt and every bound input and commit
the final manifest. It separately reports attempted, raw-acquired and
metadata-rejected targets plus missing/odd-length shred counts. Complete
attempt coverage is not complete raw acquisition; raw acquisition is not
canonical ancestry, trusted historical liveness, authenticated PoH, root
qualification, replay, publication or R2 authority. All such authority flags
remain false and recovered-target count remains zero.

The new admission profile is
`epoch141-read-only-all-target-acquisition-v5`, with its own
`horizon-epoch141-native-full-census-acquisition-all-` unit namespace.
Source tests do not authorize a native open: seal the exact binary/plan,
qualify its admission tuple, complete the fleet/guard handoff and on-node
capability proof, and perform fresh complete admission before launch. Preserve
both earlier failed attempts, the post-close rejection and the successful
first-target byte/PoH diagnostics. The epoch 141 repair remains open.

The fleet reader recognizes the all-target diagnostic only under the distinct
fixed `horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service`
owner and its sealed candidate, plan, admission manifest and private output root.
It requires the full 32 GiB output reservation in both initial guard and admission;
the first-target profile retains its original smaller limits and cannot supply
proof for this owner. Command identity, zero restarts, all 16column families,
retained source digests and the unchanged12hour/16GiB hard sandbox remain bound.
Unknown acquisition units and cross-profile evidence fail closed. Reader source
support does not adopt a claim or authorize a launch: qualify and seal the reader,
extend the routine handoff, and bind the real initial guard before activation.

The first all-target invocation `72424001…` stopped before any native database
open: its scope predicate confused the enclosing interval end 61328765 with the
finalized census's actual last post-gap target 61328744. Preserve that invocation
and guard as failure evidence, never as a completed native session. The corrected
candidate checks the exact 18283target scope before check-only returns and before
writing the initial guard. A root read-only regression revalidates the actual
finalized collection and all its retained target receipts, not just a synthetic
topology. A corrected binary still needs a distinct immutable attempt, fresh
admission and monitoring bindings; never replace the failed invocation's output.

The corrected attempt uses the distinct `acquisition-all-20261022-v2` unit,
private root, plan and admission receipt. Its admission profile remainsv 5: the
18283target scope, 32 GiB reservation, 144 GiB available-memory requirement and hard
native sandbox are unchanged. The admitter selects the new binary only for that
exact new unit; old/new binary, unit or receipt pairs cannot be exchanged. The
fleet keeps both all-target attempts as separate diagnostics. Its routine retry
handoff requires the exact retainedv 1 guard and actual zero-restart failedv 1 owner
before adopting the new initial guard. Corrected code, an old admission or an
offline handoff is never new launch authority.
