# Epoch141 all-target native acquisition

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
has bounded36,566batches,16,777,216queries and32GiB returned values. Durable
target output is capped at24GiB, including8MiB reserved for the final manifest;
fresh admission must retain the full32GiB output reservation above the existing
protected reserve. It cannot borrow the first-target256MiB output allowance or
1GiB admission profile. Output or session exhaustion preserves useful partial
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
first-target byte/PoH diagnostics. The epoch141 repair remains open.

The fleet reader recognizes the all-target diagnostic only under the distinct
fixed `horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service`
owner and its sealed candidate, plan, admission manifest and private output root.
It requires the full32GiB output reservation in both initial guard and admission;
the first-target profile retains its original smaller limits and cannot supply
proof for this owner. Command identity, zero restarts, all16column families,
retained source digests and the unchanged12hour/16GiB hard sandbox remain bound.
Unknown acquisition units and cross-profile evidence fail closed. Reader source
support does not adopt a claim or authorize a launch: qualify and seal the reader,
extend the routine handoff, and bind the real initial guard before activation.
