# Epoch 157 retained-prefix recovery

The original first runtime segment covers 67,824,000–68,140,176 and must remain
intact with its manifest and generated handoff snapshot. The successor's trusted
checkpoint list ends at 68,255,828, not the focused terminal 68,255,999. Its two
failed startup attempts are not replay divergence or permission to fabricate a
terminal commitment. The parent now preflights every runtime segment's exact
terminal before any costly replay or retained-archive reread; the child retains
its independent focused checkpoint gate.

Recover privately, with no canonical sidecar or publication authority:

1. Independently qualify the complete retained segment at its original path
   using the narrowly pinned literal-name validator. Bind output start
   67,824,000, bootstrap 67,823,809, terminal 68,140,176, v1.5.6 worker and complete
   archive/manifest digests. Do not duplicate 123 GB just to rename it.
2. Freshly admit a focused v1.5.8 qualification from the retained snapshot at
   68,140,176 through the real trusted root 68,255,828. Bind the full snapshot,
   generated-handoff evidence, source and destination workers, genesis, guards
   and immutable node. Keep every older growth claim and the century floor.
3. Require the **actual worker** to freeze its restored checkpoint before its
   first replay entry. Compare slot, bank hash, accounts hash, last blockhash,
   capitalization, transaction count, tick height and complete state to the
   verified predecessor, with zero bootstrap writes. Do not equate independent
   validator-local write cursors. The new native barrier strengthens every
   registered generated handoff; it preserves the normal snapshot constructor
   and all later canonical checkpoints, never treats restored state as carried.
4. Independently validate the resulting root-bound private segment. The final
   171 slots, exact restart/assembly provenance, complete epoch/plugin checks,
   canonical import and R2 upload/readback/sidecar remain separate unqualified
   work. A private root pass does not admit the full epoch.

Keep failed 157 in the durable open repair backlog. Its old production countdown
must be retired only through fresh complete-fleet ownership checks and the
reviewed conditional status-only cleanup; preserved data and qualification work
are not disposable. Restore a production ETA only after an actual qualified live
production claim exists. No healthy replay restart or R2 archive/sidecar mutation
is authorized by this recovery plan.
