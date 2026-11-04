# Qualified checkpoint continuation

Use this path when a retained epoch prefix and an exact historical snapshot may avoid repeating
valid replay. Compare total time to verified R2 sidecar with a cold replay, including the fresh
prefix reread, restore, suffix, assembly, independent final/plugin checks and delivery. Preserve
the original prefix, manifests, snapshots and evidence; do not truncate or append to them in place.
An unqualified shortcut is not a scheduling candidate merely because its replay remainder is small.

## Prove the restart boundary

- Use only a reviewed implementation whose exact immutable build supports the intended restart
  and archive provenance. Do not generalize a build-bound diagnostic into ordinary CLI/reuse or
  runtime-registry admission. Preserve the ordinary epoch's canonical-root obligation: combining
  a verified prefix with a suffix must not remove it or bypass focused qualification's exact
  terminal-checkpoint requirement.
- Bind the complete prefix, segment manifest, snapshot, unchanged historical worker, genesis,
  parent build, exact output coverage and private destination by digest and identity. Independently
  reread and deeply validate the entire retained prefix before execution or assembly. Revalidate
  source identities after reads and retain each independent integrity event as separate evidence.
- In the actual suffix worker, before sending any replay entry, freeze the native restored
  checkpoint and compare slot, bank hash, accounts hash/kind, last blockhash, capitalization,
  transaction count, tick height and complete-slot state with the verified prefix terminal tuple.
  Require zero bootstrap writes and the full snapshot SHA-256. A prior restore-only probe is useful
  evidence but does not replace this check in the worker that will execute the suffix.
- Treat raw write-version cursors as independent validator-local namespaces across snapshot
  restoration. Use explicit reviewed normalization mappings; never force cursor equality, invent
  continuity or rewrite consensus fields to obtain a match. Require gap-free, non-overlapping slot
  coverage, full source hashes, PoH continuity, metadata semantics and account-update ordering.

## Admit and execute privately

Freshly admit the complete incremental peak for snapshot copy/restore, indexes, suffix, assembly
output and independent verification scratch while protecting older growth claims and the century
floor. Prefer bounded measurements over treating a full cold replay and a short continuation as
equivalent workloads. Seal an isolated no-clobber plan, use a persistent non-restarting service,
bind its exact invocation to a proven reserve/VMA guard, and capture terminal evidence. Keep the
new outputs private and canonical-sidecar-free during diagnostic qualification.

For the current epoch-213 experiment, the dedicated
`epoch213-checkpoint-continuation-diagnostic` build in `README.md` is restricted to the exact retained
prefix through slot 92,447,542 and the 457 remaining slots through 92,447,999. Its explicit V4
same-runtime restart provenance preserves both source generations and independent write cursors;
it does not grant ordinary V4 reuse, publication or R2 authority. Consult the checked-in CLI/plan
implementation rather than inventing broader flags or substituting another epoch or snapshot.

## Close the normal publication gates

Independently verify the complete assembled archive and current-plugin output against the same
final digest. Require a reviewed admission path for that provenance before canonical import or
sidecar creation; do not project restarted V4 lineage into uninterrupted V1/V2 provenance. Preserve
any unresolved initial PoH anchor or adjacent-boundary obligation explicitly: a proven internal
restart does not prove the epoch's initial boundary. Normal archive/sidecar and local-retirement
gates still apply independently; do not make upload wait for retirement-only boundary receipts.
After the archive publication gates pass, authenticated upload/readback may commit the R2 sidecar,
followed by the authorized status-JSON cleanup. Never overwrite or delete R2
archives or sidecars, expose the epoch-301 tail, or use this path to restart a healthy legacy lane.

Record prefix validation, native restart validation, suffix replay, assembly, independent final and
plugin verification, upload/readback, and sidecar commit timings separately. Keep any in-flight
status/fleet updates on the same existing 30-minute observation; a user-requested status check may
run once out of band under the normal exception. Failed qualification preserves valid retained
work and starts diagnosis; it does not authorize automatic cold replay or gate removal.
