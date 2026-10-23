# Dashboard status accuracy and cleanup

The operator owns the correctness of `epoch-N.epoch-status.json`: these objects feed a live
dashboard. An object must represent actual in-flight work with an evidence-backed estimate to the
verified R2 sidecar commit, not a historical attempt, staging plan or promise to retry later.
Absence means no published live estimate; it never means the epoch is storage-complete.

## Maintain useful estimates

- The current consumer (`apps/web/src/horizon.rs` in the Vaultic dashboard repository) requires
  all six wire fields and accepts only the phases `replay`, `verification`, `upload`, `readback`.
  An unknown phase rejects the entire report. Native-input/qualification checks and assembly are
  coarse `verification`; actual transaction execution is `replay` even when its internal route is
  still unqualified. Keep detailed stage names and qualification authority separate in private
  receipts. A new wire phase requires reader support and parser coverage before publication.
  ETA is `sampled_at_utc + estimated_remaining_millis`, so republishing a newer sample must use
  a newly calculated estimate, not restart an old countdown.
- Refresh at the existing coordinated 30-minute cadence and handle authenticated failure,
  completion and phase-handoff events promptly. Do not create another routine polling loop or
  restart healthy producers to improve the display.
- Bind every estimate to the actual invocation, sample time, current progress and phase. Recompute
  remaining replay from measured rates and the real publication gate, including queued members of
  a legacy cohort. Include archive close/import, independent full/current-plugin checks, upload,
  whole-object readback and sidecar commit. A replay terminal is not a landing time.
- Revise rate assumptions and downstream allowances from observed phase durations and queue
  contention. Do not mechanically count down an old estimate, clamp an overdue job to zero, insist
  that ETAs decrease monotonically, or conceal a slowdown to keep the dashboard looking stable.
  Keep the required JSON integers and use `sampled_at_utc` and `phase` honestly.
- A running producer with temporarily missing rates is not inactive. Never invent a replacement
  estimate after an estimator fails closed. Treat a stale or invalid projection, failed status
  publication, unsupported downstream phase or missing authenticated readback as an operational
  incident: record it, repair the model/tooling promptly, and do not present the last known ETA as
  current. Leaving misleading metadata indefinitely is not a completed repair.
- Carry genuinely active verification/upload/readback forward with an evidence-bound phase and
  remaining-time estimate. If the deployed publisher only supports replay identities, qualify the
  required pipeline binding rather than pretending a terminated producer is still replaying.
  Queued epochs within a live legacy cohort remain claimed even before their own replay begins.
- Preserve the producer's real manager start and authenticated launch receipt across delivery
  phases. A private continuation's launch schema may differ from a legacy controller's; qualify
  its exact native receipt binding instead of rewriting it into a legacy shape. Never backdate a
  new phase to an observation taken before it started. Use a supported authenticated handoff-event
  publisher, or the next scheduled observation, while delivery continues independently.
- Estimate readback from its own measured progress, separately from upload throughput. Bind the
  progress journal to the exact delivery invocation and the coordinated sample cutoff; include
  time since the last marker so a stall can increase the estimate. Retain a measured allowance
  for final source revalidation and sidecar commit. Check whether reads already run concurrently
  before proposing more connections, and keep bounded transport probes distinct from full-object
  verification evidence.

## Remove confirmed inactive status objects

A failed, stopped, abandoned or qualification/admission-blocked epoch with no live replacement or
downstream work must not keep a live countdown. This status-only cleanup does **not** require a
ready archive or sidecar and does not authorize removing any archive, sidecar or retained work.

Use a reviewed, sealed Rust cleanup path with the following gates:

1. Bind the exact epoch/key, previous owner's controller/producer invocation IDs and latest durable
   status-publication receipt. Preserve authenticated current status bytes and ETag, terminal
   service/journal evidence and the fleet transition. Verify that the current object is precisely
   the owned publication being retired, not a newer sample or another server's object.
2. Positively prove that the owner is terminal or its disappearance is established by durable
   terminal evidence. Check the full claim census for a replacement replay, queued/activating
   replacement, active verifier/uploader/readback and authenticated other-host handoff. A timeout,
   stale sample, expired ETA, missing rate or one failed `systemctl` request is not proof of
   inactivity. Protect any newer active owner and repair that owner's status instead.
3. Recheck ownership and absence of replacement/downstream claims immediately before mutation.
   Fsync a private no-clobber intent binding the evidence and exact object. Issue only a conditional
   delete for `epoch-N.epoch-status.json` using the observed ETag/version. A precondition failure
   means stop and reconcile; never retry with an unconditional delete.
4. Verify authenticated absence and recheck the claim census, then fsync a private completion
   receipt. If a new live claim appeared, publish its valid fresh status through the normal gated
   path and report the race. An interrupted cleanup may resume only from its exact intent and
   matching evidence; unexplained absence is not a successful cleanup receipt.

Keep all publication and deletion receipts as history. Classify the epoch honestly in the fleet
ledger after cleanup (`failed-needs-repair`, `blocked-qualification`, etc.), not `remote-ready`.
Diagnosis, preservation, backfill and eventual replay remain separate obligations.
Retain an open repair entry with its failure evidence and next action even after authenticated
status deletion succeeds. Prioritize safe diagnosis/qualified recovery, carry that entry across
controller or chat restarts, and close it only when the recovered epoch reaches a verified ready
pair. Status cleanup fixes the dashboard; it does not fix or erase the failed epoch.

The documented `jetstreamer-r2 status-delete` completion path requires a verified ready pair; it
does not automatically implement inactive cleanup. Never fake its archive evidence or use a raw
S3/CLI delete as a shortcut. If an inactive-cleanup implementation is missing, implement, test and
seal that narrow Rust path promptly; explicitly report the still-visible stale objects until
cleanup has actually passed authenticated readback. Tests must cover live replacements, active
downstream work, changed payload/ETag, ambiguous ownership, conditional-delete races and durable
intent/completion recovery. Skill text alone is not proof that remote metadata was removed.
