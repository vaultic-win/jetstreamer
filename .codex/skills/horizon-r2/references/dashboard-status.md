# Dashboard status accuracy and cleanup

The operator owns the correctness of `epoch-N.epoch-status.json`: these objects feed a live
dashboard. An object must represent actual in-flight work with an evidence-backed estimate to the
verified R2 sidecar commit, not a historical attempt, staging plan or promise to retry later.
Absence means no published live estimate; it never means the epoch is storage-complete.

## Correct known stale estimates immediately

As soon as existing evidence shows an active epoch's ETA is wrong, overdue or tied to an old
owner/phase, correct the R2 JSON in the same work cycle, before continuing lengthy build, repair
or admission work. Recording an incident or telling the user that the ETA is stale is not the
correction. Do not wait for the next scheduled poll, a producer restart, a production build or
archive qualification. Status metadata must remain maintainable independently of those gates.

An observed missed arrival, failed attempt, newly discovered blocker or changed delivery plan
requires immediate reassessment of the published ETA. Before replying that the estimate is stale
or resuming the blocked epoch's work, publish the corrected estimate and authenticate its readback.
If publication fails, record and report the exact failure and make correction the next action.
Do not claim success from a local payload or leave the old countdown described as current.

Publish a fresh `sampled_at_utc` and a definite integer `estimated_remaining_millis` representing
the current reasonable best guess until the verified `.sha256` sidecar appears. Include remaining
repair, build, qualification, queueing, replay, import, verification, upload and readback time as
applicable. If measured rates are missing or a previous model fails, use a reviewed planning
estimate and record its assumptions and uncertainty privately. Never reset the old countdown,
clamp an unfinished epoch to zero or leave an elapsed estimate unchanged.

Bind the real active repair/task owner and honest phase (`verification` for preparation/repair),
including operator or sub-agent work while zero replay lanes run. Never impersonate the terminated
producer or delete active work's report to hide a bad estimate. If the publisher cannot represent
that owner, fixing the narrow metadata path takes priority over the production build; it must not
remain dependent on the archive tool's next release. Preserve conditional ownership checks and
verify the corrected bytes through authenticated R2 readback before reporting success.

This immediate correction is mandatory even inside the 30-minute interval. Use available evidence
and the targeted authenticated status read/write/readback; do not wait for or trigger another routine
replay/resource poll. It does not reset or replace the next scheduled full-range audit. For example,
if an epoch's advertised arrival has passed and a known import repair still blocks delivery, publish
a new best guess including that repair and all remaining delivery stages before resuming the repair.

Routine full-range audits and refreshes remain every 30 minutes; user-requested status polls remain
allowed out of band. Genuinely inactive work still follows the separate cleanup lifecycle below.

### Status-only fallback

When the qualified Rust publisher cannot represent the actual active repair owner or is waiting
on a production build, use an existing authenticated S3 client for this metadata-only correction.
Do not make status accuracy depend on that build. This fallback may replace only the exact
assigned `epoch-N.epoch-status.json` keys; it cannot create, modify or remove archives, sidecars,
verification evidence or replay claims.

Read the current object and ETag, confirm the known stale publication and exclusive current repair
ownership, and validate all six wire fields. Record the actual operator/task owner, original start
evidence, current repair activity and estimate assumptions privately; never invent a live producer
IID. Issue one conditional PUT with that exact ETag, then GET and compare the complete corrected
bytes. Save durable private before/after hashes, ETags, timestamps and the authenticated readback
result. Stop and reconcile an ownership change, HTTP precondition failure or readback mismatch;
never retry unconditionally. These receipts document a status correction and confer no archive
publication authority. Normal qualified publishing can take over after the actual phase handoff.

## Range-wide audit every 30 minutes

The operator is responsible for every `epoch-N.epoch-status.json` in the assigned range, not only
reports belonging to currently running lanes. At each coordinated 30-minute observation:

1. Use authenticated R2 inventory to discover every canonical status key in the full range and
   read its current payload and ETag. Compare remote bytes with the exact publication receipt;
   do not substitute local receipts, the dashboard cache or an active-only list for this audit.
2. Reconcile every discovered report against the complete fleet and ready-pair inventory. Check
   its actual owner, phase, sample time, definite integer fields and estimate through verified
   sidecar commit. Also identify active epochs missing a report. An overdue ETA must be diagnosed
   against actual progress or terminal evidence, rather than left counting down or set to zero.
3. Refresh all active reports from the same accepted observation and current estimate model,
   including repair, qualification and delivery phases. Verify the published bytes through
   authenticated readback. Retire obsolete reports only through the qualified completion or
   confirmed-inactive lifecycle; protect newer owners and other-host handoffs.
4. Record the per-epoch outcome in the cycle evidence: refreshed, already complete and cleaned,
   inactive and cleaned, or a specific unresolved publication/cleanup incident. Keep unresolved
   incidents in the authoritative backlog and prioritize their repair before lengthy unrelated
   work. Audit them again next cycle; acknowledging a stale report does not make it current.

Run this audit and status maintenance before lengthy repair, build or admission work, even when
zero replay lanes are running. Handle known failure and handoff events promptly between cycles.
User-requested status updates authorize the same audit out of band. Keep one observation cadence;
this requirement does not authorize additional autonomous polling inside the 30-minute minimum.

## Maintain useful estimates

- Always show an ETA for active work, including active recovery after a failed producer. When
  measured progress is insufficient, use a reviewed planning estimate with explicit repair,
  restart/qualification, replay and delivery allowances, bound to the current active repair owner.
  Explain the assumptions and uncertainty in private receipts and human updates. Repair missing
  model/tool support promptly; do not substitute "ETA unavailable", hide the countdown, reuse a
  terminal replay identity, or claim an unmeasured allowance is a guaranteed upper bound. This
  requirement does not turn an unowned backlog entry into active work or bypass publication gates.
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
  After accepting the coordinated fleet, refresh its existing live reports before lengthy
  admission or repair work; publish newly admitted owners through their separate initial event.
- Bind every estimate to the actual invocation, sample time, current progress and phase. Recompute
  remaining replay from measured rates and the real publication gate, including queued members of
  a legacy cohort. Include archive close/import, independent full/current-plugin checks, upload,
  whole-object readback and sidecar commit. A replay terminal is not a landing time.
- Revise rate assumptions and downstream allowances from observed phase durations and queue
  contention. Do not mechanically count down an old estimate, clamp an overdue job to zero, insist
  that ETAs decrease monotonically, or conceal a slowdown to keep the dashboard looking stable.
  Keep the required JSON integers and use `sampled_at_utc` and `phase` honestly.
- A running producer with temporarily missing rates is not inactive. A failed rate model requires
  a reviewed planning estimate; a failed identity check requires binding the actual current owner.
  Treat a stale or invalid projection, failed status
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

A failed, stopped, abandoned or qualification/admission-blocked epoch with no live replacement,
downstream work or active operator/sub-agent repair must not keep a live countdown. A stopped
producer with an active repair owner needs an updated repair estimate, not inactive cleanup.
This status-only cleanup does **not** require a
ready archive or sidecar and does not authorize removing any archive, sidecar or retained work.

Use a reviewed, sealed Rust cleanup path with the following gates:

1. Bind the exact epoch/key, previous owner's controller/producer invocation IDs and latest durable
   status-publication receipt. Preserve authenticated current status bytes and ETag, terminal
   service/journal evidence and the fleet transition. Verify that the current object is precisely
   the owned publication being retired, not a newer sample or another server's object.
2. Positively prove that the owner is terminal or its disappearance is established by durable
   terminal evidence. Check the full claim census for a replacement replay, queued/activating
   replacement, active operator/sub-agent repair, active verifier/uploader/readback and authenticated
   other-host handoff. A timeout,
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
