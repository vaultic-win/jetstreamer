# Horizon host utilization

Use this guidance whenever choosing replay concurrency, resuming a host, replacing a completed
lane, or deciding whether the machine can safely do more work. The user's concurrency policy targets
90% system-memory utilization; measure verified upload throughput as the useful outcome as well.

## Establish the operating point

Inventory exact live producer/controller invocation IDs, zero-restart state, managed epoch claims,
scratch paths, guards, and authenticated R2 ready pairs before making a capacity decision. Exclude
duplicate or already-complete work. Record the host totals and the effective limits that can block
another lane:

- controller CPU arithmetic and per-lane quota;
- protected memory, memory reserve, scheduling admission, `MemoryHigh`, and `MemoryMax`;
- physical scratch use, evidence-backed remaining-growth claims, candidate incremental peak, and
  the current century floor computed as twice the mean canonical `.jet` size;
- live worker VMA counts, `vm.max_map_count`, the configured VMA stop, and credible VMA growth;
- I/O pressure, major faults, memory pressure, and any current verifier, uploader, or snapshot
  activity that materially contends with replay.

Linking a dormant systemd unit triggers a manager reload, which can clear the display-only
timestamps and PID embedded in `ExecStart` while the invocation and authoritative `MainPID`
remain live. Use the reviewed command-identity comparison for that case: exact executable,
arguments and `ignore_errors`, alongside unchanged invocation ID, `MainPID`, state and restart
count. Preserve raw observations. Do not treat display metadata loss as a restart, or normalize
away an actual command or owner change.

Match a new job's systemd lifetime to its terminal verifier. If that verifier requires
`LoadState=loaded`, use its persistent service file; `systemd-run --wait` does not by itself
retain a transient unit after completion. Preserve the actual running receipt and exact PID1
start/completion journal. If systemd collects a completed unit, retain the real `not-found`
state and qualify recovery from those original proofs before promoting its result. Recreating
an idle unit does not restore the historical invocation or prove its execution.

Choose the desired lane count from memory alone, targeting 90% of total host memory used. Estimate
the marginal lane RSS from this century's observations, subtract measured non-lane usage once, and
update the count from actual host usage at the regular observation. Track the difference between
the desired count and the executing count. CPU/I/O govern sharing and throughput, while disk
pressure triggers checkpoint/offload/restore actions; they do not silently lower the desired count.
Prefer controlled oversubscription, with explicit selected victims and tested pressure-relief paths.
Runtime compatibility, non-overlapping ownership, integrity, VMA protection and the century disk floor
remain execution requirements. Missing recovery support is a concrete implementation task.

When the coordinated observer provides a host resident census, follow
`docs/horizon-host-resident-accounting.md`: subtract invocation-matched lane RSS from that same
census once and include kernel resident allocations. Do not derive non-lane resident usage by
subtracting lane RSS from `MemTotal - MemAvailable`; reclaimable mapped pages make those bases
inconsistent. Count private diagnostic replays and active delivery stages explicitly. If the
deployed target calculator does not support those owners, record the target as unavailable and
the missing accounting as the next task; do not reuse a different campaign's calculated target
or fill an older receipt with a new resource read.

Call the highest concurrency demonstrated by a clean coordinated observation under equivalent
runtime, lane shape, reserve policy, and guard settings the **proven operating point**. A valid
sample binds every live invocation and scratch tree before and after measurement, reports zero
restarts, preserves the century `.jet`-derived filesystem floor, and remains below the VMA stops.
Do not transfer a proven count between materially different machines or lane shapes without new evidence.

### Change live limits with their controller policy

When a lane shows sustained `memory.high` events and direct reclaim despite ample host capacity,
consider a bounded memory-limit experiment on one lane. First inspect its actual controller's
adoption checks and saved configuration fingerprint. Some controllers require `MemoryHigh`,
`MemoryMax`, CPU and other native properties to match their launch arguments exactly, and include
those arguments in the saved-state hash. An isolated `systemctl set-property` change can therefore
make a healthy producer fail controller adoption and exhaust controller retries. Qualify the
matching controller/state/guard policy transition before changing such a live producer's limits;
do not rewrite a saved configuration hash to bypass that check.
If its current guard becomes unarmed while the controller is inactive, qualify a temporary
producer-bound guard before a planned controller handoff; an active timer alone does not cover it.

If recovery requires restoring limits, keep the producer alive. Check actual usage and reclaimable
versus anonymous/unevictable memory before lowering a hard cap; where appropriate restore the soft
cap first, allow safe reclaim, then verify enough headroom before restoring the hard cap. Preserve
failed controller history and bind any real replacement controller ID plus its first healthy native
guard fire before resuming the observation chain. Evaluate an experiment over a complete ordinary
observation interval after the change; a mixed interval or interrupted controller is not proof of a
throughput improvement. Keep every unrelated growth claim and guard floor intact.

## Qualify measured admission budgets

Preserve the protective free-space thresholds of every existing live owner when admitting a
candidate. The required initial free space must cover the candidate's incremental peak above
the larger of (a) the century floor plus all protected remaining-growth claims and (b) the maximum
`minimum_free_bytes` in the existing invocation-bound guard plans/receipts. Do not sum a shared
threshold once per lane, count the candidate twice, or lower another owner's guard to make it fit.
Keep this inherited guard constraint separate from the twice-average-century `.jet` safety floor.
A lane that fits the growth calculation can still trip an existing guard; record the exact
shortfall and qualify reclamation/offload or a separate reviewed guard handoff before launch.
Enforce this calculation in actual admission as well as planning, using the same coordinated
sample and authenticated guard evidence; it does not authorize another routine resource poll.

Protect runtime-enforced available-memory floors as well. Bind each live owner's actual wrapper
and guard reserve. Use the larger of the host reserve and the largest enforced live-owner floor
once, then add the candidate allowance and protected remaining hard-memory growth once. Do not
add a shared floor per lane or substitute current RSS for remaining hard growth. The existing
native epoch 223 prefix enforces 480 GiB available memory; that inherited constraint is separate
from the user's 90 percent target and must not become a default reserve for new profiles. Keep
the memory-selected desired lane count while qualifying execution or a supported guard handoff.
An admission path that cannot protect a live owner's enforced reserve is not qualified for that
owner; do not lower its guard or mutate its sealed wrapper to make another lane fit.

Allocation credited against future disk growth must be a proven lower bound. A guard's upper-bound
tree walk can count hardlinked paths or shared extents repeatedly, so its total alone cannot earn
that credit. Bind unique allocation to the exact owner, root descriptors and filesystem profile;
reject aliases, mount escapes or shared allocation that the qualified proof cannot account for.
Clamp credit conservatively across the coordinated sample, guard and current admission evidence.
Keep any required integrity scan inside that fresh admission transaction, without another routine
polling loop. Unavailable allocation proof grants no new credit or admission.

### Memory reservations from lane RSS

Observe RSS in the existing 30-minute resource sample, with the ordinary user-requested status
exception. Count each process in the invocation-bound lane once, including its parent and worker;
when controller and producer are the same unit, do not add their identical measurements twice.
Bind process IDs and start times and reject a changing/incomplete census for capacity decisions.
Record per-process `VmRSS` and `VmHWM`, and sum current `VmRSS` for the lane. RSS includes resident
file-backed pages; cgroup memory additionally accounts for file cache and is a separate metric.
Individual process high-water marks may occur at different times, so their sum is not a measured
concurrent lane peak. Assembly/restore/verifier roles should remain labeled separately from settled
replay when comparing lane shapes.

The user's policy is a per-lane scheduling memory reservation **no greater than 1.5× the maximum
valid aggregate lane RSS observed in that century**, superseding the earlier 2× multiplier. Use
integer bytes and compute `floor(3 * maximum_lane_rss_bytes / 2)` with checked arithmetic; do not
round a whole-GiB reservation above the ceiling. For epochs 200–300 the initial user-selected RSS
estimate is 150,000,000,000 B, so the initial memory reservation is 225,000,000,000 B per lane. This is
an estimate until replaced by observed aggregate RSS; it is separate from the 300 GB scratch budget.
Maintain the century maximum from durable identity-valid samples, without silently resetting it
when a lane finishes or a new observer is deployed. Other centuries need their own RSS history.

Use this policy in newly sealed scheduling/admission generations. Preserve healthy producers and
their existing hard cgroup limits; scheduling reservations and hard stop limits are different.
Reassess inherited fixed reservations rather than counting both the RSS allowance and an older
per-lane allowance. Account for measured host/kernel overhead once, alongside distinct concurrent
verification/restore work, and document any genuine host reserve; do not hide extra per-lane
headroom in a repeated host reserve. Capacity still has to satisfy actual available memory,
pressure, disk, CPU, VMA and compatibility gates. An invalid RSS sample grants no capacity increase;
keep the last valid century evidence, diagnose the telemetry, and retain normal protection.

### Capped-shrink scratch estimates by century

Use a separately recorded scratch estimate for each century and worker/runtime profile. For this
campaign, the user selected **300,000,000,000 bytes (300 GB, decimal)** per capped-shrink lane for
epochs 200–300. This is an authorized planning assumption, not a claim that every epoch's peak has
been measured. It can support a newly sealed bounded admission without first demanding a completed
full-epoch peak experiment for every candidate. Exact input/runtime capability and protective guards
still have to pass. Keep uncapped historical measurements labeled with their original worker;
neither impose their larger projection on a capped candidate nor erase the evidence.

Keep the scratch estimate separate from archive output, cached or restored inputs, assembly/copy,
verification staging and margin. Count overlapping phases at their incremental peak and avoid
double-counting an already protected allocation. The twice-average-`.jet` century floor remains a
separate host reserve. Record the memory-selected target, actual executing count, local disk
headroom and any checkpoint/offload transition needed to reach that target. CPU/I/O statistics
inform sharing and useful throughput; compatibility and guards still have to qualify each job.

When live tree metering is needed, use the descriptor-based root-budget scanner. Snapshot loading
and AccountsDb maintenance rename and remove files while a scan runs; a walker intended for a
frozen capture can turn a normal vanished path into `ENOENT` and kill otherwise valid work.
Use the churn-tolerant scanner only within a qualified scan-time bound, and retain the stricter
capture walk for an actually frozen process group. Preserve a monitoring failure's
receipt and journal before correcting it; do not restart unrelated healthy producers.
Keep full-tree censuses off a replay's synchronous supervision path when the restore tree makes
them expensive. A scan deadline is unavailable metering, not evidence that the byte budget was
exceeded. For a separately admitted diagnostic, enforce its reserved filesystem free-space floor
directly, alongside hard memory and VMA controls; label the per-lane scratch amount as a planning
estimate. Do not claim an exact own-tree cap without a working qualified measurement or quota.
Retire failed preparation scratch only through a cleanup profile that accepts its actual evidence
schema. The Rust failed-diagnostic retirement tool's `warmup223_v3` profile binds that exact failed
attempt, preserves its run root/output/receipts, rehashes retained inputs, requires the old guard
timer inactive and checks live process references before deleting only scratch. It cannot retire
the current attempt or close the original replay failure. Never substitute another epoch's cleanup
schema or treat a failed restore as a resumable checkpoint.
A directory name or unused R2 holding prefix has freed no local capacity.

Reassess the estimate with each existing coordinated observation. If measured scratch approaches or
exceeds the planning allowance, stop increasing concurrency, preserve the healthy work and update
the century/profile estimate and fresh admission using the actual evidence. Changes to a live
reservation or guard need an explicit immutable transition with protection maintained throughout;
do not rewrite sealed plans. Do not transfer 300 GB to later centuries. The user's suggestion that
the 900s might need about 800 GB is illustrative until that century's estimate is measured or chosen.

When an unqualified or inherited capacity estimate is the only reason a staged singleton cannot
launch, record the missing bound and stage the smallest useful bounded experiment to resolve it.
Do not leave an indefinite hold with no evidence-gathering next action. The experiment itself must
fit fresh admission, use isolated private output and scratch, and have a sealed work/time bound,
invocation-bound reserve/VMA guard, and terminal evidence capture. Do not disturb healthy replays.
Before starting a new service profile, validate its complete guard plan through the same static
validation entry point used by the deployed guard, including the service namespace, native or
worker binding, run root and budgets. Passing a native-PID helper test alone does not prove that
the outer guard accepts that service. Qualify native-input and full-replay service profiles
separately. If the first actual guard fire fails, stop only the new attempt, preserve its exact
terminal and guard evidence, and repair the guard before a freshly admitted retry; never leave
the new job running without its required guard or change an older healthy job's guard in place.
For a failure before archive recording begins, prefer an explicit bounded warmup reproduction.
Bind the cold bootstrap and enforce its entry limit in the worker when parent progress can run
ahead of execution. Retain the native fatal result and trace; a bounded diagnostic is neither a
repaired epoch nor authority to relax its runtime or publication gates.
After a bounded reproduction captures the native fatal transaction, compare its exact signature,
slot, raw message and finalized result before choosing another runtime experiment. Preserve raw
RPC bytes and distinguish post-commit trace observations from loaded account preimages. A newer
worker passing a short suffix does not qualify it for an older cold prefix; follow independently
checkpointed era boundaries rather than repeating an unchanged failing warmup or suppressing the
native error. See [the epoch 223 investigation](../../../../docs/epoch223-fee-load-diagnostics.md).

Measure restore baseline separately from settled replay growth: physical and apparent scratch,
file count, VMAs, CPU, memory peak/events, I/O pressure, transactions and account updates. Bind the
exact worker, parent, snapshot, runtime settings, and source interval. Use multiple comparable
windows and account for nonlinear growth, compaction, archive assembly, verification scratch, and
overlapping delivery work when proposing a conservative incremental-peak envelope. A short canary,
low current use, or a cheap 457-slot continuation is not a full cold-epoch resource bound.

Use an optimized test harness for a full cold snapshot load/freeze qualification or performance
measurement. Bind its build mode, exact ignored-test selection, source and executable digest in
the preparation evidence. An inherited debug harness can exhaust the work bound without reaching
the native checkpoint; reserve it for an explicit diagnostic requiring debug behavior. Preserve
an already running attempt, capture its real terminal outcome, and qualify a separately sealed
optimized generation before retrying. Listing an ignored test is not executing or qualifying it.

Promote a smaller scheduling or growth estimate only through reviewed, sealed evidence and fresh
admission that protects all older invocation-bound remaining-growth claims and the century floor.
Keep hard memory/CPU limits, reserves and VMA stops unchanged. Do not edit claims beneath a live
controller or equate a successful performance experiment with compatibility/plugin qualification.
If the evidence cannot bound the candidate, retain the conservative budget and specify the next
bounded measurement or clean-completion event that can resolve admission. Once it does fit, use
the normal work-conserving backfill path rather than waiting for another status report.

## Keep the host work-conserving

- Before an oversubscribed admission, select the lowest-cost resumable victim and bind its actual
  invocation, checkpoint procedure, pressure trigger and idempotent recovery plan. For memory
  pressure, checkpoint and stop that job to release its RSS; SIGSTOP/systemd freeze alone is not
  memory reclamation. For disk pressure, checkpoint/stop and park its closed files under the
  approved host prefix, authenticate complete readback, then retire the exact local copies.
  Restore and resume when pressure permits. Use the lifecycle in [r2-holding.md](r2-holding.md).
  Do not label a job resumable until its actual checkpoint/restore route has passed a bounded
  round-trip experiment. Keep unsupported healthy producers running while developing that route
  against isolated work. No arbitrary live-mmap eviction or unqualified process serialization.
- Maintain one disjoint next candidate in a dormant, no-trigger state whenever missing compatible
  work remains. Preflight its manifest, immutable package, cached input, isolated GCloud identity,
  controller configuration, hashes, and capability evidence while current lanes run. Preparation
  is not launch authority.
- When a lane completes cleanly or leaves the fleet, treat that terminal transition as an event,
  not a reason to wait for the next routine poll. Recompute fresh admission and backfill promptly up
  to the proven operating point. The 30-minute cadence limits routine sampling; it does not require
  an avoidable 30-minute idle slot after an authenticated completion event.
- Do not start a producer until its exact invocation can be guarded. If invocation IDs exist only
  after launch, start the dormant controller under observation, immediately bind and prove its
  reserve/VMA guard, and do not leave it unattended before the first real sandboxed guard fire.
  Before an input-capability probe, validate the private run root itself and each required child
  under the actual service user. Creating mode 0700 children can leave an automatically created
  parent group-writable; check ownership, traversal and owner-only modes before spending time
  hashing large immutable inputs.
- If current concurrency is below the proven operating point and every gate passes, launch the
  staged replacement. If it does not launch, record the exact binding limiter or missing evidence;
  “waiting for utilization” is not a blocker.
- Overlap independent full verification, plugin verification, authenticated R2 upload, and remote
  readback with replay. Keep their receipt gates independent, and account for their measured I/O,
  CPU, and memory pressure when admitting another replay lane.
  Before the real verifier launch, prepare every directory required by its sealed wrapper,
  including nested receipt directories, with the exact owner and private modes. Run the wrapper's
  non-executing preflight in the actual sandbox. Creating only the state root can pass dispatcher
  preparation and still fail before the first archive hash. Preserve that failed invocation;
  reconcile a qualified replacement into the queue without restarting a healthy verifier.
  A completed private assembly releases its producer claim even while its independent scan is
  being prepared. Record the real terminal event and the pending delivery action; count only an
  actually launched scanner as active. Admit that scan against the current producer census and
  current guards, allowing for a complete private archive copy when the verifier needs one. Keep
  scan/assembly RSS separate from the century's settled replay comparison.
- Prefer independently replayable and publishable singleton epochs. Keep as many disjoint,
  root-verifiable singletons parallel as fresh admission and the proven operating point allow, and
  promptly fill every safe lane. Reuse sealed snapshot inputs where possible, but do not trade away
  per-epoch completion, verification, upload, and sidecar latency merely to avoid setup work.
  Preserve already-healthy legacy multi-epoch replays rather than restarting them.

Use event-driven systemd dependencies or timers for completion, guard, verifier, and uploader work
instead of frequent polling. Routine coordinated observations remain at least 1,800 seconds apart.
A completed stage may hand off promptly using a separately bound phase-event receipt against the
latest accepted resource sample. Preserve that sample's original clock, bind the prior stage's
clean terminal proof and the new live command/invocation, and retain the complete fleet history.
The event clock is not a new resource observation or launch permission. Clear an event selector
when constructing the next normal-cycle plan, while retaining its evidence and owner history.

Validate native queue-census framing on the actual systemd version before using it as an admission
gate. On systemd255, `systemctl list-jobs --output=json` can still emit text. Use the reviewed typed
`Manager.ListJobs` D-Bus adapter where that occurs; validate its signature, return nesting, job and
unit identities, and preserve the existing queued-entry denials. Never treat a parse failure as an
empty queue or bypass the census to unblock admission.

## Prioritize time to verified sidecar

When delivery is slow, inspect the actual sealed reader and its bound progress evidence
before increasing concurrency: an ordered whole-object hash may already use parallel range
GETs. Keep healthy readback running while testing a small, bounded, authenticated GET-only
range against identical local bytes. Bind the object length/ETag and range, retain transport
timings privately, and keep probe results separate from whole-object verification receipts.
A fast range or address-family comparison does not prove sustained archive throughput or
authorize sidecar publication. Apply a transport change only to a newly qualified deployment;
do not restart a healthy upload merely to try it. Use existing progress records for the
comparison and keep routine resource observations on the single 30-minute cadence.

Dispatch available independent verification, upload and readback work promptly; do not start extra
replay at the expense of starving already-complete archives in the delivery queue. Among disjoint,
compatible candidates that pass fresh admission, compare expected time until the authenticated
R2 sidecar commit, not merely epoch number or replay slots per second. Include input staging,
restore, remaining replay, archive close/import, independent full/current-plugin checks, required
boundaries, upload, whole-object readback and delivery-queue contention. Prefer qualified retained
work or checkpoint continuations when that end-to-end path is shorter.

Record the ranked shortlist, estimate basis and uncertainty, resource fit, selected candidate, and
why alternatives wait in the fleet's next-action evidence. Use actual phase timings and ready-pair
completion cadence to revise the ranking at the existing coordinated observation, not through an
extra polling loop. Label scheduling uncertainty without changing the mandatory definite numeric
status-JSON estimates; a ranking is never a substitute for an admission or integrity gate.
Keep the lowest unsupported assigned epoch on an explicit active qualification/recovery path;
short-job scheduling must not silently skip it or indefinitely starve older admitted work. Preserve
healthy legacy cohorts and cross-host ownership, stay within the assigned publication range, and
keep the epoch-301 verification tail private.

Known failures are a priority repair backlog, not candidates to drop from consideration when a
shorter new singleton becomes available. Advance safe diagnosis or qualified recovery before
additional discretionary cold admissions. When a specific repair is blocked, keep its evidence,
next unblocking action and last substantive progress in the fleet's durable repair record while
independent work continues. Neither reclaiming failed scratch nor deleting stale dashboard status
closes the repair incident; reconcile it until qualified recovery reaches a verified ready pair.

## Delegate epoch-specific repairs

Assign an epoch-specific diagnosis or repair to a dedicated sub-agent. Group epochs only when
they share the same repair and artifacts; avoid duplicate agents changing the same incident.
The main agent continues the fleet loop, assesses the memory-selected lane target, stages and
admits independent work, maintains the authoritative repair backlog, and reports progress.
Repair delegation must not turn missing compatibility evidence into an idle-host policy.

Give each repair agent the exact failed invocation, immutable inputs and receipts, remaining
integrity gates, scope of authorized changes, and ownership of files or an isolated worktree.
The agent builds, tests, seals and preflights the repair, preserves terminal evidence, and reports
the concrete next action or blocker. Coordinate overlapping files and Git integration explicitly.
The main agent retains responsibility for failed-epoch tracking and stale status-file cleanup.

Repair agents consume the main agent's latest accepted observation and fleet receipts. They do
not create routine polling loops or competing schedules. The main agent performs user-requested
out-of-band observations and distributes the resulting evidence. Before a repair agent launches
a host job, it sends the exact sealed plan, resource envelope and service scope to the main agent
for coordination against the complete fleet. This is internal admission coordination, not another
user permission request; existing user authorization persists. The main agent records the new
owner and accounts for it before admitting more work. Preserve healthy jobs and every normal
capability, resource, checkpoint, verification and publication gate.

When agent slots are full, retain a prioritized repair queue with a named next action and keep
the fleet loop moving. Do not silently drop failed epochs or replace the campaign objective with
the easiest repair. Close an incident only on the usual verified ready-pair evidence.

## Scale beyond the proven point

Increase beyond the proven operating point by exactly one replay lane at a time; capacity at or
below the proven point should be filled concurrently as soon as each singleton passes admission.
Before an experimental increase, require a fresh clean
coordinated sample of the current fleet taken at least 1,800 seconds after the preceding routine
sample, current no-trip guard receipts, complete admission arithmetic, and a dormant candidate with
disjoint work. Keep hard cgroup ceilings, the century `.jet`-derived filesystem floor,
evidence-backed remaining-growth protection, and VMA stops unchanged.

After launch, capture exact controller and producer invocation IDs, install and manually prove the
invocation-bound guard immediately, and require its first real sandboxed timer fire to succeed.
The new count is not the proven operating point until a later clean coordinated sample covers the
entire expanded fleet for a stable window. Do not admit another experimental lane before that
sample. On a guard trip, pressure event, restart, identity mismatch, or reserve erosion, stop
scaling, preserve evidence, and follow the normal guarded recovery path.

## Decide from throughput, not appearance

At each coordinated sample, report both resource headroom and useful work:

- aggregate and per-lane transactions, account updates, or equivalent replay progress per second;
- physical scratch and VMA growth per unit of useful work;
- effective CPU, memory current/peak/events, major faults, pressure, and I/O;
- verification/upload backlog and ready-pair completion cadence;
- the current proven point, live count, staged candidate, and the exact limiter on another lane.

Compare settled incremental windows at equivalent work. A new lane is beneficial only when fleet
completion cadence improves without unacceptable per-lane collapse, pressure, reserve risk, or a
growing delivery backlog. If added concurrency reduces verified-and-uploaded throughput, return to
the last proven point through the guarded controller path; do not stop arbitrary unbound workers.
