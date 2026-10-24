# Epoch 141 active repair status

This source adds a narrow status route for a **real, persistent repair queue**.
It does not deploy a service, start replay, admit workloads, verify a checkpoint,
mutate a canonical archive or release any pending growth claim. Its wire phase is
`verification` and it preserves the open `failed-needs-repair` fleet entry.

The old producer `horizon-qualify-141-original-entry-capped-root-20261023-v1.service`
(invocation `e639f007d482464f8a251455659d2ede`) is terminal. The actual native capped141
terminal capture and guard stop-completion are mandatory. Neither chat text nor a
handwritten open-repair entry establishes terminal or resumability evidence.

No durable Bank beyond bootstrap slot **60911751** is proven. Cold recovery must
redo **417014** slots to root **61328765**, then **15234** slots to terminal
**61343999**. Last logged slot60942360 and retained partial bytes receive no
resume credit. The queue streams a stable raw fingerprint of the retained partial,
recording byte count and elapsed hashing time; this is explicitly neither footer,
prefix validity, archive verification nor a serialized Bank proof. It never writes
a canonical checksum or verifier receipt.

## Owner and bootstrap

The exact sealed native owner is
`/usr/local/lib/jetstreamer/horizon-epoch141-repair-status-tools-20261024-v1/jetstreamer-r2`
and its exact unit is `horizon-repair-141-floor-20261024-v1.service`.
Use `Type=simple` for this owner. Its clock validator accepts the trusted PID1
`Started` event; `Type=exec` emits both `Starting` and `Started`, which this
profile rejects as an ambiguous start. Preserve a rejected attempt's native
journal and prove launch/state receipts absent before explicitly reconciling it.
Use `repair-owner-141 PLAN --plan-sha256 SHA --self-sha256 SHA` only after
normal sealing and independent parent admission. The queue plan schema is
`jetstreamer-epoch141-repair-queue-plan-v2`, with fields `schema`, `epoch:141`,
`program`, `terminal`, `policy`, `bootstrap_observer`, `bootstrap_fleet`,
`bootstrap_completion`, `task_slots`, and `output_directory`.
Every evidence binding has `path` and lowercase `sha256` fields. Plans and
programs are immutable root-owned regular files. Output is the precreated root-only
`/var/lib/jetstreamer/horizon-epoch141-active-repair-20261024-v1` directory, with a
root-only `task-admissions` subdirectory. Existing launch/state prohibits retry.

Launch requires one accepted coordinated v2 observer/fleet/completion, no more
than1800s old, authenticated no-anomaly inventory and all sample/digest links.
Actual OS free space must preserve228833779142B baseline, the existing256MiB
bootstrap claim and a separate64MiB queue claim. Existing protected resident and
reservation ceilings cannot be lowered. Total and currently available memory must
fit the separate2GiB queue bound. Independently launch with CPUQuota100%,
MemoryMax2GiB, swap0, bounded tasks, no automatic restarts, a private network,
read-only failed scratch and only the precise metadata directory writable.
There is no replay, export or input-restore growth inside this queue budget.
All queue state is bounded to64MiB on the OS filesystem; reaching the cap fails
closed and preserves the repair entry.

The queue owns actual task state across subprocess gaps. Its exact slots are:
`export-build-and-tests`, `export-stdio-qualification`, `bounded-parent-tests`,
`capacity-and-input-admission`. Parent must actually coordinate the engineering
work; an idle decorative service is not a repair strategy. Tasks must be separately
admitted and launched through each reviewed task's exact sandbox and resource
budget. The queue does not launch or admit them.

`repair-task-capture-141 PLAN --plan-sha256 SHA --self-sha256 SHA` captures an
already-running task from PID1 and `/proc`, rechecks owner and task identity, then
writes its immutable intake. Capture plan schema
`jetstreamer-epoch141-repair-task-capture-plan-v2` requires `epoch:141`, `task_id`,
`owner_capture`, `queue_plan`, `work_plan`, `program`, `unit`, `expected_exec_start`,
and exact `argv`. The task unit must be
`horizon-repair-141-task-TASK_ID-20261024-v1.service`. Its root-owned immutable native
ELF must actually execute the epoch141-scoped immutable work plan as an exact argv
element. A sleeping or metadata-only r2 process cannot stand in for the task.
Intake is **evidence only** and explicitly grants no resource, replay or publication
admission. Success means actual terminal exit0, never export/restore qualification.
Failure, restart or replacement writes persistent failure state; it never silently
retries, erases retained bytes or closes the open epoch repair.

## Current numeric planning assessment

Use schema `jetstreamer-epoch141-recovery-planning-v2`. It binds the historical
v2 `historical_rate_observer`, the sealed `downstream_policy`, exact bootstrap/root/
terminal slots, explicit false checkpoint/restore/launch/publication/growth flags,
nonempty `estimate_uncertainty`, `planning_assumptions_reviewed:true`, and
`engineering_and_capacity_parallel`. `allowance_millis` has positive integers for
`engineering_and_qualification`, `capacity_and_admission`,
`bootstrap_restore_and_initialization`, `checkpoint_close_export_restore`.
The existing downstream policy supplies the complete36h delivery allowance.
A first planning example uses24h engineering,48h capacity in explicitly reviewed
parallel,6h bootstrap and12h checkpoint close/export/restore. All are planning
assumptions, not measured bounds. Export/restore is not yet mainnet qualified;
build, API and segment/parent qualification remain real engineering obligations.
The initial254-slot candidate does not establish continuation or restore capability.

At historical1694 slots /1749194714 microseconds (0.9684456433 slots/s), this
example gives root replay430601349ms, suffix15730362ms, and total813531711ms
(**9d9h58m51.711s**). No partial-bank progress is subtracted. This numeric projection
must be re-reviewed as qualification, capacity or throughput changes; it is not a
promised landing deadline.

## Publication and refresh

`status-publish-repair141 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]`
requires schema `jetstreamer-epoch141-repair-status-plan-v2`, `epoch:141`, bindings
`observer`, `fleet`, `queue_plan`, `owner_capture`, `policy`, optional
`previous_publication`, `estimate_receipt`, `receipt_directory`,
`exclusive_local_epoch_ownership:true`, `authenticated_other_host_handoffs:[]`.
The current assessment additionally binds `estimate_observer` to this exact observer
and `estimate_owner_invocation_id` to the actual queue. Supply a newly reviewed
assessment for each coordinated sample; reusing the initial allowance as a fresh
countdown is disallowed. The queue's initial policy remains historical baseline,
while each publisher plan binds its current assessment without restarting the owner.

Refresh once within the normal coordinated30-minute observation, with no extra
resource sampling loop. Require fresh same-sample fleet, the exact live repair owner,
no alternate replay/downstream handoff, and an open failed-needs-repair entry.
Elapsed time uses the new queue's actual PID1 manager-start event, never the old
stopped replay or latest poll. Report zero current jet bytes during repair; retained
failed-attempt size remains only in private estimate evidence.

Before conditional PUT, authenticate the current status's exact prior receipt,
payload and ETag, accepting only the old capped141 or this exact current repair
owner. Pin that ETag or absence through the shared publication preflight. A changed
owner, stale sample, already-ready pair or race fails closed. Authenticated byte-for-
byte readback and a durable normal pipeline status receipt remain mandatory.
Only `epoch-141.epoch-status.json` may change; this route has no deletion command.
The source-only implementation must pass package tests and Clippy before sealing,
then actual launch/observation/fleet checks before any remote mutation.

## Coordinated cadence adoption

The reviewed routine coordinator adds
`--prepare-next-repair141 HANDOFF --handoff-sha256 SHA` using its normal
prepare-next argument shape. The immutable handoff schema is
`jetstreamer-epoch141-repair-routine-handoff-v2`, with `publisher` bound to the
same newly sealed native r2 program, `active_repair:{queue_plan,owner_capture,
planning_policy,invocation_id}`, and explicit false `replay_launch_authorized`,
`publication_authorized`, `r2_mutations`. This requires an actual queue capture;
there are no future or fabricated IIDs. It preserves the existing historical
original141 profile and diagnostic input, leaves ordinary replay publisher pins
unchanged and disables the old141 replay-status hook by selecting active repair.
The coordinator must be sealed from this combined source, not an older helper.

The new successor uses a distinct repair141 namespace, preserves the current
observer configuration and single scheduled sample, injects only the real141
repair pipeline claim and tracked unit, and keeps its failed-needs-repair gate.
Both provisional and final fleet reads use the new repair-capable reader, including
when the191 delivery profile is also present. No healthy producer is restarted.
Parent must replace the previously prepared coordinator/timer through the normal
single-successor lifecycle; preparing a second package alone does not remove the
old scheduled owner. The first sample must be at or after actual queue start.

Each accepted sample fingerprints the current queue state, checks the unchanged
unqualified checkpoint/growth facts, and recalculates a definite full cold recovery
projection from the measured rate and reviewed remaining stage allowances. A task
returning exit0 does not count as export/restore, checkpoint or resource admission
qualification. Until a qualified milestone exists, retain its full positive
allowance and explain that lack of credit in private assessment evidence. This can
move the landing time later when progress remains unqualified; never silently
count down an old root ETA. Revise the reviewed planning policy for measured
engineering overruns, new throughput or qualified milestone evidence, and hand off
to a supported next-phase publisher when real recovery/replay begins.
Publication failure records a same-sample incident under the actual repair IID,
keeps the repair open and does not suppress other epochs, final fleet or the one
successor cadence. Completion validates the authenticated verification-phase
receipt and exact owner. No extra resource observer is introduced.
