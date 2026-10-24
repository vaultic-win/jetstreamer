# Epoch 227 upstream comparison canary

This diagnostic tests the original slot 98091122 failure with the upstream v1.6.25
runtime. It does not qualify a full epoch or authorize archive publication.

The immutable input is snapshot 98063464 with accounts hash
`4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR` and the independently
qualified native-input proof `da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b`.
The real canonical checkpoints remain 98063464 and 98495291. Slot 98091122 is
only a complete-slot transport boundary. The sealed worker rejects entries past
that target before mutation. The parent records completion and pauses itself;
the wrapper captures and resumes it without sending another interrupt.

## Resource proposal

| Resource | Proposed bound |
| --- | ---: |
| Entire private run root | 300,000,000,000 bytes |
| External control metadata | 16,777,216 bytes |
| Incremental disk claim | 300,016,777,216 bytes |
| MemoryMax | 225,000,000,000 bytes |
| MemoryHigh | 150,000,000,000 bytes |
| Swap | 0 bytes |
| CPU quota | 8 cores |
| Runtime | 21,600 seconds |
| Worker VMAs | 3,500,000 |
| Controlled target drainage | 120 seconds |

A provisional protected free-space floor of 2,350,000,000,000 bytes requires
2,650,016,777,216 bytes of initial available disk. Fresh admission must recompute
protected growth from every live owner and guard and preserve whichever existing
floor is larger; this provisional number cannot be lowered merely to fit. The
300GB scratch assumption is the century-200 replay envelope. Native-input-only
96GB evidence cannot replace it. Admission also requires 10% host memory reserve
plus the new cap and every protected owner's unconsumed hard growth, the validated
century RSS reservation, and the observed pressure limits. A source/test pass is
not evidence that the host currently fits this proposal.

## Prelaunch order and ownership

The main campaign agent alone owns resource observations, admission and launch.
The epoch repair agent prepares and seals source/artifacts but does not poll the
healthy fleet, install/start units, write R2 objects, or push main.

1. Keep all original failed-227 scratch, partial archive, immutable launch,
   journal and input history. Never reuse those paths.
2. Seal the actual canary resource plan and a separate no-worker capability plan.
   Their run roots must differ. The resource plan schema is
   `jetstreamer-private-epoch227-v1625-comparison-plan-v1`; its fields are the
   common bounded-resource runner Plan, not the separate resource proposal.
3. Prepare ubuntu-owned mode-0700 `scratch`, `output`, `receipts`, and `ledger`
   directories beneath each new private run root. They must be empty before
   invoking that root's runner. Prepare distinct root-owned mode-0700 admission,
   capture, guard, and terminal-proof directories; ordinary receipts must never
   be written into the archive namespace.
4. Once root grants a capability job, run only the sealed runner's
   `--storage-capability` path using its separate root and immutable plan. The
   capability unit is a persistent readonly root0444 `Type=oneshot` unit ending
   `-capability-v1.service`, ubuntu/ubuntu, no restart, no swap, eight CPU quota,
   512 tasks, the same 225GB/150GB caps, 10-minute TimeoutStartSec, strict system
   and readonly home, exact writable run root, no capabilities and no-new-privileges.
   `PrivateNetwork=no`, `RemainAfterExit=no`. This proves the real Node planning
   barrier before worker creation; it is not replay or a resource observation.
5. Capture the capability only after actual successful terminal state, preserving
   the original ubuntu0400 capability receipt and plan binding. Admission checks
   the exact installed unit command and sandbox, real ExecMainPID, unique PID1
   success for the capsule invocation ID, and before/after identity stability.
6. Root obtains one fresh coordinated observer/fleet sample using the normal
   30-minute cadence (or an explicitly user-requested status exception). Use
   `admit-canary227-v1625 SPEC --spec-sha256 HASH --self-sha256 HASH`. The spec
   binds observer, fleet, actual `canary_plan`, `input_capability`, separate
   `resource_proposal`, every protected guard and root-private output. Its schema
   is `jetstreamer-private-epoch227-v1625-canary-admission-spec-v1`, mode
   `bounded-canary`. No admission helper starts work.
7. Only root may launch the accepted actual unit. It is `Type=exec` with six-hour
   RuntimeMaxSec and exact immutable runner/plan/hash argv, no restart and only
   its own writable run root. Immediately install the invocation-bound sealed
   guard, prove its first actual sandboxed success and PID1 completion, then arm
   the normal protective timer.
8. Use `capture-canary227-v1625` with the exact root0444 installed unit,
   fresh_resource_admission, input_capability, guard, guard_plan, resource_plan,
   resource_proposal and fixed capture output. The real PID/IID, command, sandbox,
   guard, timer, completed history and unchanged older owners must all validate.
9. Add exactly one captured DiagnosticClaim and tracked unit through the
   canary227 metadata event, preserving the accepted observer clock, every older
   pipeline/diagnostic owner and all gates. Epoch227 remains failed-needs-repair.

The actual unit is
`horizon-qualify-227-v1625-bounded-resource-d01adb19-v1.service`; its private root is
`/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-v1`.
Its immutable `resource_plan` must be under a
`/var/lib/jetstreamer/horizon-227-v1625-canary-resource-*` package.

## Dashboard and terminal lifecycle

Root must expose active preparation/canary work on the dashboard: `verification`
before entry execution, `replay` once actual execution is observed. Use the
single coordinated 30-minute sample, exact current invocation binding, actual
partial `.jet` length (zero before creation), actual invocation elapsed millis,
and a definite best estimate to the eventual canonical sidecar. A six-hour
canary bound is not an upload ETA. Existing failed-227 countdowns must not be
silently reused for this new owner.

When the canary stops, preserve the target-stop intent, runner result, guard
history, exact terminal unit and PID1 journal, independently check parent Bank
`BLAJ7oikrxpvcYMZnLjr9iApJGeLuhLjzyQ8Yw82WH73` and the original failing vote
transaction's result. Target completion alone is transport evidence. Do not
promote runtime, full-root, canonical-prefix, plugin or publication gates from
it. The checkpoint at 98495291 and full tail still require separate qualification.

A terminal canary with no genuine active downstream owner must have its exact
status conditionally removed using authenticated inactive cleanup and durable
terminal/ownership evidence; do not invent a canonical sidecar. An actual repair
handoff keeps a supported phase only with its current accountable owner and
updated definite ETA. Root owns the terminal fleet event, metadata refresh or
inactive cleanup. No autonomous second polling loop is authorized.

## Prepared artifacts and command interfaces

The actual plan is sealed at
`/var/lib/jetstreamer/horizon-227-v1625-canary-resource-v1/resource-plan.json`
(SHA256 `194d3c5d4827c9f93c392b0b30bec16cdef103ae94df78e64c6f6f80ebec50e3`).
The separate capability plan is
`/var/lib/jetstreamer/horizon-227-v1625-canary-capability-plan-v1/capability-plan.json`
(SHA256 `77527b684115ba8744b310056d117511e9c87b593c5d28e50cfc04fd9b3f0922`).
The resource proposal is
`/var/lib/jetstreamer/horizon-227-v1625-canary-proposal-v1/resource-proposal.json`
(SHA256 `db796da348c7e91bd1321ff2693bc420517ac60abf0483df3e36a7d1004795f6`).
Readonly unit templates are separately sealed in
`/var/lib/jetstreamer/horizon-227-v1625-canary-unit-templates-v1`; they have not
been installed or started as part of preparation.

The sealed R2 helper supplies:

- `admit-canary227-v1625 SPEC --spec-sha256 SHA --self-sha256 SHA`
- `capture-canary227-v1625 SPEC --spec-sha256 SHA --self-sha256 SHA`
- `status-publish-canary227 PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]`
- `capture-canary227-v1625-terminal SPEC --spec-sha256 SHA --self-sha256 SHA`

Status plans use schema `jetstreamer-canary227-status-plan-v1`, mode
`launch-event` or `observation`, and bind observer, fleet, launch, receipt_directory,
estimate_receipt, initialization_allowance_millis, fallback_slots_per_second,
downstream_allowance_millis, estimate_basis and estimate_evidence. Supply positive
best guesses for every stage: archive_close, boundary, canary_qualification,
full_epoch_replay, full_verification, plugin_verification, readback,
runtime_qualification, sidecar_commit and upload. Bind the measured old failure
and current qualified inputs as evidence. These planning guesses must include
remaining full-epoch work after the bounded canary; no stage disappears merely
because target98091122 completes. Run check-only before the first mutation.

Terminal specs use schema
`jetstreamer-private-epoch227-v1625-canary-terminal-spec-v1`, binding launch,
optional result and the fixed output
`/var/lib/jetstreamer/horizon-227-v1625-canary-terminal-v1/proof.json`.
The actual wrapper result is `receipts/resource.json` or `receipts/failure.json`.
If an OOM or forced termination prevented either result, omit result only when
both files are positively absent; the helper preserves that absence and the
actual latest PID/terminal invocation/PID1 completion instead of inventing a
result. The terminal proof always denies semantic and publication promotion,
even when the wrapper reports complete-target success, and grants zero automatic
resource release credit. New capacity needs the next accepted complete sample.
Its metadata event preserves all claim history and the failed repair gate; the
existing authenticated inactive-status cleanup then recognizes only that exact
canary owner, rechecks its latest actual terminal PID and rejects replacements.
