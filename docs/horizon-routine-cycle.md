# Bounded routine metadata cycle

`jetstreamer-horizon-routine-cycle` consumes one already-completed, pinned v2
routine observation. It does not sample resources, launch or stop replay, admit
capacity, upload archives/sidecars, delete objects, or schedule another cycle.
The operator remains responsible for qualification, repair, stage handoffs,
admission, completion events and stale-status cleanup.

Its root-owned hash-bound plan pins the scheduled observer configuration,
previous observation, ETA model, estimate receipt, fleet plan/receipt, exact
sealer/estimator/R2 executables, assigned epoch census, endpoint digest and private
output paths. `--check-only` validates those bindings without accessing R2,
sampling a producer or creating cycle outputs. The executable also authenticates
its own separately supplied digest through `/proc/self/exe`.

At execution it requires the exact next 1,800-second routine sample, unchanged
ordinary invocation identities and epoch terminals, and no newer campaign fleet.
It preserves all model formulae, gates, diagnostics and completed pipeline
history. Added repair evidence is append-only. A changed epoch boundary, producer
handoff, user-requested observation, new admission or newer fleet requires a
reviewed replacement plan; it never invents an ETA or relabels a phase.

One narrowly pinned narrative correction is permitted: when the exact retained
epoch225 reserve-stop incident (`fc51f75a…`) is supplied as added gate evidence,
the exact old next-action digest (`31b7234d…`) in `failed-needs-repair` is replaced
with the evidence-backed instruction that the parent already reclaimed material
scratch and no deletion tool is needed. The incident must deny deletion, replay
and publication, and bind the original producer plus8192B scaffolding. Only that
text changes; state, evidence, tracked units, diagnostics, admission and integrity
gates remain untouched. A newer action or state is never overwritten. Immutable
prior fleets remain history. Check-only validates the same correction evidence
in memory; it does not write a new fleet or take another resource observation.

The helper claims a unique private cycle directory, fsyncs an intent, authors
and seals the updated model and fleet plan through the Rust deployment sealer,
delegates ETA calculation, publishes every exact status through the existing
authenticated Rust publisher, then performs read-only full-range reconciliation.
It checks the resulting receipts before fsyncing a completion record. The only
remote writes are the explicitly modeled `epoch-N.epoch-status.json` updates.
No arbitrary child subcommand or shell fragment is accepted by the plan.

Run a first deployment for **one cycle only**, in a non-restarting root systemd
oneshot with a ten-minute execution timeout, control-group kill semantics,
`TasksMax=512`, a small CPU quota/memory ceiling, the existing credential file,
and only `CAP_DAC_OVERRIDE` for private-path traversal. Keep archives and sealed
tools read-only; writable paths are the exact private cycle, status, estimate and
fleet-receipt directories. Schedule after the independently armed observer has
had time to finish. Neither this rollout nor a successful metadata cycle
establishes replay/resource/publication qualification.

Before an out-of-band user status observation or a stage/admission transition,
cancel any pending metadata-cycle timer/service alongside the obsolete observer
schedule, and derive a new predecessor chain. The helper additionally fences
against a newer full campaign ledger, but that fence is not permission to race
two operators or to leave an obsolete resource timer armed.

For the exact existing dev-samjohnson epoch157 deployment, an optional
`epoch157_terminal_handoff` manifest binding allows the already-sealed parent to
advance from its v1.5.6 terminal68,140,176 to its v1.5.8 terminal68,255,999.
This is an ETA-model transition only, not runtime qualification, replay launch,
restart or publication authority. The exact immutable preflight report path and
SHA-256 are allowlisted; no other epoch, runtime or deployment is accepted.
The original predecessor model and estimate bindings remain intact. The derived
model moves the115,823 queued slots into the successor terminal, leaving zero
additional slots, the same invocation identities, authoritative producer-start
clock and43,200-second downstream allowance. No remaining replay is discarded.
Only a clean global-slot rate window and one stable worker across the physical
scans can consume the transition. A window crossing the known boundary includes
handoff latency; transaction/update counter resets do not change its slot rate.
The accumulated slot delta must exactly match the global first/last difference,
and the rate must reproduce that delta divided by elapsed time. Slot resets,
worker races, changed owners and unknown terminals fail closed without status
publication or an extra resource poll. The successor helper retains a pending
binding and drops it only after an authenticated completed cycle has consumed it.
The estimator and R2 writer keep their independent checks. Deploying this source
still requires a new seal, exact-package checks and a separately armed cycle;
existing running producers and already-armed cycles are not modified.
The offline `--prepare-next-terminal157` mode adds this exact binding to the
next plan only after checking the genuine completed predecessor and immutable
manifest; it does not arm timers or deploy anything. Later successors use the
ordinary `--prepare-next` mode. Use the new qualified executable for both the
handoff-enabled cycle and its successor preparation; older strict readers reject
the new optional field instead of silently ignoring it.

A failed preflight writes nothing. A failure after the intent writes a private
failure record and may leave some statuses freshly published; preserve every
receipt and inspect the exact stage. There is no automatic retry or interval
shortening. Recover only through the existing same-payload receipt recovery and
normal reconciliation paths, without another resource poll, blind overwrite,
archive deletion or healthy replay restart. Do not rerun an occupied cycle
directory. The agent must inspect both successful fleet transitions and failed
units; a completion record is not proof that an epoch became ready.
