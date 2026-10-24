# Same-cycle bounded diagnostic admission

The ordinary fleet reconciler still requires its observer timestamp to advance.
Do not take another replay/resource sample merely because a fresh admission in
the current control cycle has added a diagnostic after its initial ledger.

For exactly one newly admitted supported private diagnostic, a new sealed fleet
plan may instead include:

```json
{
  "admission_transition_guard": {
    "path": "/absolute/root-private/sample-EXACT_GUARD_INVOCATION.json",
    "sha256": "EXACT_GUARD_RECEIPT_SHA256"
  }
}
```

This is reporting-only evidence, never launch, resource admission, publication,
or extra polling authority. The plan must bind the exact modern predecessor
ledger and the identical observer path/hash/timestamp. Preserve every previous
diagnostic unit, epoch, invocation and launch binding, including terminal ones;
add exactly one distinct supported claim. Preserve all previously tracked unit
names. The ordinary invocation/source validation and before/after complete unit
census still run. Authenticated R2 inventory/status reads remain mutation-free.

The added claim needs its actual first successful sandboxed Rust guard receipt:
exact producer invocation/cgroup, active zero-restart non-restarting service,
control-group killing, no delegation, no trip or observation error, one readable
worker below the VMA stop, and free space above its sealed floor. Rehash the
guard's separately bound plan and require its unit/invocation/private root and
safety limits to agree. The accepted guard must postdate the predecessor ledger
and observer and remain within the same 30-minute freshness window.

The output records `admission_transition_guard`. A second same-sample transition
cannot chain from that output: it must wait for the next coordinated observation.
The exception cannot remove or replace history, add arbitrary ordinary replay,
relax compatibility, change observer evidence, fabricate a workerless admission,
or accept stale/foreign/error-bearing guard evidence.

Supported contracts are explicitly enumerated in `validate_same_sample_admission`:
the exact epoch-140 native restore-only probe, epoch-203 bounded/root-prefix/shrink-budget
experiments, epoch-224 bounded measurement, and epoch-225 bounded/natural-root measurements.
This is not a generic diagnostic admission or a runtime-range expansion. Each contract keeps
its own pinned guard digest, private namespace, source/package bindings and safety profile.
In particular, epoch 140 uses the host's unchanged `eca42993…` standalone guard, fixes the
slot-60,911,751 snapshot and v1.4.25 worker, and forbids replay entries, prefix qualification,
suffix execution and canonical publication. Its normal zero-worker bootstrap/drainage allowance
does not waive the real one-worker first-fire requirement for this admission event.

On the next normal 30-minute cycle, **omit** `admission_transition_guard` from the
new plan, bind the newer observer and the latest post-admission ledger as its
predecessor, and use ordinary monotonic reconciliation. Do not carry the event
option into normal polling or start a second monitoring loop. User-requested
out-of-band observations keep their existing explicit observer-reason policy.
