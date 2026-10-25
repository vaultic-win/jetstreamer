# Capped admission: audit and conservative bracket review

The real 5746ac2a admission at 02:18 UTC refused its combined late-envelope gate.
There was no positive receipt or producer start. The seven inputs were not saved,
so no source inspection can establish which term actually failed. The three bound
completed protective receipts stayed unchanged in the subsequent metadata-only
inspection. Normal live cgroup cache release is a plausible cause: remaining hard
memory growth is `hard cap - current cgroup charge`, so that obligation increases
when current charge shrinks. That fact is not proof of the actual failing term.

This source change preserves the original seven admission predicates. A failed
late gate now writes a root-owned 0400, bounded, no-clobber, fsynced diagnostic
alongside the uncreated admission output. It records every boolean and its numeric
operands, both exact raw censuses and cap sets, both guard/growth/memory evidence
and memory policies, and all immutable input/self bindings. It makes no new resource
observation and never asserts admission, archive completion, replay or publication.
The diagnostic additionally previews the conservative arithmetic below. Preview
success does not change admission policy or authorize a retry.

## Proposed replacement of the monotonicity heuristic

Let G0/G1 be before/after protected disk growth, A0/A1 before/after remaining hard
memory growth, and Fd/Fm the accepted conservative disk/memory availability.
Let D0 and M0 be the already checked complete before obligations; let M1 be the
complete after memory obligation. All arithmetic must stay checked.

1. Require exact before/after raw owner censuses and exact hard cap sets. Retain
   all current-owner, immutable guard, source/native223, full-roster, source
   identity, sampled-data, freshness and transaction-duration checks. Do not
   normalize command displays or suppress unknown owners.
2. Compute G = max(G0,G1), then call the existing protected_floor with the same
   century floor and authenticated completed guard bindings. Call disk_requirement
   on that result. This must still fit the plan's DECLARED protected floor; a
   larger computed obligation does not authorize changing the plan or the 2 TB
   floor. Set D = max(D0, this recomputed complete disk requirement).
3. Compute A = max(A0,A1), then call the existing memory_requirement with A and
   the fully validated after evidence. It must keep the native223 480 GiB floor,
   the baseline host fraction, complete candidate MemoryMax plus guard reserve,
   every protected remaining hard-memory obligation and canary top-up accounting.
   Set M = max(M0,M1,this recomputed COMPLETE memory requirement). Taking the max
   of complete requirements matters: choosing only max(A0,A1) and subtracting a
   different bracket's already-accounted floor can lose an obligation.
4. Require min(Fd, actual_disk_before, actual_disk_after) >= D and
   min(Fm, actual_memory_before, actual_memory_after) >= M. Preserve the existing
   final post-mirror availability reads and require those further minima to fit D
   and M. Including the accepted observation AGAIN is essential when M exceeds
   M0: the existing initial check proved only that the sample covered M0.
5. Bind both raw brackets, their recomputed complete policies and conservative
   maxima/minima into the positive admission receipt. Re-run the original final
   immutable/source/freshness gates before publishing its no-clobber receipt.

This protects at least every before AND after obligation while spending at most
any accepted/before/after availability. It permits increased remaining growth only
when the full recomputed safety envelope fits. An owner/cap change, missing guard,
under-reserved declared disk floor, native223 floor violation, arithmetic overflow,
insufficient accepted or current capacity, or stale source still refuses admission.
There is no claim that two samples bound all future resource movement: unchanged
hard caps, complete candidate reservation and persistent guards remain mandatory.

The isolated source exposes two pure helpers for reuse by the separate closed
233 adapter: capped204205_admission::bracketed_requirements and bracketed_fit.
The first maxes complete recomputed obligations; the second requires exact census
and caps plus minimum of accepted/before/after availability. Neither computes or
replaces profile-specific floors. maintenance_capacity.rs is NOT edited here.
Tests cover cache shrink, ordinary disk growth, changed floor components, every
availability bracket, actual insufficiency and owner/cap changes. The live capped
admission policy remains unchanged until this equivalence is reviewed and the
recomputed maxima are explicitly wired into its receipt and final post-mirror gate.

## Smallest next safe path and provenance

Review the bracket equivalence, wire it into capped admission (and only the closed
233 mode in the separately owned maintenance module), then qualify the frozen
combined R2 source with meaningful focused/default/all-feature tests and strict
Clippy. No Cargo has run for this change. Freeze new production R2 bytes, capture
actual compiler/source/extern/native inputs before target reuse, independently
review and seal them. Pin the exact NEW R2 SHA in the admission self binding and
future ETA model's publisher_sha256; do not reuse a model pinned to 5746ac2a.

The qualified bounded8 node/control/probe and their durable actual disposable
capability remain unchanged; this R2-only arithmetic/audit repair does not require
rebuilding the historical worker, replaying the probe or promoting the observer.
The 02:09 source capture expired at 02:24 and must remain preserved. Prepare a
separate uniquely named fresh capture/plan/proposal/receipt/attempt after all
non-expiring work is ready, retaining the original 1792749926759 epoch clock and
failed v1/v2/v3 evidence. Use a fresh accepted fleet and genuine current guard
bindings; then one admitted, independently guarded private start, immediate REAL
live launch capture, same-sample metadata fleet event and authenticated status
publication. No retrospective receipt, raw S3 mutation or canonical publication
is authorized by this diagnosis.
