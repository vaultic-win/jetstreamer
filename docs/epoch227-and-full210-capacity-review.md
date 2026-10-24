# Epoch 227 and full 210 capacity review

This is a source-only review of preserved evidence. It authorizes no guard change,
new observation, admission, service action, resource release or R2 mutation.

## Evidence and immediate conclusions

Accepted observation 351 is sampled at 2026-10-24 07:40 UTC, SHA256
`832cb485b43557183a5b62d052dd720f02e9530213cff556353c044cefa2d627`.
Accepted fleet is
`/var/lib/jetstreamer/horizon-campaign-fleet/20261024T074000Z-v351-v2/fleet-ledger.json`,
SHA256 `dcbd88f706a78d886dc3274170ff59e44d9fe841201cc016f21582de083d55e5`.
Its conservative available disk is exactly 2,368,757,645,312 bytes. This review
never treats that historical value as current free space.

The older exact guard basis is
`.codex/tmp-readiness/foundation-prefix213-resource-basis348-v1.json`, SHA256
`7cf87971ad50bb94a387f6422c5b621ab3b6471370b060fcd29182356502212d`.
Its guard receipts are valid historical inputs for observation 348, not fresh
351 guards. In particular, the 209 receipt predates 351 by 4,898 seconds and the
223 receipt by 4,838 seconds. Existing admission requires a guard no earlier
than its coordinated observation and no more than 1,800 seconds old.

The 2.35 TB canary floor is a provisional plan value, not a required constant in
`canary227_admission`. The code already accepts a smaller independently computed
floor when it still covers all existing remaining growth, the century floor,
and every still-effective guard floor. Recomputing and sealing a new plan,
proposal and exact command binding needs no runtime/worker change. It does not
permit using 348 guards to approve 351 or omitting a producer.

An external guard handoff cannot currently remove the active 223 floor:
`epoch223_native20_prefix_gate.rs` has a compiled 2,000,000,000,000-byte runtime
floor. The immutable d18fd429 wrapper calls that check every 15 seconds and stops
its child on failure. It has no runtime policy reload. Replacing only its
external guard would leave that stopping condition intact. No restart or hot
patch of that healthy producer is proposed.

## Canonical disk arithmetic

Use the same equations in the fresh Rust admission:

- C = ceiling of twice the sum of verified ready archive lengths divided by their
  count, using the current century inventory.
- R_i = complete remaining growth of each actual old owner, with only its
  authenticated, scope-matching allocation credit.
- P = max(C + sum(R_i), every effective external and in-process floor).
- Required initial free = P + the new candidate's entire incremental claim.

The 14 ready archive lengths in 351 sum to 1,717,682,084,320 bytes. Therefore
C = ceil(3,435,364,168,640 / 14) = 245,383,154,903 bytes.

The following table uses the recorded 351 allocations. Values involving fresh
209/223 guard allocation remain conditional, not fresh admission evidence.

| Existing owner | Recorded scope and allocation | Remaining growth expression, bytes |
| --- | --- | --- |
| 225–226 | Scratch 214,485,000,192; original baseline 179,696,549,888 | 687,194,767,360 - 34,788,450,304 = 652,406,317,056 |
| 204 | Scratch 152,473,677,824 | 319,325,014,016 - O204 |
| 205 | Scratch 163,699,986,432 | 308,098,705,408 - O205 |
| 209 | Whole root 129,906,003,968 | 341,892,687,872 + D209 |
| 223 | Whole root 107,226,472,448 | 364,572,219,392 + D223 |

O204/O205 are actual physical allocations of the two exact private prefix output
files, not logical lengths, scratch sizes or old estimates. Each source profile
currently requires its credited output allocation to be at most 128 GiB.
Observation 351 does not record those output allocations; they must be obtained
through the existing identity-stable admission checks or the next coordinated
observation. Older admission 345 recorded 60,166,582,272 and 65,306,378,240 bytes,
but those are not substituted for fresh output evidence.

D209 and D223 are nonnegative deficits between the 351 whole-root sample and
min(sample, fresh same-invocation whole-root guard allocation). They are zero
only if a qualifying current guard supports that much credit. A reclaim must
not become invented allocation credit. The old 348 guards cannot prove either
D is zero at 351.

Writing O = O204 + O205 and D = D209 + D223 gives:

    Sum of old remaining growth = 1,986,294,943,744 - O + D
    C + old remaining growth   = 2,231,678,098,647 - O + D
    P                         = max(that value, 2,000,000,000,000)

The 225 formula preserves its original 640 GiB *remaining* claim and baseline.
It cannot be replaced by 300 GB minus current scratch. That legacy claim also
reserves uncredited output/cohort work; a century assumption alone does not
qualify a smaller budget for this running invocation.

| Candidate | Incremental claim | Consequence using only preserved 351 free |
| --- | ---: | --- |
| Repaired 227 canary | 300,016,777,216 | Fits only if fresh O - D is at least 162,937,230,551 bytes and all other gates pass |
| Full 210 | 471,832,246,272 | Cannot fit while any effective floor is 2 TB: short by at least 103,074,600,960 bytes |
| Both new claims | 771,849,023,488 | With a 2 TB effective floor, short by at least 403,091,378,176 bytes |

The canary's provisional floor would require 2,650,016,777,216 bytes, exceeding
351 free by 281,259,131,904 bytes. Its best possible requirement with a 2 TB floor
is 2,300,016,777,216 bytes, leaving at most 68,740,868,096 bytes of historical
headroom. Actual P could be larger; the missing fresh credits decide that.

Even a hypothetical removal of both 2 TB external floors would not prove full
210 fits from these values. The two output credits are capped at a combined
274,877,906,944 bytes, giving C + remaining growth no smaller than
1,956,800,191,703 bytes before any guard-credit deficit. Adding full 210 still
exceeds 351 free by at least 59,874,792,663 bytes. A guard rebase alone is therefore
not the entire capacity solution. No projected retirement or future completion
is added to free space here.

The recorded century RSS ceiling is 251,041,591,296 bytes, so the 225 GB candidate
cap is below that recorded ceiling. This is not a fresh memory admission: actual
hard cgroup growth, host reserve, pressure and complete identity brackets still
need the ordinary fresh Rust checks.

## Effective floors and handoff constraints

The 348 receipts report these external floors:

| Owner | Floor, bytes |
| --- | ---: |
| 225–226 | 317,008,659,347 |
| 205 | 1,210,361,856,915 |
| 204 | 1,372,922,903,443 |
| 209 | 2,000,000,000,000 |
| 223 | 2,000,000,000,000 |

The 223 in-process floor is independently 2 TB. It remains binding even if its
external reader accepts a different plan. The new canary wrapper also holds
its admitted floor in its immutable startup plan; removing arbitrary padding
before launch is preferable to attempting to change it later.

A future external handoff for a producer that supports it must preserve the
original launch and old guard proof and introduce a separately authenticated
transition, not rewrite either. Bind exact unit/IID/PID, unchanged zero-restart
producer command, worker and whole-root/VMA/memory bounds; old/new guard
binary/plan hashes; the complete fresh observer/fleet/guard basis; all old
remaining growth and effective internal floors; and the new numerical floor.
Prove bridge coverage before retiring the old protective schedule, the new
sandbox's actual PID1 success and active timer, and a final unchanged producer
census. Readers must validate the new lineage before accepting its receipt.
No phase, runtime, archive, checkpoint or publication authority changes.

A general certificate must explicitly reject a proposed floor below an active
immutable in-process floor. Existing 223 cannot accept a live reload, so there
is no useful all-owner sub-2-TB handoff under the no-restart constraint today.
After natural terminal or for a future separately qualified reload-capable
wrapper, recompute the complete claims; never merely delete the old guard from
the max calculation. Building a lower external 209 guard now would not remove
the 223 stopping point and would add transition risk without unlocking 351.

## Helper coupling and source integration before coexistence

The normal e1589345, full-210 86693cdd and repaired-227 3f2e9a4f helpers are distinct
sealed generations, not interchangeable model extensions. The repaired helper
has the selection-v2 canary and no full-210 model; the full-210 helper has its
full-210 profile/peer/terminal/status route and no selection-v2 canary model.
The original normal helper understands neither new full profile.

There is also a concrete discovery omission: the existing `fleet::census`
checks `horizon-qualify-*`, controllers, root sweeps and named native units,
but not unassigned `horizon-singleton-210-*`. An old plan that drops a new full
210 owner could miss it instead of rejecting it. The accompanying source-only
patch recognizes every assigned `horizon-singleton-EPOCH-*` as a required census
member. It does not make an unknown profile valid. Reserved protective services
such as `horizon-singleton210-protective-v1.service` retain their distinct names;
no broad suffix exemption is introduced. The added regression is not compiled
in this review, and no old binary changes in place.

Before either new job can coexist with the other, qualify and seal one integrated
reader generation with both complete profiles. Required source integration:

1. Merge the exact full-210 lifecycle/910cdfe2 guard profile and repaired 227
   selector/cap correction/selection-v2 lifecycle, preserving existing five-owner
   handlers and all frozen launch/terminal evidence. Build with both native-small
   features. Add the singleton discovery fix to every campaign admission reader
   that remains responsible for this host; switch the sole normal cadence to the
   integrated reader before admitting a new singleton.
2. Add a closed `canary227_peer` analogous to `full210_peer`: exact selection-v2
   unit, root, actual launch PID/IID/command, parent 79963ff4, runner 81a804e3,
   bounded worker d01adb19, guard 90e6fe78, real first guard/timer and zero restarts.
   Validate current actual requested systemd caps and rounded cgroup caps rather
   than substituting RSS. Preserve the native proof and original failed full 227.
3. Route roster/current/limits/disk/memory/completed-guard selection through both
   peer adapters and the original 223/209/204/205/225 accounting. Filter only the
   positively authenticated exact peer from an arithmetic subview, add its
   complete claim back exactly once, and preserve raw fleet and observation.
   Unknown, duplicated, missing, restarted, wrong-root or missing-guard owners
   must reject the entire admission.
4. For a live canary, reserve 300 GB minus min(whole-root coordinated allocation,
   fresh guard allocation), plus its uncredited 16 MiB external control budget.
   If observation scope is only its scratch child, take no whole-root credit.
   Keep every remaining slot/full-replay/publication gate unresolved. For full
   210, retain its whole-root claim and explicitly carry the separately admitted
   32 MiB external metadata reserve in future-peer accounting as well. Do not
   let a max-of-old-floors calculation accidentally swallow that declared claim.
5. Teach both admissions, the normal fleet/status matching, initial metadata
   events, terminal events and conditional inactive cleanup about both exact
   profiles. Retain every other registered claim/gate and the original observer
   clock; terminal metadata grants zero automatic capacity-release credit.
   Require an expanded coordinated observation before another ordinary admission.
6. Add joint fixtures for five old owners plus either/both new owners, omitted
   singleton discovery, exactly-once disk/memory/metadata growth, guard reclaims,
   old-helper rejection, wrong generation, phase handoff and terminal cleanup.
   Qualify the integrated helper and equivalent sandbox before any actual launch.
   Existing archive upload/verification utilities need no profile-driven restart
   if they neither model admission nor mutate fleet ownership.

## Safest next path

First complete already-authorized durable custody/retirement work, then use the
next accepted coordinated evidence; do not credit expected reclaimed bytes.
Remove the 2.35 TB padding only by recomputing P from a fresh complete basis and
sealing a new canary plan/proposal/command binding. Keep the current 223 internal
floor and all other old protections. Finish integrated reader/peer support before
launching a profile that an old helper cannot model. Defer any guard-threshold
handoff until it can provide an actual benefit and every internal floor and
transition gate can be honored without restarting healthy work.
