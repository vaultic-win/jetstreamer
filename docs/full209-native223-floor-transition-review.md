# Full 209 / native 223 floor transition review

This is source-only review of the accepted cycle 354 evidence. It authorizes no
poll, guard change, producer restart, reservation reduction or deployment.

## Accepted evidence and arithmetic

Fleet `/var/lib/jetstreamer/horizon-campaign-fleet/20261024T091300Z-v354/fleet-ledger.json`,
SHA256 `4dd9ff836bbf4624e496388e085222eb222eb4ee70d7cc53b6e74c73c63fd9f3`,
binds observer SHA256 `3bc6fb20ac0aa0972bc173038b8071d0ba84799c26b1b1fedc126d2821cbbecb`
at 09:13 UTC. Recorded free disk is 2,323,934,646,272 bytes. These are historical
accepted values, not a new current sample. Its 14 ready archive lengths sum to
1,717,682,084,320; the century floor remains **245,383,154,903 bytes**.

Use complete claims, not a selected owner's scratch alone:

```
C = ceil(2 * ready_archive_length_sum / ready_archive_count)
G = sum(all actual owners' remaining incremental growth)
P = max(C + G, every effective external and in-process floor)
required_initial_free = P + complete new incremental claim
```

Every credited existing allocation must be identity-stable and match the exact
claim scope, including physical output allocation when the claim includes it.
Reclaimed or offloaded bytes are not allocation credit. Every same-sample owner,
auxiliary writer and outstanding metadata claim must be included exactly once.
The legacy 225 remaining reservation and its baseline are not replaced by a
new 300 GB scratch assumption. Terminal status alone does not release a claim.

The 2.35 TB canary value is provisional padding, not an admitted policy constant.
`canary227_admission` already accepts a freshly computed floor covering P; a
new, separately sealed plan can use the actual computed value without changing
its worker or relaxing its reservation. At P = 2 TB, the canary's complete
300,016,777,216-byte claim would leave 23,917,869,056 historical bytes of
headroom at cycle 354. This is only a lower-bound fit calculation: fresh full
owner growth and output credits could make P larger, and actual admission
still requires all identity, capability, memory, guard and timing gates.

Full 210's root claim is 471,798,691,840 bytes, plus 33,554,432 metadata bytes:
471,832,246,272 total. At an effective 2 TB floor it needs
2,471,832,246,272 free bytes, **147,897,600,000 more** than cycle 354 records.
Even hypothetical completed retirement of the 125,316,500,795-byte 213 prefix
would leave only 2,449,251,147,067 bytes, a remaining deficit of
**22,581,099,205 bytes**. That reclamation is not credited until real custody,
retirement and a later coordinated sample prove it. Changing a provisional
canary number cannot repair full 210's physical deficit.

## Effective floors differ from external guard plans

Cycle 354 preserves these actual owners:

- Full 209: unit `horizon-singleton-209-capped-4aeca563-v1.service`, invocation
  `1bf0db73ccd44c2c90461889498d4f82`, main PID 307346. Its immutable launch is
  `/var/lib/jetstreamer/horizon-209-singleton-capture-actual-v1/launch.json`,
  SHA256 `341de3f9b0f8dc835e80f624452223a43a051077e0cf3a65ef66144182e4fac7`.
- Native 223: unit `horizon-qualify-223-v1620-root-prefix-resource-full-v1.service`,
  invocation `e70aaf097e7c4583b216aba454145910`, main PID 386102. Its launch is
  `/var/lib/jetstreamer/horizon-native223-prefix-capture-actual-v1/launch.json`,
  SHA256 `a629f2a5eb1a6be5e3ec38e66769f0698841fb7ccc8d43110ac3bfd73df99ac3`.

Full 209's normal node command has no runtime floor-reload argument. Its
external guard plan is authenticated by `singleton209::guard_matches`, which
requires `minimum_free_bytes == original_launch.guard_minimum_free_bytes`.
Simply replacing its guard plan invalidates readers that bind the immutable
launch, even if the replacement threshold is otherwise defensible.

Native 223 has the stronger, independent blocker. Its actual immutable runner
`/var/lib/jetstreamer/horizon-native223-next-root-d18fd429-v2/jetstreamer-epoch223-v1620-root-prefix-resource`
has SHA256 `d18fd42956cafd34d6dccabeb2a47fbbca8c8d857ef8ed7adb39d8ad2a2b1d7d`.
`epoch223_native20_prefix_gate.rs` compiles `PREFIX_FLOOR = 2_000_000_000_000`;
`prefix_runtime_resources()` checks that floor in the running wrapper.
`epoch223_v1620_root_prefix_resource_bin.rs` calls it every 15 seconds, writes
an original guard-stop receipt and terminates its owned child on failure. That
binary has no reload hook for a replacement floor. Its external contract also
binds the original 2 TB plan and guard receipt directory.

Consequently an external guard handoff alone cannot make live native 223 safe
to run below 2 TB. Restarting or hot-patching that healthy wrapper to acquire a
new source policy would violate the current preservation constraint. Pausing
it does not remove its remaining-growth reservation or qualify its resume
below the same built-in floor. The existing floor remains effective until its
real terminal transition is authenticated or a separately authorized mechanism
exists. No such live mechanism is established by this review.

## Safest next source design and precise missing proof

Do not deploy a live floor reduction for capacity that it cannot unlock. The
immediate safe optimization is to recompute the canary proposal from complete
fresh accounting rather than copy 2.35 TB. Keep native 223's real 2 TB stopping
point in P. The existing reader API already supports this proposal correction.

If an external full 209 guard transition is independently useful later, the
smallest safe source change is an **explicit immutable transition overlay**,
not a rewritten launch or a broad exception in `guard_matches`:

1. Bind the unchanged original launch, original guard executable/plan and old
   qualified fire; exact producer IID, main/child PIDs, commands, root, worker,
   memory/VMA/root caps and all raw original proof remain unchanged.
2. Bind the exact fresh accepted observer and complete fleet, per-owner original
   growth reservations and baselines, validated allocation/output credits,
   century inventory and every effective external/internal floor. Compute
   `P_after = max(C + G, all external floors except only the explicitly superseded
   old guard, all internal floors)` with checked arithmetic; no growth claim,
   allocation requirement or internal floor is removed. During overlap the
   effective floor remains `P_overlap = max(P_after, old_external_floor)`.
   Bind a complete same-sample before/after census and current guard allocation
   evidence. Preserve auxiliary writers and outstanding metadata reservations.
3. Bind a distinct new guard binary/plan/service/timer and its exact requested
   threshold. The new threshold must cover P_after. Handoff itself must protect
   P_overlap; subsequent admissions cannot use the lower prospective value until
   real old-guard retirement is authenticated. A native 223 overlay claiming an effective floor below 2 TB
   must be rejected for this immutable runner, regardless of proposed capacity.
4. Qualify the new guard under the unchanged producer identity and prove its
   actual successful PID1 fire plus armed timer before retiring old external
   coverage. During overlap both floors are effective. Only an authenticated
   terminal handoff of the old guard can retire its external floor; never create
   an interval without qualified protection. Producer/worker remains untouched.
5. Update all actual owner readers together: fleet matching, peer adapters,
   admission arithmetic, current limits/guard selection, future status/capture
   and complete-owner census. They must recognize this exact overlay lineage
   while retaining the original launch as immutable history. Old sealed readers
   do not silently gain this behavior. Add omitted/duplicate owner, stale fire,
   wrong IID/caps/command, double credit, rounded metadata, guard overlap and
   rejected native-223-internal-floor fixtures before build/seal.

Before producing any operational overlay, root needs actual same-sample physical
output allocations for 204/205, fresh qualifying 209/223 whole-root guard
allocation evidence no earlier than the admission sample, complete unchanged
owner claims, first-fire/timer proofs for the prospective new guard, and an
integrated reader generation recognizing the transition. Preserved 348 guards
or 354's historical free value cannot be promoted into a future admission.

For native 223 the additional prerequisite is precise: either wait for its
natural success and authenticate the real terminal/source-idle handoff into
its independently admitted reader/assembly owner, or identify a previously
qualified in-process floor reload in the exact running immutable binary.
Source shows no such reload, so external rebasing cannot supply it. Future
runner generations can accept a root-sealed, generation-bound resource policy
before launch (or an explicitly qualified reload), but that source change does
not alter this running invocation or justify a restart now.
