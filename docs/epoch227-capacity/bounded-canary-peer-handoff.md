# Selection-v2 bounded canary peer handoff

This source change models only
`horizon-qualify-227-v1625-bounded-resource-d01adb19-selection-v2.service`.
It does not qualify a full epoch 227, clear the original failed attempt, authorize
a launch, or deploy any artifact. All operational transitions remain root-owned.

The accounting split preserves the raw fleet, complete unit census, diagnostic
claims and failure history. Only the derived active accounting view removes the
canary after authenticating its original claim, captured actual launch and
admission. Coupled readers are the prefix223 native20 roster/guard selector and
the shared singleton227 protected disk growth, current owners, memory and limits.
Unrelated generations retain their existing closed profiles; this is not a
general permission to admit arbitrary peers.

Disk growth is `300,000,000,000 - allocation_credit + 16,777,216` bytes. Credit is
the minimum of both original whole-root observer passes and both latest guarded
whole-root passes, all bound to the actual invocation, PID, worker and stable
process starts, clamped to a current two-pass allocation lower bound. The existing
observer and guard walks count multiply linked paths conservatively for upper
budgets; those totals alone cannot earn allocation credit. The additional current
proof uses no-follow descriptors anchored through every root ancestor, rejects
symlinks/special files and all regular-file hardlinks, rejects mount/device
escapes and duplicate directory aliases, checks the same entry identities and
nonshrinking sizes/blocks across two bounded passes, and holds root/ancestor
descriptors through the final owner check. Every opened subtree must match the
closed Linux ext non-reflink filesystem profile; XFS, Btrfs, overlay and unknown
profiles fail closed because link count alone cannot rule out shared extents.
This is integrity evidence inside the existing fresh admission transaction, not
an extra routine observation or monitoring loop. Scratch-only observations, missing raw passes, cap maxima used as
allocation, stale guards, trips and cooperative target drainage fail closed.
The external 16 MiB control metadata reservation never disappears. Guard command,
sandbox, PID1 completion and active waiting timer must still match the exact plan.

Systemd requested memory caps remain 225 GB and 150 GB. Kernel caps must reproduce
their host-page rounding, with swap disabled, 512 tasks and eight CPUs. Remaining
hard-memory growth uses the lower bracketed cgroup charge, separately from lane
RSS. Current identity and all static kernel limits are checked again; variable
memory charge is intentionally excluded from static-cap equality.

The live native223 prefix has a separate 480 GiB available-memory runtime floor.
The new strict sampled canary candidate reserves
`max(total_memory / 10, 480 GiB when native223 is live) + 225 GB + protected remaining hard growth`.
Only the difference between the effective floor and the host baseline is added,
so the 480 GiB floor and remaining growth are each charged once. A one-byte larger
baseline can arise from the pre-existing conservative ceil division. The exact
floor policy and required bytes are recorded in the strict admission. Legacy
canary candidate admission rejects a live native223 owner. A later live-canary
peer contribution carries the same separately evidenced floor top-up; derived
views retain the raw native223 census entry. Native223 candidate admission already
reserves its own 480 GiB floor and has no live native223 predecessor, so it receives
no duplicate top-up. Original canary admission provenance must prove this policy
if native223 was live at launch; an older under-reserved admission is ineligible.

The strict output-credit profile additionally requires explicit collected or
inactive entries for both `horizon-foundation-prefix213-park348-v2.service` and
`horizon-foundation-holding213-maintenance-v1.service`. Missing entries,
activating/start, active/running and deactivating/stop-post fail closed. The same
gate runs against both actual current censuses. The observed cycle 357 maintenance
shape (PID 650856, activating/start) is represented by the rejection test; no new
host sample is taken by these source tests.

## Coupled rollout checklist

1. Wait for the genuine maintenance terminal and reconcile it. Obtain the normal
   fresh coordinated observation and actual census; never infer inactivity from
   the absence of an entry. Preserve all prior receipts and failures.
2. Qualify and seal the selected observer, admission, capture, guard, runner and
   fleet transition as independent exact artifacts. Bind this reviewed source
   lineage and all immutable input digests in the admission and captured launch.
3. Add the exact diagnostic whole-root observer row and accepted fleet claim for
   the actual canary invocation. Bind its initial status, actual guarded launch,
   and eventual genuine terminal through the normal launch-event transition.
   Do not invent a future IID, PID, sample or completed guard.
4. Preserve the entire accepted observer/fleet binding and all original owners.
   Every protected guard must cover the complete active roster exactly. Keep the
   bounded target distinct from canonical checkpoints and full-epoch completion.
5. Do not reuse the sealed `e7701f95` routine metadata helper after a sixth owner
   appears: that helper accepts exactly the original five owners. Root must own
   the manual transition until a separately qualified successor helper exists.
6. Keep each existing publisher's exact selected-owner and plan checks. The
   current sealed `e1589345` six-report publication is three commands:
   `status-publish-qualification` for 204, 205, 225, 226,
   `status-publish-full209` for 209, and `status-publish-prefix223-native20` for 223.
   The latter two each select exactly one own registered diagnostic claim,
   accepted unit census entry and diagnostic observer row, retaining actual
   identity/command checks. None has a global five-owner whitelist; their
   selected-owner validation accepts a bound complete fleet with additional
   properly registered peers. The separate `status-publish-canary227` command
   similarly selects its own exact diagnostic claim. This source audit does not
   make the five-owner orchestration helper compatible. A fresh exact plan and
   binding are still required for each publication and initial status.
7. At target drainage, reconcile the real terminal before releasing any claim.
   The normal-running peer adapter intentionally refuses draining/stopped states.
   Status remains an inclusive estimate to canonical sidecar readiness, including
   follow-up full replay, qualification, upload and verification, not time to the
   bounded target. No archive or canonical sidecar is authorized by this change.

## Qualification

Source qualification passed with the shared absolute target, incremental off,
offline locked release profile and two build jobs: all 770 R2 tests passed,
48 intentionally ignored; strict all-target Clippy passed with `-D warnings` for
production and test targets. This includes 10 bounded-peer tests, five current
allocation tests and seven output-credit/maintenance tests. Logs are
`/tmp/epoch227-peer-full-tests.log` and `/tmp/epoch227-peer-clippy.log`.
`git diff --check` passed. No live deployment, admission, new host resource sample
or remote operation has been performed from this worktree.
