# G3: fund the first guard from verified unused capacity

The held G2 producer `5986d31775c647fc971d4bd41a482158` obtained genuine guard
`0c29c33ca3a743d7be4b65106449e15f`, then rejected `post-guard protected floor
increased` at 13:27:07 UTC. The receipt records successful rollback. No payload
release, staging completion or admission receipt was written. All three preserved
guard samples show zero workers and no trip. The original first-guard identity,
plan, cold-stage receipt, source/build seals, failed receipt and empty producer log
are pinned in `retry2.rs`, which verifies old G2 units remain drained.

The retained preflight and final prelaunch fit have these exact values:

| Quantity | Preflight | Final prelaunch |
| --- | ---: | ---: |
| Protected HOME floor | 8,511,984,860,482 | 8,513,508,777,282 |
| Remaining epoch168 growth | 204,696,690,688 | 206,220,607,488 |
| Peer remaining growth | 1,043,718,569,984 | 1,043,718,569,984 |
| Audit remaining archive | 31,898,718,971 | 31,898,718,971 |
| Audit remaining working allocation | 10,374,324,224 | 10,374,324,224 |

The 1,523,916,800-byte floor increase equals the increased remaining168 growth.
The guard was armed at the exact changing floor, with no funded allowance for
another increase while the held gate was protected. The failing *post-guard*
fit was discarded before receipt publication by the old controller, so its exact
floor is unknown. This repair does not invent that missing measurement.

The final retained complete requirement was 8,614,478,867,778 bytes, including
100,970,090,496 bytes of remaining candidate growth. The minimum of its native
available value and audit-conservative available value was 8,723,980,529,664:
109,501,661,886 bytes of uncommitted slack. A 16 GiB margin would have required
8,631,658,736,962 bytes and armed the guard at 8,530,688,646,466. These retained
numbers justify the policy; **every retry recomputes them with fresh evidence**.

`horizon_guard_floor_margin_20261120_v1/floor.rs` funds exactly 16 GiB only if
the full current fit has that much uncommitted slack. It requires checked integer
arithmetic, complete candidate-growth accounting and zero capacity credit. The
native fit now records the actual final conservative available value, rather than
the earlier value that could overstate slack. After the first real guard, a full
new fit must establish both:

* current protected floor <= the already-armed higher floor;
* conservative free HOME >= that armed floor + complete remaining candidate growth.

Neither constraint is weakened. If movement exceeds the paid margin or free space
no longer covers it, the held producer rolls back. `POST_GUARD_FIT.json` is now
written **before** checking the floor, preserving an actual rejected fit.
Successful capacity includes the selection, raw fit and higher-floor validation
bindings. The same arithmetic and receipts are used by the shared171/172 launcher,
including both feature routes. Existing sealed/running helpers are unchanged.

## Parent integration and next retry

1. Apply the source patch to current `account-updates`. Keep the epoch90 audit
   recovery build first. In the retained serial slot, run tests/strict Clippy and
   release builds for169 and shared172, plus shared172 with `--features epoch171`.
   The common module adds five arithmetic/regression tests using the real retained
   prelaunch figures; the retry adapter adds two custody/lineage rejection tests.
   Native offline node-path controls must use the updated G3 fixture script.
2. Commit/push and verify source containment before any admission. Build and
   normal-seal all three new169 executables (`admit169`, `gate169`, `focused169`)
   and their genuine artifact proof into
   `/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-admission-20261120-v3/admission-v1`.
   Existing node/worker/input seals remain exact inputs. Source containment must
   include the retained5a67854c controller and the new merged source tree.
3. Prepare the new HOME-backed runtime root as root:root0700, its empty `barrier`
   as root:root0755, empty `guard-receipts` as root:root0700, and empty
   `guard.stdout`/`guard.stderr` as root:root0600. Optional top-level preparation
   files are `artifact-proof.json`, `controller-plan.json`, `native-controls.log`.
   No other files may preexist. Do not create a new admission lock: the adapter
   verifies and uses the original G2 lock inode101132300.
4. Prepare the fresh
   `/home/sol/.jetstreamer-private/epoch169-focused-diagnostic-20261117-v1/attempt-g3`
   as sol:horizon0700, containing only empty sol:horizon0600 `producer.log`.
   Leave `attempt-g2`, both old runtime generations and `v158` inputs unchanged.
   The new attempt's identity is observed and bound in `RETRY2_COLD_SETUP.json`.
   Complete whole-lane accounting includes retained and new metadata.
5. Native-qualify the unchanged resource/security envelope with its new paths.
   All cgroup memory/CPU/tasks/runtime limits, root cap and worker-specific
   identity checks remain unchanged. Make sure the current audit successor's
   genuine owner/config/artifact is recognized by the shared audit fit; if its
   generation changes, integrate that authoritative adapter rather than bypassing
   the audit census. Use a fresh complete peer/audit fleet after any transition.
6. Run the newly sealed executable with
   `--preflight FLEET FLEET_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT`, then
   `--launch` with the same argument structure and fresh accepted inputs. The
   controller rechecks the failed G2 custody and unused G3 namespace, selects the
   funded floor, starts only its held gate, obtains genuine first-guard evidence,
   performs the complete post-guard fit and sandbox checks, then releases the
   unchanged node/worker route. All new units use the `20261120-v3` suffix.

Source-only validation is not native admission. The repair agent did not create
these runtime paths, run a compiler, reserve a build slot, launch an actor or
change R2. Failed old evidence is retained, including the fact that its missing
post-guard measurement cannot be recovered from the stored receipts.
