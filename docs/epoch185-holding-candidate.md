# Exact stopped epoch185 partial holding candidate

Candidate only: no production deployment, large partial hashing, R2 request or local artifact mutation was performed while preparing this change. Existing136 inspection, transport and retirement behavior is unchanged. The shared generic `holding-park` remains the transport implementation; the new185 profile copies the reviewed136 exact quarantine/recovery transitions with independently scoped provenance and capacity gates.

The only selected artifact is the original stopped185 `archives/epoch-185.jet`, logical size 56,206,322,555 bytes, device64512/inode100270097, mode0600 uid1001/gid1003, one link, mtime/ctime1792801929.171229060. Its measured physical blocks represent 56,206,397,440 bytes (~52.35 GiB). No valid container prefix, portable Bank, continuation, canonical readiness or successful185 repair is asserted. Accounts-state, inputs, snapshots, status cache, logs and all receipts stay local and outside this selection.

## Plans and commands

Every command takes `SPEC --spec-sha256 HEX --self-sha256 HEX`, with root-owned immutable hash-bound plans and the reviewed running uploader digest. Plans reject unknown fields. Every `Bound` below is `{ "path": "/absolute/evidence.json", "sha256": "64 lowercase hex" }`.

`holding-inspect185` takes:

```json
{
  "schema": "jetstreamer-horizon-holding-inspect185-plan-v2",
  "mapping": "Bound",
  "guard_intent": "Bound",
  "guard_completion": "Bound",
  "qualification": "Bound",
  "deployment": "Bound"
}
```

The string `Bound` is a documentation placeholder for the object above. Guard paths and SHA values are pinned to `/var/lib/jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1/{intent,completion}.json`; these native mutable-directory receipts are read through the stable root-owned evidence reader. Transport qualification and original185 deployment-seal receipt have independent pinned paths/digests. This does not rehash or qualify the original runtime binaries.

Inspection requires the two exact old owners collected (`LoadState=not-found`), inactive/dead/PID0/restarts0, no trigger/handoff fields and no persistent `/etc/systemd/system`, `/run/systemd/system` or `/run/systemd/transient` unit definitions. It rejects adjacent canonical sidecars and aliased/changed source identity. Whole-lane current and staged references are checked before and after admitted hashing. It emits ordinary eligibility-v2 explicitly classifying an interrupted unvalidated failed artifact and denying prefix, resume, publication and retirement authority. The inspector intentionally cannot choose an arbitrary source, and does not contact R2.

After reviewed eligibility is sealed, use the existing generic `holding-park` with schema `jetstreamer-horizon-holding-park-plan-v2`, exact mapping/eligibility/source/length/SHA. It supplies no-clobber content-addressed upload, full authenticated readback and durable custody beneath the authorized `node_02/` prefix. No canonical `.jet` or sidecar key is created.

`holding-check-retire185` and `holding-retire185` take:

```json
{
  "schema": "jetstreamer-horizon-holding-retire185-plan-v2",
  "mapping": "Bound",
  "guard_intent": "Bound",
  "guard_completion": "Bound",
  "qualification": "Bound",
  "deployment": "Bound",
  "inspection": "Bound",
  "custody": "Bound",
  "capacity_completion": "Bound",
  "prior_check": null
}
```

The check requires `prior_check:null`. Retirement requires a sealed successful exact descriptor check no older than900seconds. Both take the existing shared `/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock` in addition to the holding transition lock. Both validate latest complete fleet ownership, terminal/current/staged references, custody and remote manifest/blob identity; local bytes are freshly rehashed. The remote canonical185 archive and sidecar must remain absent. Actual retirement then uses only the fixed same-filesystem quarantine `.../r2-holding-state-dev-samjohnson-v1/retirements/epoch185-stopped-20261024.partial`.

Durable intent → quarantine/moved proof → unlink intent → completion records preserve idempotent recovery. Source/quarantine conflicts, changed inode/hash/ETag, missing transition frontiers and reappearing artifacts fail closed. Completing this lifecycle grants neither growth-claim release nor a restore/replay admission.

## Fresh post185 pressure-relief basis

`capacity_completion` is a separately reviewed root-owned hash-bound receipt with this distinct schema. Do not reuse capped186's old five-owner capacity basis or fabricate the next observer receipt:

```json
{
  "schema": "jetstreamer-horizon-holding-retire185-capacity-v2",
  "host": "dev-samjohnson",
  "fleet": "Bound",
  "guard_completion": "Bound",
  "sampled_at_utc": "fresh fleet timestamp",
  "recorded_unix_seconds": 0,
  "pressure_relief_only": true,
  "new_launch_authorized": false,
  "restore_authorized": false,
  "growth_claims_released": false,
  "pre_retirement_free_space_credit": 0,
  "epoch185_original_growth_claim_retained": true,
  "epoch141_original_growth_claim_retained": true,
  "all_live_staged_and_retained_growth_claims_preserved": true,
  "retained185_physical_bytes": 56206397440,
  "all_current_protected_bytes": 0,
  "original_claim_bindings": [
    {"epoch":185,"retained_growth_bytes":824633720832,"binding":"Bound"},
    {"epoch":141,"retained_growth_bytes":0,"binding":"Bound"}
  ]
}
```

Zero clocks/protected bytes/141 bytes in this template must be replaced with real measured/reviewed values. The protected amount must conservatively retain all current obligations and be at least the original185 guard floor3,503,746,342,342. Both original claim receipts are authenticated, with exact unique141/185 entries;185 retains at least768GiB and141 retains its original positive growth amount. The code cannot derive these policy amounts from arbitrary historical receipt schemas; reviewing the complete protected-claim arithmetic is an independent prerequisite.

The fleet must be an accepted complete101–200 fleet in the existing canonical private fleet directory, sampled after the native185 stop and at most30minutes old, and have the same timestamp as this capacity receipt. The capacity receipt is at most15minutes old. Every newer fleet/phase event invalidates it. Current owner/census identities and restart counts must still match. Epoch185 must be failed-needs-repair or blocked-qualification, with no active replay, diagnostic, downstream pipeline or replacement owning its scope.

Pressure relief does **not** require free space to exceed protected growth already: it allocates no restore/new replay and grants no claim release. No physical credit exists before authenticated custody and actual guarded unlink. A separate future admission must use actual current free space and full obligations.

## Remaining gates

1. Parent runs serialized tests and Clippy against this candidate; no candidate build was started by the audit agent.
2. Review exact policy, original claim bindings and full post185 protection arithmetic against the next accepted complete fleet. Preserve185 and141 obligations until an independently qualified transition releases them.
3. Seal the reviewed uploader candidate and each plan/evidence bundle using the normal Rust sealer. Qualify command dispatch, permissions and adversarial isolated transition fixtures without contacting production artifacts.
4. Obtain explicit parent admission for the large stable hash/readback work and any production R2/local transitions; preparing source grants none of those actions.
5. Admit source hashing, produce and review eligibility, park/readback with the existing generic transport, seal custody and fresh pressure-relief basis, run successful exact check and then separately authorize exact retirement.
6. After native completion, reconcile actual freed physical bytes and keep185 in open repair accounting. No Bank continuation was qualified.
