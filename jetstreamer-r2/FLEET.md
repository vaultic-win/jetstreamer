# Campaign fleet receipts

`jetstreamer-r2 fleet-reconcile PLAN --plan-sha256 HEX` performs authenticated
read-only inventory/status reconciliation and writes one private no-clobber fleet
receipt. It never starts work or changes R2 objects. The root-owned plan must bind
a coordinated observer-v2 receipt no older than 30 minutes, its predecessor fleet,
the full campaign epoch gate census, and tracked terminal/live units.

Ordinary replay claims come only from the stable observer bindings. A status ETA
is current only when authenticated status bytes and the local publication receipt
match that same live invocation and observer timestamp. Stale/orphaned status
objects remain untouched and never become active work merely because they exist.

An optional `diagnostics` list accounts for bounded private A/B lanes that already
capture their own invocation-bound cgroup/target-stop metrics inside the sealed
runner. Each entry has this shape:

```json
{
  "epoch": 154,
  "unit": "horizon-perf-epoch154-example@control.service",
  "invocation_id": "0123456789abcdef0123456789abcdef",
  "scratch_path": "/private/exact-cohort/control/scratch",
  "launch_receipt": {
    "path": "/private/exact-cohort/launch-receipt.json",
    "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
}
```

These are illustrative values, not launch or admission authority. Each claim
must match one exact zero-restart live service in the hash-bound reviewed
performance-launch receipt. The service name must bind the same epoch, its live
scratch must be canonical, claims must be unique by unit, and no ordinary replay
may overlap that epoch. Multiple diagnostic variants of one epoch are allowed.
The complete unit census is checked before and after remote reads.

Diagnostic entries are explicitly `diagnostic-qualification`, not ordinary
replays or sidecar claims. They retain the qualification gate and have no current
sidecar ETA. A stopped or failed service is excluded from the active list; its
launch receipt alone cannot establish terminal success. Inspect its bounded
canary/result receipt before progressing or retiring artifacts.

Receipts also contain unit and epoch-state transitions against the preceding
fleet. Newly bound units, disappeared units, changed invocation/state/commands,
and epoch classifications are explicit. Continue using one coordinated
30-minute observation/status/fleet cycle, not another polling loop for this tool.
