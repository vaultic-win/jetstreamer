# Exact 185 staged-reference diagnosis and reconciliation

This extends the qualified 185 holding candidate without changing its strict inspector, 136 behavior, native 228 paths, canonical archive gates or growth claims. The first production inspection (`38bf7d724d2e40e78102403b98bb5789`) stopped before archive hashing because staged consumers remained. A literal config search identified nine candidates; only the new native diagnostic establishes the authoritative census.

`holding-diagnose185-references` uses the existing exact sealed 185 inspection plan. It verifies native stopped 185 provenance and the retained partial's metadata, runs the existing whole-lane process and staged-reference scanners, records all reported references without exclusions, and captures the nine known metadata owners plus original config inode identities. It does not hash the partial, traverse account trees, contact R2 or mutate units. Its durable diagnostic explicitly grants no reconciliation authority. An extra reference is reported rather than hidden.

`holding-reconcile185-staged` takes an immutable hash-bound plan:

```json
{
  "schema": "jetstreamer-horizon-holding185-staged-reconcile-plan-v2",
  "mapping": {"path":"EXACT EXISTING MAPPING","sha256":"EXACT SHA"},
  "inspection_plan": {"path":"SEALED EXACT185 INSPECTION PLAN","sha256":"EXACT SHA"},
  "diagnostic": {"path":"SEALED NATIVE DIAGNOSTIC","sha256":"EXACT SHA"},
  "preservation": {
    "path":"/usr/local/lib/jetstreamer/horizon-node02-holding-epoch185-staged-backup-20261024-v1/preservation.json",
    "sha256":"EXACT SHA"
  }
}
```

Placeholders deliberately cannot execute. A complete production plan can be sealed only after the native diagnostic and preservation evidence exist.

The preservation manifest has schema `jetstreamer-horizon-holding185-staged-preservation-v2`, host `dev-samjohnson`, exact `diagnostic` and `inspection_plan` bindings, `replay_data_removed:false`, `growth_claims_released:false`, and exactly nine `members`. Each member contains `unit`, exact original config path, `original_identity` from the diagnostic, and hash-bound `config`/`journal` files. Configs must be named `UNIT.config.txt` and journals `UNIT.journal.jsonl`, directly under the fixed backup directory above. Preserve available native unit journals and record capture scope before collecting anything. All evidence is root-owned immutable regular data; all configs and journals together are capped at 16 MiB. No backup lives in systemd's scanned config roots.

The exact metadata jobs are the eight retained transient units `horizon-idle-credentials185-full-{refresh,preflight}-20261023-v{1,2,3}.service` and `horizon-epoch185-full-admission-20261023-v{1,2}.service`. Their original invocation IDs, original config hashes and terminal statuses are compile-bound in `holding_epoch185_staged.rs`. Successful jobs are PID0/active-exited; failed jobs are PID0/failed with the original status 1. Every job must retain its exact identity, one-shot definition, no restart, no trigger/handoff, no ExecStop/ExecStopPost and an empty cgroup before collection. Structured native D-Bus queries positively prove both stop-command arrays empty, MainPID/ControlPID zero and Unit.Job absent, between equal before/after native manager snapshots. Missing systemctl command-array fields are never interpreted as empty. Collection recovery instead requires positive not-found/inactive/dead Unit properties and an empty native Unit.Job, with a durable transaction frontier; it does not invent missing Service fields. A changed/restarted/live owner fails closed.

Before the first manager mutation, the command requires a diagnostic at most 30 minutes old, matching exact original nine-reference census, immutable byte/journal preservation, fresh whole-lane process/reference checks and a durable transaction intent. It then journals intent for each exact terminal job, revalidates native identity/config inode/bytes and cgroup emptiness, and requests `systemctl --job-mode=fail stop UNIT`. Failed state may be reset only after revalidation. Collection is complete only when PID1 reports not-found and the original transient fragment is absent. The tool never unlinks transient fragments itself. If collection has not completed, it preserves intent and fails for later reconciliation.

The obsolete static Oct 20 controller is separate from the stopped Oct 23 controller. Its exact file is `/etc/systemd/system/jetstreamer-epoch185-singleton-20261020-controller-v1-r2.service`, SHA `949de6d3feca587ea6c7bfcf8e798cf007042bc909c706acdd6ab6e62961c2cc`. It must remain inactive/dead/PID0 with no restart/stop/handoff actions and its original loaded definition. After all eight metadata jobs are collected, the tool copies this file into the private reconciliation state directory, fsyncs it, and uses the 136 pattern's same-parent no-clobber/atomic exchange to install a `/dev/null` mask. Every intermediate original inode/hash is checked. The exchanged original is removed only after the retained copy and durable frontier exist. This is the sole config-byte removal, with two preserved copies; it does not touch replay data. Native staged scans run before and after the complete exchange; no temporary or terminal fragment is excluded from a scanner result.

State is kept under `/var/lib/jetstreamer/horizon-terminal185-staged-reconciliation-20261024-v1`. A completed or interrupted transition may re-enter only with the same immutable transaction bindings. Recovery revalidates preserved bytes and fresh native ownership/references; a missing frontier, reappearing original, conflicting copy or foreign intent fails closed. A durable existing transaction may use its original diagnostic after 30 minutes because the current native gates are repeated; a new transaction may not.

Operational sequence: qualify and seal the new tools; run and seal the no-hash diagnostic; review its actual references and native terminal states; seal all original config/journal bytes plus preservation manifest; seal/review the exact reconciliation plan; coordinate its event window with the parent; execute only under its separate production admission. Then run the unchanged strict 185 inspector under a fresh admitted hash window. No source preparation or test result authorizes a unit/config mutation, park or retirement.

Tests cover exact terminal metadata identity, stop actions/restarts/replacements, collected-state recovery authority, arbitrary target selection, unknown staged references and forbidden exclusions, plus the 136 pattern's isolated copy/exchange/interruption/conflict fixtures. These source changes need fresh combined r2 tests/Clippy/release before use.
