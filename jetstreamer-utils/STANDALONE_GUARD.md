# Standalone Horizon replay guard

`jetstreamer-horizon-standalone-guard` protects one exact, non-restarting standalone
`horizon-qualify-*.service` invocation. It does not manage adaptive controllers;
those require controller-before-producer stop ordering.

Seal the executable and a separately hash-bound plan with the deployment sealer.
Run as root in a persistent systemd timer service:

```text
jetstreamer-horizon-standalone-guard /absolute/plan.json --plan-sha256 HEX --self-sha256 HEX
```

Plan shape (values here are illustrative, not admission evidence):

```json
{
  "schema": "jetstreamer-horizon-standalone-guard-plan-v1",
  "unit": "horizon-qualify-example.service",
  "invocation_id": "0123456789abcdef0123456789abcdef",
  "filesystem": "/srv/horizon",
  "minimum_free_bytes": 1000000000000,
  "worker_root": "/srv/horizon/private/exact-generation",
  "maximum_worker_vmas": 800000,
  "receipt_directory": "/var/lib/horizon-example-guard"
}
```

Paths must be canonical absolute directories. The plan must be a root-owned,
single-link, non-writable-by-others regular file; the receipt directory must be
root-owned and owner-only. Supply the actual generation root, not a shared home
or campaign scratch parent. Derive the floor and VMA limit from the normal
campaign admission evidence, including older producers' remaining growth.

The producer must have `Restart=no`, `KillMode=control-group`, `Delegate=no`,
the exact bound invocation ID, and zero restarts. The guard scans nested cgroups,
requires recognized workers to stay beneath the generation root, and stops the
bound producer on a disk-floor or VMA trip, multiple workers, or unreadable worker
evidence. Zero workers is allowed during bootstrap and terminal drainage; this
is not proof of replay progress. Unit identity/state changes invalidate a sample.

Use a sandbox with read access to the exact generation and `/proc`, and write
access only to the receipt directory. An unprivileged worker can require
`CAP_SYS_PTRACE` for `/proc` reads and `CAP_DAC_OVERRIDE` for private ancestors.
Prove the actual least-privilege sandbox against the live worker. Neither a
manual unsandboxed run nor a waiting timer proves protection. Observe and retain
the first real sandboxed timer invocation before leaving a new replay unattended.

Every guard sample is fsynced no-clobber. A trip fsyncs a stop intent before
signaling and writes completion only after terminal state. Interrupted stops
resume from the exact plan/invocation-bound intent even if disk space recovers.
A collected transient unit is terminal only with that prior intent and an absent
original cgroup. A replacement invocation is never stopped. Old receipts remain
unchanged. The guard does not delete scratch, restart work, publish archives,
mutate R2, establish resource admission, or replace coordinated 30-minute replay
observations and fleet reconciliation.

For a bounded measurement, add the optional strict mode:

```json
{
  "worker_root": "/srv/horizon/private/exact-generation/scratch",
  "bounded_measurement": {
    "intent_path": "/srv/horizon/private/exact-generation/target-stop-intent.json",
    "producer_uid": 1001,
    "target_slot": 66577778,
    "maximum_drain_seconds": 600
  }
}
```

This is an extension to the complete plan above, not a standalone plan. The
intent must be a direct member of the producer-owned private measurement root,
immediately above the exact scratch directory. Strict mode requires one readable
bound worker while active; start under observation and prove the guard against
the actual worker before leaving it unattended. A zero-worker observation is
accepted only with the unchanged sealed runner's complete, private, stable,
same-invocation target-stop intent: target reached, scratch snapshot captured,
SIGINT controlled stop, no external signal, and a fresh timestamp. The timeout
must be between 1 and 900 seconds; the existing runner uses 600 seconds.

The first accepted workerless handoff is pinned no-clobber in the root-private
guard directory. A rewritten intent, moved deadline, changed digest, different
plan or different producer invocation cannot renew or transfer that exception.
Malformed, missing, unreadable, stale or foreign handoffs trip the exact bound
producer. A valid handoff never excuses multiple workers, unreadable maps, a
filesystem-floor trip or a VMA trip. Legacy plans without this optional mode
retain their normal bootstrap/drainage behavior.

Every stop goes through the same final exact-invocation/restart-policy check;
an identity mismatch is an error without signaling the replacement. This differs
from the old performance guard's mismatch-as-stop behavior, which must not be
reused for new measurements. Qualify the Rust binary and its handoff/copy-path
tests before sealing, and retain the real sandboxed first-fire requirement.
