# Closed OS guard for the native checkpoint experiment

`jetstreamer-utils/src/v1425_os_experiment_guard.rs` is a standalone Rust binary.
It does not add a Cargo workspace target, historical worker protocol request,
replay selector, production timer or native resume authority. It reuses the
existing descriptor-based `horizon_standalone_guard_root.rs` physical census
without changing that module. Build the standalone binary and its tests with
the current Rust1.98 compiler and compatible, read-only release dependency rlibs;
do not write the modern Cargo target. Cached rlibs from historical compilers or
different serde-core feature identities are not interchangeable.

The only profiles are the fixed native-build unit
`horizon-v1425-portability-native-build-20261023-v1.service` and the explicitly
selected `--canary` disposable unit
`horizon-v1425-os-budget-canary-20261023-v1.service`. There is no arbitrary unit,
PID, filesystem, root, threshold or receipt-directory selector. The immutable
budget is
`/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json`,
SHA-256 `2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620`.
Both profiles require `/var/lib` device2304 and at least220243844550free bytes,
preserving the205211459014floor plus10GiB fixture and4GiB modern-builder claims.
The build tree is exactly
`/var/lib/jetstreamer-builds/readback-progress-20261022-v1/legacy-v1-4-25`, with
maximum11232206848physical bytes. The canary's separate fixed tree has a16KiB
limit. Source/cache remain read-only; only exact guard receipts are writable.

Plans have exactly five fields:

```json
{
  "schema": "jetstreamer-v1425-os-experiment-guard-plan-v2",
  "profile": "build",
  "budget": {
    "path": "/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json",
    "sha256": "2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620"
  },
  "invocation_id": "EXACT_CURRENT_32_HEX_INVOCATION_ID",
  "start_monotonic": "EXACT_POSITIVE_EXEC_MAIN_START_MONOTONIC"
}
```

The canary profile string is `disposable-canary` and requires `--canary` on the
command line. Seal each exact plan with the native deployment sealer. Invoke
`guard PLAN --plan-sha256 HEX --self-sha256 HEX`, optionally `--check-only`.
`--check-only` rechecks target identity across the sample, writes an immutable
receipt and never stops anything, including when it observes a breach.
Prepare root-owned mode0700 receipt roots and their exact invocation-ID children:
`/var/lib/jetstreamer-v1425-os-guard-build-20261023-v1/receipts/IID`, or the
corresponding canary tree's `receipts/IID`. Never reuse another invocation's
receipt namespace.

The watcher checks only its experimental target and OS budget. It treats a
physical-census error or alias as a breach. It requires exact invocation/start,
zero restarts, Restart=no, KillMode=control-group and no delegation before
stopping. It fsyncs no-clobber intent, rechecks ownership, persists fresh stop
authorization, rechecks again, then asks systemd to stop only that fixed unit.
A durable submission and terminal completion follow. Interrupted frontiers
preserve evidence; an owner change never authorizes stopping the replacement.

On this host, systemd clears both InvocationID and execution start timestamps
after stopping the unit. Cleared fields alone are not terminal lineage. Recovery
additionally requires the exact durable authorization/submission, inactive/dead
PID0, empty/unpopulated cgroup, no pending job, and the latest trusted PID1
terminal history from the current boot. The bounded journal census validates
trusted PID/UID/executable/scope/transport and exact UNIT, requires the latest
bound invocation to remain the original, and requires its latest lifecycle to
be stopped(done) or deactivated. A replaced-and-finished invocation is rejected.
Completion preserves the journal records and digest, and manager state is read
again after the journal. Repeating a completed transition revalidates these
facts without rewriting its original receipts or submitting another stop.

Qualification on2026-10-23 used the separately sealed v2 guard at
`/usr/local/lib/jetstreamer/horizon-v1425-os-experiment-guard-20261023-v2/guard`,
SHA-256 `27982342db4cee587f0ca966c62a572ba1fd3f65b52e8ba206160a191376d336`.
Strict standalone compilation passed and12unit tests passed. The sandboxed
canary check/actual-stop/idempotent recovery used target invocation
`5a183aef0be34c29979b60976ee0bd1e` and sealed plan SHA
`39a9b5d6e3089f18b05c83dc8d599613cebe62b241e6ae06c48a43f75649e721`.
The over-budget check receipt SHA is
`c4a1dc6dee3d979832b89117899083fb9db754d920e40071390d207569fa5441`;
the terminal completion SHA is
`e374c390fdbae66dd670fb3c0dd748e5fac0bd5f2a8ee9fd3e93a06577e36abe`.
The completion is under that invocation's canary receipt directory. Its retry
left all four durable frontier hashes unchanged. The initial v1 qualification
failure remains preserved separately; it stopped its disposable canary but
correctly refused to invent terminal proof when systemd cleared its metadata.

These results qualify this guard's closed experimental stop path. They do not
qualify native checkpoint export, fresh-process runtime continuation, archive
writer recovery, a live replay stop, or R2 retirement. The parent must acknowledge
the guard evidence before the separately admitted native test build starts.
