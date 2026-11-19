# Full211 protective stop and retirement

This source is unbuilt. Main must run the bounded offline tests and actual
experiment before accepting it. The new route uses the exact full211 launcher,
producer/guard templates, unit names, private root, genesis projection, CPU and
memory envelopes. It does not rerun native211 or execute the full211 node.

## Operation boundary

Every review and startup plan carries `operation: "launch"` or
`operation: "qualify-guard"`. Only the latter can enter the experiment. Its
admission grants `held_gate_launch_authorized: true` and keeps
`replay_launch_authorized: false`; all archive, publication and remote mutation
flags remain false. The held gate checks that operation independently and will
never consume a token or exec the node for a qualification plan. A token
directory appearing during the experiment is an error.

Production `admit` and `launch` require a `launch` review and a semantically
accepted stop/retirement graph. Qualification is the only narrowly scoped
exception to that predecessor requirement; it keeps current complete fleet,
resource, source publication, input capability, sandbox and consumer prestart
requirements. It does not reduce a reservation, advance epoch progress or
grant production authority.

## Actual experiment

1. Complete source/build/feature/provenance qualification and seal the exact
   launcher and full211-enabled generic standalone guard. Qualify the actual
   root metadata sandbox and uid1000 read paths. Obtain the separately booked
   input capability outside the startup lease.
2. Prepare the pristine root with only `output/genesis.tar.bz2`, an empty
   uid/gid1000 mode0400 bind placeholder. Use the documented root/output modes
   and token directory. All four full211 unit names must be unused. Obtain a
   fresh complete fleet review with `operation: "qualify-guard"`, a new safe
   `attempt` and the exact input/artifact bindings. Do not use production launch
   to create the qualification.
3. Under Main's admitted metadata service, run:

   ```text
   LAUNCHER qualify-guard REVIEW REVIEW_SHA SELF_SHA NEW_EXECUTION_DIRECTORY
   ```

   The startup/admission keep their normal filesystem floor. Only the guard's
   stop experiment plan uses `minimum_free_bytes: 18446744073709551615`; all
   other guard fields and templates remain exact. The controller captures the
   held mapped launcher, NUL-separated argv, PID/IID, sole cgroup process, no
   children/descendant cgroups, absent token and pristine root inode metadata
   before starting the timer. It never constructs or seals a release token.
4. The actual generic guard must produce its normal `sample-IID.json`,
   `stop-intent.json` and `stop-completion.json`. It must report the floor trip,
   no worker, no observation error, whole-root accounting and enabled stop.
   The generic guard exits successfully after synchronous PID1 stop; a
   native265-style failed guard or `stop-request-IID.json` is not accepted.
5. Capture requires the original producer to terminate with SIGTERM
   (`ExecMainCode=2`, `ExecMainStatus=15`, `Result=success`, no restart), its old
   PID absent, its cgroup/descendants drained and no remaining `/proc` membership.
   The root, output directory and empty placeholder must retain their original
   identities. The timer is stopped after the guard finishes. Neither the
   producer nor its retention target is restarted or removed by this command.
6. PID1 journals must establish one same-boot/same-invocation producer start,
   then the held observation, guard start, producer stopping, producer
   deactivation and guard deactivation, in that order within the original
   startup lease. Missing, duplicate, foreign or out-of-order events reject.
   The capture binds the actual journals and native guard records, complete
   producer sandbox, exact four unit templates and source admission graph.

The command prints a binding for `protective-stop-capture.json` in its private
execution directory. Failure preserves evidence and does not grant acceptance
or auto-retry. Main should retain the failure and correct the failed gate.
Strict journal framing and the 15-second guard/50-second controller budgets
need actual qualification; passing static tests does not establish them.

## Explicit retirement

Main reviews and seals the exact successful capture with the Rust sealer. Do
not alter its source records, sealed startup packages or root. Invoke separately:

```text
LAUNCHER retire-qualification SEALED_CAPTURE CAPTURE_SHA SELF_SHA NEW_EXECUTION_DIRECTORY
```

Retirement validates the full capture graph again and requires the same boot,
exact retained producer terminal, idle original successful guard, stopped timer,
active non-activating retention target, absent token, absent original PID,
recursive kernel drain and unchanged pristine root. It checks the four installed
root-owned symlinks and their immutable target hashes against templates derived
from the original attempt, rejects runtime overrides/drop-ins, and records a
durable `retirement-before.json` before mutation.

Only these four links under `/etc/systemd/system` are eligible:

- `horizon-singleton-211-capped-4aeca563-v1.service`
- `horizon-singleton211-protective-v1.service`
- `horizon-singleton211-protective-v1.timer`
- `horizon-singleton211-terminal-retention.target`

The command stops only the empty retention target, rechecks drainage and native
owners, checks each link's inode/target again, unlinks those links, fsyncs that
directory and reloads PID1. All four units must be collected (`not-found`,
inactive, no job). A final kernel/root/token check precedes
`retirement-complete.json`. Sealed packages, private records, node/worker inputs
and qualification root contents are preserved. No reset-failed, archive
deletion, R2 operation or automatic production launch is performed. A partially
failed retirement retains its before proof and requires explicit diagnosis;
it is not silently broadened into generic cleanup.

## Main acceptance and production

Seal the retirement receipt and prepare a sealed
`horizon-singleton211-protective-stop-qualification-v1` with:

- `Main_accepted: true`, exact `gate` and `guard` bindings,
  `sandbox_permissions_verified: true`.
- `capture` and `retirement` bindings to those sealed receipts.
- Every ordinary false authority flag required by `no_authority`.

Bind it as `protective_stop_qualification` in the production prestart document.
Production admission validates the native sample, intent, completion, held
identity, sandbox/templates, original-clock PID1 ordering, four-link retirement
and exact capture relationship. It does not replace those checks with acceptance
booleans. Historical validation reads retained immutable templates directly;
it does not follow the deleted or subsequently reused installed unit links.

Prepare a fresh complete fleet review with `operation: "launch"` and a **new**
attempt namespace. All old immutable packages remain preserved. Production
launch must prove its own real first no-trip guard sample and same-PID node exec
before fleet/status registration. The experiment neither counts as replay nor
qualifies any archive or upload.
