# Production 136 parent handoff

`admit136 session PLAN SHA FLEET SHA` is the complete in-process donor/admission
writer. It preserves one writer invocation and the same exclusive operation lock
through donor fencing, initial admission, the payload's genuine guard prefire,
parent status registration, a second complete capacity fit and immutable
`parent-release.json`. The parent still launches the previously qualified payload
under its existing exact actor envelope and owns every authenticated R2 operation.

This source is prepared for an **exclusive window without 169 or 172**. Existing
evidence budgets 59.25 CPUs before the 136 actor/guard/writer and 63.5 after them.
The 169 actor and guard alone add another 4 CPUs: at least 67.5 on the 64-CPU host.
No independently proven donor CPU credit exists. Retained memory remains
810,658,050,048 bytes; the 171 actor's 68 GiB and 1 GiB guard reservation fund
136's actor plus the two 512 MiB guard/writer shares. All retained donor disk,
peer, audit, auxiliary, OS and historical obligations remain. No 172 closure is
treated as resource or disk credit.

Use `admit136 cpu-preflight FLEET SHA` to inspect the CPU reservation for a
concurrent epoch 136 run. It checks the 43-core historical booking against
its four original producer invocations and the standard epoch 169 retry, then
reads the current focused 169 owner and both PID 1 unit inventories. The report
lists the closed standard launch routes and the proposed 4.25-core allocation.
It takes no lease. The existing session continues to require its exclusive
topology until a compatible writer and guard can enforce the loan.

The new topology check binds the exact post-172 closure and requires its producer
and guard to remain drained. It refuses live 169 actors/guards, while the existing
shared operation lock excludes concurrent 169/172 admission. The complete native
fit still rejects unknown worker owners and requires fresh peer/fleet evidence.
It does not stop another actor to open this window.

The native 136 denial PASS at 13:03:20 UTC is pinned by path and hash. It proves
the exact node/worker reach the pre-Initialize Hello barrier and accept denial.
The controller refuses to interpret it as affirmative worker-guard qualification,
snapshot restoration or replay. The already-built production payload independently
checks the real worker's image/credentials/PID/start ticks, waits for a new genuine
guard sample containing exactly that worker, measures the whole run root and then
sends `R`. That code and the original 7,396-slot reproduction are unchanged.

Run the sealed controller in its intended read-only mount namespace to check the
current production plan and fleet before scheduling the writer.

```text
BASE/controller/admit136 preflight PLAN SHA FLEET SHA
```

Preflight checks the installed controller, payload provenance, donor ancestry,
whole donor root, production topology and complete native fit. It exits nonzero
at the first failed gate. A successful result describes the sampled conditions.
The writer repeats the full initial fit immediately before fencing 171 and again
after the exclusive donor handoff.

## Integration sequence

1. Parent applies this source to `account-updates`, builds/tests it in the retained
   serial build slot, publishes it, verifies remote containment, and normal-seals
   the new controller. The payload package must bind the genuine native PASS in its
   artifact proof and retain all exact input, worker, source and historical pins.
   A previous sealed controller cannot execute the new mode.
2. Qualify the PID1 donor fence with the existing `qualify-pid1` mode under the
   parent's booked native allowance. Prepare the exact BASE/controller and tools
   packages; leave the reproduction root absent. Qualify the intended writer and
   payload mount/capability envelopes. Existing source-mode tests do not prove this.
3. Prepare the parent's status hook before beginning the 180-second handoff. Start
   `admit136 session PLAN SHA FLEET SHA` as the fixed `WRITER_UNIT`, exactly
   512 MiB, 0.25 CPU, 64 tasks and zero swap. Use `Restart=no` and an execution
   bound long enough for staging plus the 900-second admission. Include the actual
   native PASS and post-172 closure in the writer's read-only evidence mounts.
4. The controller emits `BASE/parent-launch-request.json` after genuine admission.
   Parent launches the exact admitted payload, binding the emitted admission hash.
   The payload stages its signed inputs, arms the production guard and emits
   `reproduction/receipts/ready.json` only after successful zero-worker prefire.
5. The controller verifies the waiting payload and the current timer-driven guard,
   then writes `reproduction/receipts/parent-status-request.json`. Parent publishes
   the genuine epoch136 status and records the waiting owner in the fleet. Use the
   exact metadata contract below. It must remain a repair/verification status;
   neither the node nor historical worker has started at this point.
6. After authenticated readback, parent normal-seals immutable copies of the status
   proof and fleet if their original files are writable. Run the metadata-only
   response, inside the parent's existing charged metadata allowance:

   ```text
   BASE/controller/admit136 register-status PLAN SHA STATUS_RECEIPT SHA CURRENT_FLEET SHA
   ```

   This validates genuine parent evidence and the original live writer/ready owner,
   then atomically writes `reproduction/receipts/parent-status-registration.json`.
   It does not acquire the session's admission lock, launch an actor, publish R2,
   perform a capacity booking, or open the node gate. The session gives this step
   at most 90 seconds, bounded by ready+175 seconds and admission expiry.
7. The original writer consumes that registration, repeats the full original fit
   and donor lease checks, verifies current guard/owner again and writes the exact
   `parent-release.json` consumed by the existing payload. Only node spawning is
   authorized. Worker Initialize remains gated inside the unchanged payload.
8. Preserve every failed generation. There is no automatic restart/reissue. Return
   donor fencing only with the existing `release` mode after actual candidate,
   guard, writer drain and admission expiry. A written source packet is not a run.

## Public audit compatibility

Run `admit136 audit-owner FLEET SHA` as the writer identity to qualify the read-only
audit check independently of donor availability. The production fit uses the same
check before and after its disk measurement. For public playback, expose the sealed
observer package, its launch and predecessor receipts, audit state, deployed audit
binary and config, and native systemd, proc and cgroup information to the writer.
The controller verifies the public launch, PID, start ticks, executable, command
line, cgroup, shared four-CPU slice and fleet inventory. Full-range playback streams
archives with zero archive staging. The fit retains the 16 GiB working allowance,
2 GiB Cargo allowance, existing HOME floors, memory, CPU and all replay obligations.
Earlier download-mode fleets retain their exact archive and process checks.

## Parent evidence contract

Let `REQUEST` and `READY` be exact path/SHA bindings to the emitted request and
ready receipt. Both parent status proof and updated fleet must include the same
`epoch136_pending_owner` object:

```json
{
  "unit": "horizon-qualify-136-actual-20261120-g1.service",
  "invocation_id": "ACTUAL_PAYLOAD_IID",
  "helper": { "path": "EXACT_HELPER_PATH", "sha256": "EXACT_HELPER_SHA" },
  "ready_recorded_unix_seconds": 0,
  "ready": { "path": "READY_PATH", "sha256": "READY_SHA" },
  "parent_request": { "path": "REQUEST_PATH", "sha256": "REQUEST_SHA" },
  "node_spawned": false,
  "worker_spawned": false,
  "repair_open": true,
  "ordinary_replay_claim": false
}
```

Populate the timestamp from the actual ready receipt. Both documents also carry
`epoch136_registration_unix_seconds`: the real status registration time, at or
after ready and no more than 120 seconds old. The status proof must bind epoch
136, key `epoch-136.epoch-status.json`, `producer_invocation_id`,
`current_repair_owner: "/root"`, `authenticated_readback: true`, nonempty readback
ETag, 64-character digest, and actual `after_status` with epoch136 and phase
`verification`. These are fields on the durable parent proof, not new required
dashboard body fields. They must describe the actual conditional write/readback.

The fleet's `effective_status_receipts["136"]` points to the exact immutable proof
being consumed. Set `all_active_status_reports_authenticated_readback: true` only
with genuine evidence. Keep complete memory/DATA totals, all reservation endings,
three live-owner arrays and the terminal172 closure identical to the accepted
input fleet. The waiting136 helper is registered separately; adding it to a
replaying/bootstrap/private-worker array before spawning would be false.

`register-status` supplies the existing payload wrapper schema and fields. The
session independently revalidates them against the exact ready/request before
releasing. Its release records `initialize_authorized:false` and
`positive_worker_release_still_required:true`; these do not relax payload checks.

## Required checks before integration

Seven new regression tests cover native denial versus positive qualification,
pre-spawn identity, missing/foreign/tripped guard samples, authenticated owner
registration, stale/crossed status, post172 zero-credit closure, and concurrent
169/172 rejection. Run these with all existing donor tests and strict Clippy in
the parent's booked slot:

```text
cargo test --locked --offline --manifest-path scripts/horizon_epoch136_donor171_20261120_v1/Cargo.toml --target-dir ADMITTED_TARGET -j1
cargo clippy --locked --offline --all-targets --manifest-path scripts/horizon_epoch136_donor171_20261120_v1/Cargo.toml --target-dir ADMITTED_TARGET -j1 -- -D warnings
cargo build --locked --offline --release --manifest-path scripts/horizon_epoch136_donor171_20261120_v1/Cargo.toml --target-dir ADMITTED_TARGET -j1
```

Also run the already-existing production payload test
`first_real_guard_requires_the_actual_worker_and_fresh_invocation`. A real positive
production-worker gate, restoration and original target comparison remain native
work after source tests, publication, normal sealing, exclusive admission and
current status registration. No affirmative production execution is claimed here.

## Writer and payload plans

Pass the complete controller plan to `session` and `register-status`. The parent
launches the sealed worker helper with the plan path and digest in
`parent-launch-request.json`. The helper accepts exactly eleven plan fields.
For an extended controller plan, the writer emits the corresponding immutable
`BASE/payload-plan.json`. An existing eleven-field plan retains its original
path and digest. The capacity receipt binds both plans. The admission and the
payload's launch receipt bind the actual payload plan, and status registration
checks both bindings against the same writer session.

To inspect the exact projection from a root-owned plan, run
`admit136 payload-plan PLAN SHA`. This prints the payload JSON without taking
a lease. Before activation, exercise the installed helper with the planned
mounts. Its input checks require root-owned files with no write mode bits.
The live fleet and historical snapshot download receipt may be mode 0600.
Bind root-owned, byte-identical immutable copies at those exact paths inside
the helper's read-only mount namespace and retain their digests and custody
evidence. Expose the same sealed controller image at its canonical path.

## Concurrent six-peer operation

For a concurrent session, supply both `standard169_cpu_loan` and
`joint_fit_145` in the full writer plan. The first binds the historical
standard epoch 169 route and its 4.25-core loan. The second binds the sealed
145 capacity executable and deployment receipt. Preflight reports the
prospective fit while the original six-owner exporter is active. Each
activation step requires positive support from the actual 145 process and
its native guard. The gap between export and publication retains the
activation hold.

The writer checks CPU and the complete joint fit before fencing, again after
fencing, on admission, and after the waiting helper's guard prefire. All
standard 169 routes must be masked and physically drained. The focused 169
worker keeps its own reservation. The loan covers the 136 helper, guard and
writer within the 64-core total and leaves 4.75 standard cores reserved.
The 145 guard computes remaining candidate disk from the protected physical
root. The sealed helper also requires the original admission free-space
floor on its post-prefire call.

Run the fixed writer service from the host using the normally sealed controller
and current fleet bindings.

```sh
run-writer preflight PLAN PLAN_SHA FLEET FLEET_SHA
```

This diagnostic runs at the writer's quarter-CPU, 512-MiB, 64-task limits.
Read systemd's journal for the resulting JSON. For an admitted schedule, first
have the qualified parent prepare the immutable copies of this fleet and the
historical download receipt, and have the launch and registration handlers
ready. Use the same arguments with `session` in the coordinated admission
window. The writer rechecks the full fit and fences, writes the request, and
waits for the parent. The registering process enters the writer's mount
namespace, so that namespace also projects the immutable initial fleet at its
original path. The worker and its guard retain their own service limits.


The seven-compatible 145 provider is the normally sealed
`epoch145-publication-20261121-v1/joint-tools-v2/export145`. Bind both its
actual ELF SHA-256 and its deployment receipt in the new immutable writer plan.
The provider qualifies a separately materialized historical worker by its
staged executable, identity and contents. The 136 helper, node, source worker
and original denial receipts retain their original pins. Use the existing
parent and actor with the new controller projected at the helper's established
path. An initial fit and a waiting-worker fit still require six authentic
incumbents, the live compatible 145 phase and its common lock. The original v4
encoding process is ineligible. A five-incumbent terminal-166 successor needs
its own topology qualification before admission.
