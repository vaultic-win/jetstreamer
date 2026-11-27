# Epoch 167 bounded checkpoint replay

The private route uses the existing 512 GiB epoch 167 tree, a 42 GiB producer with a 40 GiB memory.high limit, a 1 GiB guard and zero swap. It starts at the authenticated FR2 snapshot at slot 72,509,256 and verifies through the authenticated NY5 checkpoint at slot 72,515,090. The signed trace worker observes the historical mismatch within that interval. The result is a bounded diagnostic segment.

The producer is `horizon-qualify-167-checkpoint-bounded-20261127-v1.service`. The protective timer is `horizon-guard-167-checkpoint-bounded-20261127-v1.timer`, with the corresponding oneshot service. They are separate from the original drained epoch 167 invocation and its timer.

## Prepare

Use the existing HOME-backed checkpoint input leaf. Make `bounded-72509256-72515090-v1` inside that leaf, with separate `output` and `private` children. The three directories use UID 1001, GID 1003 and mode 0700. Create a root-owned 0600 `producer.log` in the run root before making the run root immutable. The children and append file remain writable. The guard measures all existing epoch 167 bytes, including this child, against a cap of the measured retained allocation plus 48 GiB. The original 512 GiB booking stays charged.

Use `/var/lib/jetstreamer/horizon_runtime_data/epoch167-checkpoint-bounded-20261127-v1` as the root-owned mode-0700 state leaf. Create a root-owned mode-0755 `barrier` and mode-0700 `guard-receipts` there. Use a private root-owned working directory for the preparation outputs.

Prepare a root-owned JSON specification with schema `horizon-epoch167-bounded-replay-spec-v1` and digest references for `terminal`, `checkpoint_generations`, `closed_input_digests` and `worker_deployment`. Use a root-owned copy of `PINNED_SNAPSHOT_GENERATIONS.json` and the existing `167_SOURCE_DIGESTS.json` custody artifact. The worker seal must contain the exact trace binary and native worker build receipt. The preparation checks the worker commit against `origin/account-updates`.

Run `replay167.py --record PREPARED.json prepare SPEC SHA STAGING`. Its package plan seals the gate, payload and exact checkpoint list. The payload pins the node, trace worker, bootstrap, genesis and the existing qualified source range index by inode and SHA-256.

Use `python3 -IB adapt_capacity.py V31_SEAL_PLAN.json PROVIDER_STAGING` from the merged checkout to generate the independent capacity seal plan. The generator verifies the V31 member hashes, applies the tracked provider patch, and puts the exact merged `replay167.py` bytes into the provider as the held-owner callback. It verifies the four original holding-helper source hashes, runs the Rust tests, and builds the V32-capable release helper. The sources default to the `holding` directory beside V31's staged provider source directory. Pass `--holding-source V31_HOLDING_SOURCE` to use another copy with the same hashes. Seal the 81-member plan at its prescribed `tools-homefloor-170-full-metered-independent-v20-joint168-v31-replace167-reserve` destination.

A terminal joint 168 request retains the original 168 enrollment, growth and stop allowances, sets `mode` to `terminal` and `guard` to null, and adds the exact invocation's `terminal` receipt reference. The provider authenticates the exact native exit, requires the producer and guard units to drain, and keeps the booked cap and memory charges. The last accepted worker roster can anchor this transition before the next cadence records it when the matching protected invocation has genuinely exited and drained. Set `compute_release` to null to retain the old compute charge. For the scoped epoch 167 resource quote, bind `compute_release` to `{"unit":"horizon-168-joint-continuity-9d6a680157ac.service","invocation_id":"328366ba244949efb9c9725df7279051"}`. The provider validates the exact sealed comparator and its cgroup, preserves its 2 GiB and one CPU, and removes the remaining 58 GiB and one CPU from the retired 168 producer and guard charge. All disk bookings remain intact. A live joint 168 request uses its current guard sample. V32 READY and ACTIVE bind the exact V31 predecessor. The provider prices only these registered writer generations.

The provider includes the current fleet and 185 restore reservations in the HOME floor. It prices the bounded 167 run on top, using its prestart physical measurement and the 48 GiB growth limit. The whole-tree and HOME limits are fixed in the start intent and rechecked against fresh held and post-guard observations. The capacity request schema is `horizon-epoch167-bounded-capacity-request-v1`. Bind `fleet`, `capacity_deployment`, `full146_request`, `joint168_request`, and `replacement167_request` by exact path and SHA-256. Include `writer` with its `active` registration and deployment `seal` references. The provider checks the incumbent guard samples or the accepted joint 168 terminal receipt. The 167 scope binds 300% producer CPU, 25% guard CPU and zero swap.

## Guarded startup

Run each command as root with `/usr/bin/python3 -IB /path/to/replay167.py`. Record the artifacts in the state leaf. Use the exact file SHA-256 from each successful command when running the next one.

| Step | Command arguments | Result |
|---|---|---|
| Fresh prestart admission | `--record START_INTENT.json prestart PREPARED SHA PACKAGE_SEAL_SHA CAPACITY_REQUEST SHA` | Binds the candidate package and complete baseline, preserves the whole-tree booking and fixes the armed floor. |
| Held producer command | `argv START_INTENT SHA` | Emits the exact systemd argv. Submit after the controller enrolls the transition and serializes admission. |
| Fresh held admission | `--record HELD_CAPACITY.json held START_INTENT SHA` | Rechecks the complete incumbent census with the exact one-process gate and the original reservation. |
| Invocation-bound guard | `--record ACTUAL_GUARD_PLAN.json guard-plan START_INTENT SHA HELD_CAPACITY SHA` | Binds the approved floor, cap and exact held invocation. |
| Protective timer command | `guard-argv ACTUAL_GUARD_PLAN SHA` | Runs the sealed guard's static plan validation and emits the exact timer argv. |
| First live guard | `--record FIRST_GUARD.json first-guard START_INTENT SHA ACTUAL_GUARD_PLAN SHA SAMPLE SHA` | Checks native timer, sealed command, journal, held PID, zero workers, and both complete tree walks. |
| Fresh post-guard admission | `--record POST_GUARD_CAPACITY.json post-guard START_INTENT SHA FIRST_GUARD SHA` | Rechecks the complete live census, guard, conservative physical measurement, HOME and RAM. |
| Invocation permit | `release START_INTENT SHA POST_GUARD_CAPACITY SHA` | Revalidates actor, guard and fleet, writes the root release receipt, then atomically creates the exact invocation permit. |

Use absolute paths for arguments. The argv commands print JSON arrays intended to be passed unchanged to the native command runner. A gate emits one `worker-ready` JSON record in `producer.log` and expires after 240 seconds if a matching permit never arrives. Once released, the gate execs the node at the same PID and start ticks. Continue through the controller’s first protected worker and progress checks.

The source checkout and both package plans must bind the same gate source bytes. The provider verifies this before running the held census callback. The controller supplies the fresh fleet, live guard samples, source containment and actual admission serialization.
