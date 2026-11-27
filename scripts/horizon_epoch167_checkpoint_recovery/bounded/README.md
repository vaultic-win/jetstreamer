# Epoch 167 bounded checkpoint replay

The private route uses the existing 512 GiB epoch 167 tree, a 44 GiB producer, a 1 GiB guard and zero swap. It starts at the authenticated FR2 snapshot at slot 72,509,256 and verifies through the authenticated NY5 checkpoint at slot 72,515,090. The signed trace worker observes the historical mismatch within that interval. The result is a bounded diagnostic segment.

The producer is `horizon-qualify-167-checkpoint-bounded-20261127-v1.service`. The protective timer is `horizon-guard-167-checkpoint-bounded-20261127-v1.timer`, with the corresponding oneshot service. They are separate from the original drained epoch 167 invocation and its timer.

## Prepare

Use the existing HOME-backed checkpoint input leaf. Make `bounded-72509256-72515090-v1` inside that leaf, with separate `output` and `private` children. The three directories use UID 1001, GID 1003 and mode 0700. Create a root-owned 0600 `producer.log` in the run root before making the run root immutable. The children and append file remain writable. The guard measures all existing epoch 167 bytes, including this child, against the original 512 GiB cap.

Use `/var/lib/jetstreamer/horizon_runtime_data/epoch167-checkpoint-bounded-20261127-v1` as the root-owned mode-0700 state leaf. Create a root-owned mode-0755 `barrier` and mode-0700 `guard-receipts` there. Use a private root-owned working directory for the preparation outputs.

Prepare a root-owned JSON specification with schema `horizon-epoch167-bounded-replay-spec-v1` and digest references for `terminal`, `checkpoint_generations`, `closed_input_digests`, `worker_deployment` and `worker_provenance`. The checkpoint evidence is the exact bytes of `PINNED_SNAPSHOT_GENERATIONS.json`. The existing custody artifact is `167_SOURCE_DIGESTS.json`. The worker provenance uses schema `horizon-epoch167-bounded-worker-source-v1` and binds `binary`, `source_commit`, `branch` and `remote_contains_source`. Use the worker seal installed by the controller and the exact remote source commit proved by that controller.

Run `replay167.py --record PREPARED.json prepare SPEC SHA STAGING`. Its package plan seals the gate, payload and exact checkpoint list. The payload pins the node, trace worker, bootstrap, genesis and the existing qualified source range index by inode and SHA-256.

Use `adapt_capacity.py V31_SEAL_PLAN.json PROVIDER_STAGING` to generate the independent capacity seal plan. The adapter uses the V31 resource equation and adds the single held gate to the paired native census. It preserves the stopped epoch 167 and 170 bookings and serial epoch 185 restore commitments. Seal the generated capacity provider under its specified basename. The capacity request schema is `horizon-epoch167-bounded-capacity-request-v1`, with `fleet`, `capacity_deployment`, `full146_request` and `joint168_request` as exact path and SHA-256 references. Create the two incumbent requests from their current live guard samples.

## Guarded startup

Run each command as root with `/usr/bin/python3 -IB /path/to/replay167.py`. Record the artifacts in the state leaf. Use the exact file SHA-256 from each successful command when running the next one.

| Step | Command arguments | Result |
|---|---|---|
| Fresh prestart admission | `--record START_INTENT.json prestart PREPARED SHA PACKAGE_SEAL_SHA CAPACITY_REQUEST SHA` | Binds the candidate package and complete baseline, preserves the whole-tree booking and fixes the armed floor. |
| Held producer command | `argv START_INTENT SHA` | Emits the exact systemd argv. Submit after the controller enrolls the transition and serializes admission. |
| Fresh held admission | `--record HELD_CAPACITY.json held START_INTENT SHA` | Rechecks the complete incumbent census with the exact one-process gate and the original reservation. |
| Invocation-bound guard | `--record ACTUAL_GUARD_PLAN.json guard-plan START_INTENT SHA HELD_CAPACITY SHA` | Binds the approved floor, cap and exact held invocation. |
| Protective timer command | `guard-argv ACTUAL_GUARD_PLAN SHA` | Emits the exact guard timer argv. |
| First live guard | `--record FIRST_GUARD.json first-guard START_INTENT SHA ACTUAL_GUARD_PLAN SHA SAMPLE SHA` | Checks native timer, sealed command, journal, held PID, zero workers, and both complete tree walks. |
| Fresh post-guard admission | `--record POST_GUARD_CAPACITY.json post-guard START_INTENT SHA FIRST_GUARD SHA` | Rechecks the complete live census, guard, conservative physical measurement, HOME and RAM. |
| Invocation permit | `release START_INTENT SHA POST_GUARD_CAPACITY SHA` | Revalidates actor, guard and fleet, writes the root release receipt, then atomically creates the exact invocation permit. |

Use absolute paths for arguments. The argv commands print JSON arrays intended to be passed unchanged to the native command runner. A gate emits one `worker-ready` JSON record in `producer.log` and expires after 240 seconds if a matching permit never arrives. Once released, the gate execs the node at the same PID and start ticks. Continue through the controller’s first protected worker and progress checks.

The source checkout and both package plans must bind the same gate source bytes. The provider verifies this before running the held census callback. The controller supplies the fresh fleet, live guard samples, source containment and actual admission serialization.
