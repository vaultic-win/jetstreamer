# Epoch 136 parent launcher and waiting-status registration

This parent handles the two file events emitted by the epoch 136 admission writer. Run its normally sealed executable from the parent's charged metadata service, using the controller plan and normal deployment receipt selected for the admission. The controller source and immutable payload must already be on `account-updates`.

Before starting the writer, provision the private, root-owned mode-0700 directory `/var/lib/jetstreamer/horizon_runtime_data/epoch136-parent-handoff-20261121-v1` on the HOME filesystem. Reserve the exact bytes of the fleet and download receipt mirrors, plus the waiting-fleet output and small event/intent files. Keep the input sources and the cadence's status receipt tree accessible to the privileged reader. The publication adapter needs the same authenticated endpoint and credential inputs as the existing campaign cadence. Registration also needs to enter the live writer's mount namespace with its pinned process root.

```sh
parent136 prepare-inputs "$fleet" "$fleet_sha"
parent136 inspect "$writer_plan" "$writer_sha" "$controller_seal" "$seal_sha"
```

`prepare-inputs` pins the fixed historical snapshot download receipt and the exact fleet selected for this writer. It creates root-owned, immutable content-addressed copies and verifies their bytes on reuse. The actor receives these files read-only at their original paths along with the sealed controller at its canonical path. `inspect` checks the actual sealed writer and reports the host controller, current request/reproduction presence and prospective base unit arguments. The final command acquires its fleet-specific mounts after admission.

After the 145 owner qualifies for the complete current fleet plus the bounded 136 diagnostic and a current full fit succeeds, the parent metadata service can drive both events from the same execution. Run this pair in its existing charged, R2-enabled service immediately after preparing the immutable input mirrors. Supply the tested root-owned writer launcher and the verified parent image.

```sh
"$writer_launcher" session "$writer_plan" "$writer_sha" "$fleet" "$fleet_sha"
iid=$(systemctl show -p InvocationID --value horizon-admit-136-actual-20261120-g1.service)
exec "$parent" dispatch "$iid" "$writer_plan" "$writer_sha" "$controller_seal" "$seal_sha"
```

The dispatcher binds the live writer PID, process start time, cgroup, image and command to that admission's invocation. It waits for both file events, runs launch and registration, and verifies the original writer's final node-spawn release. A pidfd detects writer exit during any wait. Stage both commands after a completed cadence with enough time for admission and input staging. The parent needs R2 connectivity, the existing three credential environment variables and permission to enter the writer's mount namespace. Select these in the already charged parent service. The writer can keep its private network namespace.

The commands below support inspection and one-time recovery.

- On `BASE/parent-launch-request.json`, run `preview` to print the exact unit arguments or `launch` to start the admitted 3-CPU, 68-GiB payload. The request binds the writer session, its full plan and the strict eleven-field payload projection. A durable intent precedes the one-time systemd submission. Retain any uncertain launch for native inspection.
- On `BASE/reproduction/receipts/parent-status-request.json`, run `register` immediately. The writer allows up to 90 seconds to receive registration, bounded by the admission and ready deadlines. The parent takes the upcoming status cycle's actual lock while its timer is idle, publishes the six-field verification forecast using the authentic prior ETag, and verifies the conditional result through authenticated readback. The parent releases the lock after the durable authenticated event receipt. Its evidence is `r2-status-receipts/event-136-waiting-<payload-invocation>/RECEIPT.json`. The waiting fleet preserves the original resource totals and actual-worker arrays. The parent returns the registered evidence to the unchanged writer, which repeats its full native prefire and capacity check. The payload requires its own genuine worker guard before Initialize.
- After an uncertain PUT, `parent136 reconcile` reads the same object and recovers its event receipt if the durable intended bytes are present. It reports an unchanged predecessor or a mismatch separately. This command also works after writer expiry. An expired waiting actor still requires the writer's normal native recovery sequence.

The offline fixture `qualify_projection.py FLEET SHA FIXTURE_PARENT` exercises the deployed cadence's forecast and event chain against genuine predecessor evidence. It uses a private directory on HOME or a verified HOME-backed loop device and simulates only the candidate status. Its output identifies the original authenticated receipt, preserved fields and negative cases.
