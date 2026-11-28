# Epoch 247 reboot adapter — source handoff

This standalone Rust program starts **only the first reboot recovery lane**, epoch 247.
It does not resume the interrupted bank. It preserves the old root, partial archive,
accepted input receipt and historical launch evidence. It uses the unchanged original
authenticated snapshot, node, worker and manifest in a fresh root. No GCS restore is needed.

No service has been prepared, started or modified by the source work. No R2 object is touched.
`REQUIRED-PATHS.txt` lists dependencies the controlling operator must preserve during cleanup.

## Exact booked resources

| Resource | Value |
|---|---:|
| Epoch | 247 |
| Fresh root physical cap | 506,191,984,640 bytes |
| Producer MemoryHigh | 167,361,060,864 bytes |
| Producer MemoryMax | 251,041,591,296 bytes |
| Control allocation, including 1 GiB guard | 1,610,612,736 bytes |
| Producer CPUQuota | 800% |
| Producer AllowedCPUs / CPUAffinity | 80–95 |
| Producer TasksMax | 512 |
| Guard CPUQuota / TasksMax | 100% / 256 |
| Worker VMA maximum | 3,500,000 |
| Start-pre sleep | 60 seconds |
| Original dynamic operator deadline | 50 seconds |
| Setup-child namespace readiness budget | 2 seconds |

Main must book the aggregate memory obligation and a positive century filesystem floor.
`required_initial_free_bytes` must equal `guard_minimum_free_bytes + 506191984640`;
the guard minimum must cover the century floor and Main's other ongoing disk obligations.
The fresh observer must report at least that initial free amount. The actual first guard
sample independently checks it before a startup token can exist.

## Namespaces

* Producer: `horizon-qualify-247-reboot-20261117-v2.service`
* Guard: `horizon-247-reboot-20261117-protective-v2.service`
* Timer: `horizon-247-reboot-20261117-protective-v2.timer`
* Root: `/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2`
* State: `/var/lib/jetstreamer/horizon247-reboot-20261117-state-v2`
* Static recipe seal: `/var/lib/jetstreamer/horizon247-reboot-20261117-static-v2`
* Actual-IID guard seal: `/var/lib/jetstreamer/horizon247-reboot-20261117-guard-v2`
* Tokens: `/var/lib/jetstreamer/horizon247-reboot-20261117-tokens-v2`
* Guard receipts: `/var/lib/jetstreamer/horizon247-reboot-20261117-receipts-v2`

These are one-shot namespaces. A failed attempt retains evidence and never automatically retries.
Main must review the actual unit state before dispositioning a failure, especially a failure after
the first-fire token was sealed. The adapter does not automatically stop, restart or delete anything.

## Qualification and deployment

Build and test with `CARGO_TARGET_DIR=/tmp/horizon-reboot247-cargo-20261117`, offline,
with at most two Cargo jobs. The crate has its own workspace and lockfile.

`emit-source-templates DIRECTORY` creates source JSON only. The supplied admission deliberately
has `Main_accepted:false`, no resource observations, expired timestamps and placeholder evidence.
It is not executable authorization. Its initial launch-plan path refers to source: replace it
with the final sealed launch-plan path and exact hash in the accepted admission.

Before preparation or launch, Main must inspect the source, independently seal the binary and
launch plan using the Rust deployment sealer, and supply a Root-owned hash-bound admission:

```
horizon-reboot247-launch inspect PLAN PLAN_SHA256 SELF_SHA256
horizon-reboot247-launch prepare PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
horizon-reboot247-launch preflight-launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
horizon-reboot247-launch launch PLAN PLAN_SHA256 SELF_SHA256 ADMISSION ADMISSION_SHA256
```

`inspect` is read-only. `prepare` creates fresh root state and seals/loads an inactive producer.
`launch` is the only command that starts it. A fresh admission may be used between preparation
and launch; each admission lasts at most 300 seconds and binds an observer under 1800 seconds old.
`preflight-launch` checks the prepared state and loaded unit without starting the producer. It
is available only for the exact first launch failure recorded under `state-v2/launch/failure.json`;
that failure occurred before a producer invocation or guard state existed. The follow-up launch
uses a distinct `launch-v2` evidence directory and preserves the first failure record.

Admission binds immutable owner, observer, fleet, capacity, complete census and interruption
evidence. `evidence_claims` names JSON pointers in those real evidence schemas. Each required
claim is compared with the actual hash-bound source value; merely hashing unrelated files cannot
satisfy the checks. Owner evidence must agree on boot ID, controller PID and start ticks; observer
evidence on time, total memory and available bytes; fleet and census on zero preexisting replay;
capacity on every booked numeric resource and floor. Main's normalized accepted decisions may
be used where existing raw schemas have no such field, but must carry the original source proofs
and Main must validate those derivations before setting `Main_accepted:true`.

The first-lane census rejects all busy Horizon/Jetstreamer/archive services except the exact
admitted launcher unit. Main must coordinate other control jobs so they have completed before
invoking the adapter. This is intentionally not a concurrent second/third-lane admission adapter.
It also rejects any live node or historical worker process and requires old 247–249 producers
and epoch247's old guard graph to be closed. Unknown property omissions fail closed; native
timers/not-found units may lack service-only PID/control-group properties.

During the original 60-second prestart, the adapter verifies the actual setup child, its mounts,
UID, capabilities and CPU affinity; binds the actual producer IID into a new guard plan; seals the
guard graph; observes its real first timer firing and Root/PID1 journal lifecycle; verifies the
fresh guard sample and typed next timer deadline; and only then seals the invocation-specific
startup token. This entire dynamic sequence retains the original 50-second deadline.

The output `guarded-startup-handoff.json` explicitly says useful transaction replay has **not yet
been observed**. Main must make the normal post-start actual-worker observation, reconcile fleet
and dashboard state, and adopt the persistent single 30-minute observation cadence. The protective
guard timer is a separate safety mechanism. All archive/plugin/boundary/publication gates remain.
