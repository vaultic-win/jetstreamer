# Closed full epoch 207 implementation

This route builds on `df57e9c041ab62f230c06cba4b95bf613ca6b2a4`. It does not change the producer, worker, native test, admitted MD5 candidate, actual metadata-only preflight, or original native proof. It does not broaden `native207` bootstrap qualification or any foreign runtime route.

The full output is exactly slots 89424000 through 89855999 (432000 slots). Bootstrap is 89423444, warmup starts at 89423445, supplied canonical accounts roots are 89523820 and 89855469, and 530 slots follow the last root. There is no invented root at the last slot and no epoch 208 tail.

## Closed commands

All commands use the existing `PLAN --plan-sha256 SHA --self-sha256 SHA` argument convention and independently validate immutable root-owned input plans.

- `prepare-singleton207-inputs`: rehash the exact existing node, production worker, cached bootstrap and genesis. Bind and revalidate the genuine admitted metadata, actual preflight and original native proof. Emit `inputs.json` in `/var/lib/jetstreamer/horizon-singleton207-inputs-*`. No service launch, Bank restore, resource sample or R2 action.
- `admit-singleton207`: require a separately root-reviewed source/sandbox/CPU readiness receipt and inputs from this exact R2 helper. Require the fresh complete fleet and observer, every guard, the real capped 204 continuation, all old failures and a clean coordinated expanded-fleet window. Emit a private admission only; do not start anything.
- `capture-singleton207`: capture the actual exact node, kernel/cgroup caps, original PID1 clock, copied worker digest and lifetime, actual completed first protective fire and waiting timer. Admission must be no older than 900 seconds. A plan alone is insufficient.
- `status-publish-singleton207`: use the accepted fleet and same coordinated 30-minute observer, or a single actual launch event, plus immutable evidence-backed numeric ETA model. Measure the PID-bound private cohort `.jet` while it grows. Refresh only `epoch-207.epoch-status.json` with authenticated readback. Preserve existing inactive-status and completed-pair cleanup policies.
- `capture-singleton207-terminal`: authenticate the original captured launch, actual terminal manager state and root-sealed exact producer/PID1 JSON-lines journal. Record natural success or failure without qualifying an archive, creating a canonical sidecar or permitting publication.

## Producer profile that root must prove before admission

Unit: `horizon-qualify-207-singleton-admitted-v1.service`.
Private root: `/home/ubuntu/.jetstreamer-private/qualification-207-singleton-admitted-v1`.
Precreate the root and empty `output`, `private` and `receipts` directories as canonical ubuntu-owned 0700 directories. The existing closed node creates its own PID-bound cohort tree beneath `private/destination-<output-path-sha256>/work/root-cohort-207-207/`.

Command (ordered argv is part of the binding):

```
/var/lib/jetstreamer/horizon-207-singleton-node-08e1-v1/jetstreamer-node 207 /home/ubuntu/.jetstreamer-private/qualification-207-singleton-admitted-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon-207-root-metadata-candidate-reviewed-20261025-sdk59001-v1/preflight207-singleton-candidate.json --cohort-manifest-fingerprint=sha256:9df04afe0f7ced39c179f2e5dafc34dac2aa6724fe1a8285b38cbfb528834db7 --snapshot-archive=/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/snapshot-89423444-3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px.tar.zst
```

Exact environment:

```
JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1
JETSTREAMER_HISTORICAL_WORKER_V1_6_16=/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/jetstreamer-historical-worker-v1-6-16-store8
JETSTREAMER_PRIVATE_RUN_ROOT=/home/ubuntu/.jetstreamer-private/qualification-207-singleton-admitted-v1/private
SOLANA_RAYON_THREADS=8
RAYON_NUM_THREADS=8
JETSTREAMER_HISTORICAL_POH_THREADS=8
TOKIO_WORKER_THREADS=8
RUST_MIN_STACK=134217728
RUST_LOG=info
```

The eight CPUs 16–23 are a proposal, not an allocation grant. Root must separately prove current CPU ownership and a disposable sandbox with `AllowedCPUs=16-23` and `CPUAffinity=16-23`. CPU quota alone does not bound the old runtime's CPU discovery or thread pools. TasksMax is 1024, rather than the old failing 512 ceiling. Producer MemoryHigh is 150000000000, MemoryMax 225000000000, swap is zero, quota is eight CPUs, runtime is three days, and file limit is 128 GiB. Exact remaining sandbox restrictions are enforced in source and the effective kernel values are captured independently.

The unchanged store8 worker is **not** the 209 shrink-budget worker. A 300 GB scratch trial plus 128 GiB file allowance gives the outer tree stop threshold; reserve an additional 32 GiB drainage and 32 MiB metadata. The guard stops at the actual own-tree limit or protected free-space floor. The route does not claim a full-cold peak qualification, resumable checkpoint or upstream shrink cap.

The standalone guard is the existing immutable `044ccba7` tool. Its exact protective unit is `horizon-singleton207-protective-v1.service`, receipt directory `/var/lib/jetstreamer/horizon-207-singleton-guard-receipts-v1`, and independent guard MemoryMax is 1 GiB. Root must prove static plan acceptance and the actual first completed fire before the launch receipt exists. The generic `horizon-qualify-` path is used; no native-main or bounded-stop exemption is permitted.

## Capacity and shared peers

The new checker shares only the current bracketed 225 GB producer + 2 GiB helper/native-223-floor resource arithmetic with first-root 233. The saved memory policy retains its historical `first_root233_memory_policy` key/schema for compatibility. This is resource evidence, never a 233 runtime qualification. Both sampled and actual brackets must fit the maximum obligations, including positively authenticated native-223 floor release, if any. No growth credit is granted for already allocated bytes.

The existing verifier-223 peer implementation is retained verbatim as `verification223_live_peer.rs`. The new outer `prefix223_live_peer` adapter understands only exact full-207 and first-root-233 claims in addition to those old peers. It preserves all raw fleet/observer/failure history, independently authenticates their diagnostic claims and latest completed guards, charges the complete disk reservation without allocation credit, charges producer hard-cap growth and each independent guard's full 1 GiB, and checks real kernel/manager limits. This lets the next qualified sibling admission retain either owner rather than dropping it from resource accounting.

## Gates that remain separate

Source, passing tests and a captured binary do not prove the root's source review, disposable sandbox, CPU assignment, actual new resource admission, producer start or first guard. Those must be performed and captured by the parent in order. Natural parent completion does not replace full archive checks, current-plugin checks, canonical root-cohort gate verification, boundary policy, authenticated whole-object upload/readback, sidecar commit or local-retirement rules. The terminal receipt intentionally grants none of those authorities.


## Successor correction: typed workerless Assembly

The initial 74e0739b generation passed 991 default and 991 all-feature tests and strict Clippy, but static review against the actual epoch 204 Assembly frame exposed a policy defect: the clean-window check demanded a historical worker from every active role. The successor narrows this for exact, authenticated typed capped Assembly only, in both full-207 and first-root-233 admission. An unavailable observer alone grants no exemption.

Two hash-bound accepted frames must identify the same producer/guard, admission, plan, PID and unchanged Assembly phase. The original phase start must cover the entire clean coordinated host-pressure window, the current frame/guard must reach its end, and both guards must have zero workers. A fresh capacity bracket cannot move that accepted owner backward into restore or replay. All existing conservative producer/guard hard-memory growth, full disk reservation, original 204 admission origin (1e1e generation), and positive native-223 terminal floor-release proof remain unchanged. Ordinary replay peers still require their complete stable one-worker observation windows. This correction neither restarts an owner nor rewrites historical admission or launch receipts.


## Successor correction: Assembly in resident-memory planning

The a7b79ed2 generation passed both 993-test suites and strict Clippy before the linked fleet-memory planning defect was identified and preserved. The final successor shares the exact typed Assembly proof with a separate host-sample mode: the phase must already cover that sample, without claiming a complete scaling window. Its unchanged producer/guard identities, prior accepted Assembly frame, and current bound guard remain mandatory.

An authenticated Assembly owner remains in the complete owner census and explicit evidence, but is not a historical replay lane. Its real PID must have the same positive start ticks and actual nonzero RSS in both whole-host snapshots. That RSS remains in whole-host overhead exactly once. It is neither invented as a worker sample nor subtracted as zero-growth capacity. Unknown, unresolved, foreign and phase-changing owners fail closed; ordinary replay census/RSS, the marginal average and 1.5x century maximum are unchanged. The actual new-lane admission separately still requires the complete clean 30-minute phase window and every conservative hard-memory/disk growth obligation.
