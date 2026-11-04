# Epoch 203 bounded prefix resource measurement

For the separately scoped natural-completion canonical-root attempt, see
[epoch203-root-prefix-resource.md](epoch203-root-prefix-resource.md). Its longer
target does not change these target-stopped benchmark contracts.

`jetstreamer-epoch203-bounded-resource` is a separate private measurement binary,
not a complete-prefix replay or complete-epoch qualification. Historical attempts
stopped at 16.10% and 64.35%; their outputs were retired on October 9. No complete
reusable prefix has been established.

Its compile-time profile pins:

- epoch203/bootstrap `87,695,515`, snapshot SHA-256
  `e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4`,
  length `8,142,103,526`;
- unchanged v1.6.16 store 8 worker SHA-256
  `3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a`,
  `SOLANA_RAYON_THREADS=16`;
- measurement target `87,720,000`, at most 1,000 observed slots of overshoot,
  and separately specified underlying canonical root `88,127,580`;
- maximum six-hour execution, 256-GiB captured physical scratch, and initial
  free space of at least `3,185,678,193,366` bytes. Fresh whole-host admission may
  require more; this constant is not proof that the work fits.

The separate `epoch203-single-thread-resource` utility feature keeps the exact
snapshot, worker, target, root and resource limits above, but pins
`SOLANA_RAYON_THREADS=1` instead of 16. It requires `r1` unit/run-root namespaces
and records the actual thread count in its result. This is a same-input storage
fan-out/throughput comparison, not a runtime change or full-prefix qualification.
The retained store 8 worker uses `min(rayon_threads, 8)` eager stores; compare the
new result with the preserved 16-thread run at equal slots/transactions, including
restore overhead, physical bytes, VMAs and phase timing. Do not extrapolate a
short-window saving into a full-epoch budget. The default 203 profile and both
225 profiles remain at 16 threads; healthy deployments remain untouched.

The immutable hash-bound plan uses
`jetstreamer-private-epoch203-bounded-resource-plan-v1`, with the strict fields
described for [epoch225](epoch225-bounded-resource-runner.md). It instead requires
`horizon-qualify-203-bounded-resource-*.service`, a direct private run root named
`bounded-resource-203-*`, and the exact epoch 203 snapshot/target/root above. The
checkpoint file must contain exactly the bootstrap and root snapshot names.
This cannot borrow or shorten the existing complete-span epoch 203 deployment.

The binaries share target-stop/capture mechanics, not scope. Epoch 225's fixed
profile, optional upstream-comparison feature, receipts and runtime bounds stay
unchanged. There is no arbitrary epoch/profile option. The epoch 203 binary
removes inherited v1.6.20/v1.6.25 worker overrides and selects only its exact
v1.6.16 worker.

Before launch: publish reviewed source, seal the runner/plan, bind parent,
snapshot, worker, genesis and checkpoint inputs, exercise the exact parent's
focused route and runner identity gate, and pass fresh CPU/memory/disk/VMA and
integrity admission. Use an isolated persistent non-restarting unit. A six-hour
bound cannot transfer another lane's memory reservation. Leave healthy replays
and already-sealed guards unchanged.

Use a separately sealed standalone guard's `bounded_canary` profile. It binds
the epoch 203 unit to the epoch 203 schema and target; an epoch 225 receipt cannot
excuse a missing worker. Preserve the strict pre-target worker census, reserve/
VMA stops, bounded drainage, capture digest and nonrenewable receipt pin. Prove
the first real sandboxed guard fire before unattended operation.

Record restore baseline, multiple settled 30-minute resource/useful-work windows,
and pre-shutdown terminal capture. Do not add another polling loop. Use results
to qualify a conservative nonlinear full-prefix envelope or specify the next
bounded measurement; do not extrapolate one early value into a full-prefix bound.
Even success grants no full cold-epoch peak qualification, runtime promotion,
canonical sidecar, public import, R2 operation or scratch retirement. A canonical
prefix, separately qualified 419-slot suffix and complete anchored/plugin scans
remain necessary for the proposed two-stage publication path.

The parent's focused planner separately admits a prefix ending at the retained
canonical root `88,127,580`: output starts at `87,696,000`, covers 431,581 slots,
and leaves 419 slots through `88,127,999`. A planner regression checks this exact
boundary and keeps ordinary epoch 203 runtime selection rejected. This is only a
planning capability, not evidence that a complete prefix exists, that the full
prefix fits, or that its native restart tuple has been verified. The epoch 213
continuation runner remains restricted to its exact epoch 213 artifacts; it cannot
execute or publish an epoch 203 continuation.

`jetstreamer-epoch203-resource-compare` provides a read-only, exact-attempt
comparison after the single-thread run's successful `receipts/resource.json`
exists. Seal it and a `jetstreamer-private-epoch203-resource-comparison-plan-v2`
plan with `baseline_path`, `baseline_sha256`, `candidate_path`,
`target_stop_sha256` and `target_capture_sha256`. Invoke the
binary as root with `PLAN --plan-sha256 HEX --self-sha256 HEX
--candidate-sha256 HEX`. The baseline digest and both attempt identities are
build-bound. The producer writes immutable UID-1000 receipts; preserve those
originals and use the Rust sealer with independently supplied digests to retain
root-owned `resource.json`, `target-stop.json` and `target-capture.json` under
`/var/lib/jetstreamer/horizon-203-r1-bounded-outcome-20261020-v1` before comparison.
The comparator pins those exact copy paths and cross-checks the target, child,
invocation, canonical capture hash and complete capture object. A missing
candidate receipt is a closed gate, not permission to substitute a live sample
or a failure receipt.

The comparator hashes stable, bounded, root-owned input files without following
symlinks, validates the exact same snapshot/node/worker and bounded target,
rejects failed or externally interrupted runs and memory/scratch safety events,
and prints private comparison JSON to stdout. Preserve that output through the
normal sealed-evidence workflow; the tool writes no files and performs no remote
operations. It reports total latency, first-progress latency, actual progress
window boundaries/rates, terminal work totals, physical scratch, file counts and
memory peak. Different first markers or target overshoot are visible, not
normalized away. It makes no production thread selection, nonlinear peak claim,
replay admission, runtime promotion, canonical sidecar or publication decision.

Fleet reconciliation accepts only the distinct
`jetstreamer-private-epoch203-bounded-resource-launch-v1` receipt for this run.
It pins the worker and runner digests, bootstrap/target/root, unchanged v1.6.16
semantics, live zero-restart invocation, and explicit false prefix/peak/promotion/
publication authorities. One same-sample admission report may use this profile's
exact newly sealed guard after its real sandboxed worker/maps proof. It still
must preserve all diagnostic history and cannot chain another event or authorize
another resource observation. Normal reconciliation must advance its observer.
