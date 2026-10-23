# Epoch203 capped-shrink canonical-root diagnostic

`jetstreamer-epoch203-shrink-root-prefix-resource` is a separately opt-in profile
of the existing native root-prefix supervisor. Build with
`epoch203-shrink-root-prefix-resource`. It pins the same parent (`025757b9…`),
bootstrap87695515 (`e4558485…`), 16 Rayon threads, output start87696000 and
canonical terminal root88127580. Only the worker changes to the separately tested
upstream shrink-budget-cap candidate (`4aeca563…`). Old binaries and profiles are
not replaced or relabeled.

The 24,485-slot bounded comparison reached observed slot87720002 under that
worker, snapshot and parent. Physical scratch was63,036,743,680 bytes versus
172,458,995,712 baseline bytes; wall time increased14.5%. These are measured
diagnostic results, not a full-prefix resource or canonical correctness proof.
Settled routine windows showed47.2,52.0,57.5 and63.9GB scratch and roughly307k
VMAs. The late growth rate increased, and the run recorded943 memory-high events.
Keep those uncertainties in any fresh admission; do not promote a lower budget
or increase concurrency from the short comparison alone.

Retain the existing768-GiB terminal scratch bound,72-hour runtime bound and
3,185,678,193,366-byte startup free-space minimum. The scratch bound is enforced
while collecting terminal evidence, not by a periodic whole-tree scan. A separate
invocation-bound actual-free-space/VMA guard remains mandatory and must preserve
all older growth claims, the current century floor, and independent archive and
buffer components. Any stricter launch floor must be sealed in fresh admission;
this binary does not calculate or authorize fleet capacity.

Plans and results use the separate `epoch203-shrink-root-prefix` namespace;
run roots begin `shrink-root-prefix-resource-203-`, and units begin
`horizon-qualify-203-shrink-root-prefix-resource-`. The native runner waits for
natural successful parent completion and validates the complete producer manifest
for431,581 output slots, the exact worker, and canonical terminal accounts hash.
It preserves independent checkpoint, manifest and resource evidence and denies
ordinary replay, complete-epoch qualification, publication, sidecars and R2
mutations. No419-slot suffix is authorized merely because this prefix completes.

Before launch: seal the package and exact plan, capability-probe the actual parent
and worker, obtain a fresh complete routine observer/fleet admission, and bind and
prove the new guard's first real sandboxed fire. Preserve all earlier partials.
After natural success: independently reread the full prefix and qualify the
native restart tuple,419-slot suffix, private assembly, complete current-plugin
and publication path. This root diagnostic alone closes none of those gates.

The Rust `jetstreamer-prefix203-completion-dispatch` can perform the closed
one-shot reader handoff. Its path event watches only this producer's durable
`receipts/root-prefix.json`; it authenticates and stops its own watcher before
admission, preventing retries or a persistent-path spin. A clean terminal owner
and exact manager success event, unchanged producer result/manifest/archive
identities, absent sidecar and prior validation, and the pinned reader/unit
files are mandatory. It does not scan or qualify the archive itself.

The dispatch plan binds a fresh routine observer and complete fleet, including
the unchanged225owner, thirteen canonical size samples, and optional exact
cold223snapshot verifier. It reserves the complete128GiB cold-test cap plus
8GiB reader/4GiB dispatcher above the448GiB host reserve, and protects225's
640GiB remaining growth plus the century floor on disk. Live producer, stale
observation, changed ownership or any failed gate stops the handoff; it never
restarts or stops a producer, edits guards, retires scratch or touches R2.

Only a fsynced root-owned `ready.json` and successful dispatcher exit permit
systemd `OnSuccess` to start the separately sealed independent reader. The
reader's own receipt remains the independent integrity event. No419slot suffix,
native restore, assembly, sidecar or publication is authorized. A deliberately
triggered negative qualification while the producer is live must prove no
reader launch and that the watcher stops; afterward rearm only with a separately
sealed fresh plan, preserving the failed probe journal.

The distinct v2 dispatcher also accepts the observer's exact zero-worker
diagnostic for this203producer during its post-worker segment reread, but only
after independently reproving current clean natural terminal state and the
exact manager success event. It does not turn that unavailable worker sample
into replay progress, a valid ETA or terminal proof. Complete fleet bindings,
fresh global resources, the fully observed unchanged225owner, archive/result/
manifest identities and all independent reader gates remain mandatory. A
permission error, changed owner, another missing worker or stale sample is still
fatal. Keep the v1 deployment immutable; install v2 with separately sealed fresh
observer/fleet copies and requalify the negative live-owner sandbox before arming.
