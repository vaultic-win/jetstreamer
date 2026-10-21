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
