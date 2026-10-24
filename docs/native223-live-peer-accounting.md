# Typed live epoch 223 peer accounting

`fleet::prefix223_live_peer` is shared by candidate admission profiles. It
recognizes only the actual native20 full-prefix attempt:

- Unit `horizon-qualify-223-v1620-root-prefix-resource-full-v1.service`.
- Invocation `e70aaf097e7c4583b216aba454145910`.
- Original immutable launch
  `/var/lib/jetstreamer/horizon-native223-prefix-capture-actual-v1/launch.json`,
  SHA-256 `a629f2a5eb1a6be5e3ec38e66769f0698841fb7ccc8d43110ac3bfd73df99ac3`.
- Whole-root ceiling 471798691840 bytes; raw memory maximum 225000000000 bytes
  and high watermark 150000000000 bytes, rounded exactly by the kernel page size.
- Existing guard `044ccba7…` and its original 2000000000000-byte minimum-free
  baseline. The peer's own floor is preserved independently of candidate growth.

The module exports `roster`, `disk`, `memory` and `current`. Each candidate keeps
its own identity, input, native proof, resource cap and launch gates. Epoch
223's own admission roster and its self-overlap rejection are unchanged.

`roster` returns all recognized live owner names, including 223. The disk/memory
helpers authenticate the real registered diagnostic and immutable launch through
the existing prefix bindings, sandbox and first-guard provenance. Their internal
accounting view isolates only this already-accounted owner before calling the
existing reviewed peer arithmetic, then adds its reservation back. The accepted
fleet, all diagnostics, failed227 history, claims and unit census are preserved.
Unknown, duplicate, restarted, substituted or differently scoped 223 owners fail.

Disk growth is the whole-root envelope minus the smaller of the same-invocation
coordinated whole-root allocation and the current whole-root guard allocation.
Both scopes must be the exact run root, not `scratch/`. Missing observations,
old guards, wrong roots, budget exceptions and a tripped guard are rejected.
No synthetic post-launch sample or missing-telemetry credit is supplied.

Memory growth uses the actual cgroup hard cap minus its current charge. The
kernel maximum/high controls must equal the exact page-rounded raw requests;
swap must remain disabled. RSS cannot replace this remaining hard-memory claim.
`current` rechecks the original manager, command and effective sandbox while
the candidate's existing admission code brackets all owners, caps and actual
free memory/disk. It creates no new coordinated observer sample or host mutation.

Epoch 210 now uses these functions in its own admission and running capture.
It retains its original 300000000000-byte root cap, 128 GiB memory cap and exact
native harness/guard/cold-plan bindings. Its complete sample still requires a
real coordinated observation of 223. Observation339 predates that launch and
cannot be turned into such a sample; use the normal340 cycle or a later accepted
fresh complete cycle. This accounting does not qualify either epoch's runtime,
checkpoint, full archive, sidecar or publication.

Regression fixtures preserve the actual immutable launch, first guard and guard
plan. Tests exercise those static bytes, exact tuple rejection, complete owner
and failed-history preservation, whole-root observation credit and kernel memory
rounding without reading host resources or executing either replay.

The native210/native227 protected-cap snapshots also pass through the exact
full-prefix223 adapter. The original generic cap validator still checks every
other owner unchanged, including its strict128/112GiB native-auxiliary contract.
Only the authenticated original223 claim is split into the existing full223
sandbox validator, retaining its225GB maximum,150GB high watermark, zero swap,
8CPU quota,512tasks and exact control group. Its requested manager caps must
also match the immutable launch; kernel-rounded growth remains independently
validated by the existing memory adapter. The six-field cap snapshot includes
this owner and remains exactly equal before/after admission. A derived view
never replaces the accepted fleet or drops a healthy producer/history record.
