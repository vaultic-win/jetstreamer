# Capped 204/205 fleet and status compatibility

Source base: final admission emitter `84573d3d86c709318b3a592462cf8aa9327c6c27`.
The frozen node/control source `8f328729` and its artifacts are not edited.
No host observation, service action, admission, Bank run or R2 operation has run.

The deployed observer is binary `78dc39c3b8cf3e4198e6d2b35348ba764fe1c2ceecbd12cc536090ae8315facd`,
from source `3e932681` based on `42bac936`. This branch predates its output-file
and RSS additions. Its observer executable must not be built or deployed.
The shared `process_references.rs` source is identical to the deployed source.

The deployed replay observer requires one stable worker beneath the configured
scratch directory. Prefix reread, suffix validation and V4 assembly legitimately
have no worker. Its optional output-file evidence is closed to the two original
prefix units/IIDs/PIDs and cannot be borrowed by future continuation units.
An unavailable diagnostic observation is therefore not proof of inactivity or
zero resource use. The adapter leaves observer configuration and binary unchanged,
preserves old diagnostics, and consumes separately captured bounded metadata,
actual guard heartbeats and complete manager/terminal evidence in the same
30-minute campaign cycle. Explicit user status requests remain eligible for
out-of-band observations under the existing observer reason contract.

There is also a concrete frozen-control compatibility blocker. In
`historical.rs::bind_worker_executable`, the actual worker is a readonly copy
owned by UID 1000 at `scratch/.../bound-worker/historical-worker`.
The frozen control's `process_sample` instead requires the child executable to
equal `Plan.worker.path` and requires UID 0 for executable hashing. It would
reject that legitimate worker at native startup. A separately qualified shared
control correction must authenticate the actual copied inode/path, content
digest and process identity before a live launch. The status adapter does not
weaken or bypass this guard and does not assert that the frozen candidate can
already launch safely.

Public status phases are limited here to `replay`, `verification`, `upload` and
`readback`. ETA policy includes prefix reread, native restore and suffix replay,
suffix validation, assembly, independent full verification, current-plugin
verification, required boundaries/import, upload, readback/source revalidation
and sidecar commit. All estimates remain definite unsigned integers and best
guesses, never success or publication proofs.
