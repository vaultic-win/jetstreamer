# Epoch 265 selected-worker native lifecycle

This source adds a disjoint native265 profile to fleet capture, terminal proof,
status retirement and resource observation. Existing native211, native210-small,
native227-small and ordinary replay profiles retain their bindings.

The exact producer is `horizon-265-native-input-20261119-v1.service`. Its main
image is the sealed `horizon265-native-input-daa786c0-20261119-v1` standalone
harness, SHA256 `0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9`.
One direct child may use only selected worker `horizon-supported235-shrink-debt-e3f15eb2-v1`,
SHA256 `c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4`.
The private root is `/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1`.

`capture-native265-input` takes the same sealed-spec/self-digest CLI shape as
native211. The spec schema is `jetstreamer-native265-running-capture-spec-v1`,
with `startup_handoff` and `output`. Output must be
`/var/lib/jetstreamer/horizon-native265-running-*/intent.json`.
Capture validates the complete original admission/source/prestart/stop-retirement
and first-guard evidence graph, current sandbox, exact mapped processes, active
periodic protection and unchanged peers. It creates a zero-entry private claim;
no resource sample or launch/publication authority is manufactured.

Fleet accepts `private-cold-snapshot-verification` for the exact unit and epoch265.
The immutable running intent may join its original accepted resource sample as a
metadata event, using the native211 predecessor-preservation pattern. The new
claim cannot overlap an existing265 owner or change other gates/owners. Native265
remains a private qualification stage and never an ordinary replay lane.

`capture-native265-terminal` takes a sealed
`jetstreamer-native265-terminal-capture-spec-v1` with:

- `running_origin`, `journal`, `observer`, `fleet`, and `output` as in native211.
- `native_result`: an immutable copy of the actual root `native-result.json`.
- `guard_history`: an immutable `horizon-native265-complete-guard-history-v1`.

Terminal output is `/var/lib/jetstreamer/horizon-native265-terminal-proof-*/proof.json`.
Producer journal bytes belong under `horizon-native265-terminal-raw-*/journal.json`.
The harness completion message and successful PID1 event must belong to the exact
original PID/IID/boot and occur in order. The result must bind the original startup
plan/token, selected worker handshake, canonical slot114479281 accounts commitment,
zero checkpoint writes, unchanged write version, acknowledged shutdown and reaped
worker. Current producer and worker processes and their cgroup must be drained.

The guard-history document contains `guard_plan`, `producer_invocation_id`,
`boot_id`, `pid1_journal` and `records` (immutable bindings to all sample/terminal
receipts). Its PID1 journal covers every firing from the original startup through
a successful post-terminal drain firing. Every start needs a successful finish,
every firing a matching receipt, and live coverage gaps must stay below120s.
Terminal drain must retain both original process pins. Capture compares the
complete actual receipt directory against the bound records and rejects any trip,
transition, missing record, foreign process or unresolved outcome. Arrange a stable
post-terminal capture; do not erase or omit a guard transition to pass this gate.

Terminal fleet events preserve every original claim/reservation; inactive-status
cleanup accepts only the exact independently qualified native owner. This is
status cleanup, not memory release, local-data deletion, replay admission or R2
archive qualification.

Observer configuration uses epoch265, the exact producer, real IID/MainPID, root
path above and harness path/SHA. It observes either the harness alone or that
harness plus its exact direct worker, rejecting replacement images, changed starts,
extra processes and replay overlap. Main/child accounting remains resource-only.
The terminal-aware wrapper now accepts optional `native265_handoff` and preserves
that diagnostic unchanged; rebuild/seal the observer and update the wrapper's
`OBSERVER`/`OBSERVER_SHA` pins before deploying this path.

Source tests cover guard first-fire identity, direct-child membership, exact
result commitments, complete terminal guard history, terminal journal ordering,
peer preservation, status owner rejection, observer tuple and wrapper passthrough.
Main must run bounded builds/tests/Clippy, seal artifacts and publish exact source
containment before accepting prestart consumers. These sources do not establish
that native265 has run or qualified.

## Direct recovery after successful completion

The original native run completed successfully before its running-intent capture
was accepted. The terminal capture also accepts
`jetstreamer-native265-terminal-capture-spec-v2`: replace `running_origin` with
the original `startup_handoff` and a sealed `consumer_transition`. This route
never creates a retrospective running intent or renews a launch deadline. It is
restricted to the original invocation `ce5f66a82fdd4c0e93ca99f27b925112` and its
unchanged admission, token, worker and result.

The successor transition binds published source, the actual compiler argument
array, immutable build evidence and every original dependency. The sole added
dependency is the separately qualified full211 consumer library; its exact three
manifest changes are registered alongside its artifact and qualification receipt.
Retained native210/native227 modules are unconditional in this R2 crate, so the
transition preserves the actual predecessor feature set without inventing Cargo
features. Unknown dependency changes and unreviewed source changes still fail.

The deployed guard has a 60-second execution limit, which PID1 renders as `1min`.
Live checks and complete-history verification use that same bound. Its genuine
`root-pin.json` is validated against the original plan and retained root inode,
ownership and mode; unknown or trip artifacts remain failures.

After successful producer completion and process drainage, stop only the unused
guard timer and let any in-flight guard finish naturally. Keep the producer unit,
retention target, inputs and every receipt. Direct capture requires a stopped
timer, successful drained guard, exact complete PID1 history, all original guard
records and unchanged terminal identity before and after validation. The terminal
proof can join the existing fleet without fabricating an earlier active claim;
it grants no resource release, replay launch or archive publication authority.
