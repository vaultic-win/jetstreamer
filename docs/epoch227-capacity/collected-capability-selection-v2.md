# Exact selection-v2 collected capability adapter

This source adapter handles one genuine no-worker capability invocation whose
systemd terminal counters were collected. It is closed to the original private
UID 1000 / 0400 receipt, SHA
`a03d09115980dd7dac9859b7ca7f4ead616fc595759dbee44f527205065d3fae`, the selection-v2
capability plan, unit/sandbox, runner, node and worker identities. The original
positive-counter reader remains in force for every other capability namespace.
It never retries a capability, replays entries or reconstructs positive counters.

Existing immutable evidence suffices to implement this path. The initial
properties preserve PID 580417, positive start 1781970577079 and IID
`3bb301ecef9d455e97f8b353ceba7e25`. The sealed terminal properties preserve the
actual collected PID/start/exit/code zeros and empty current IID. The sealed
journal has exactly four genuine PID 1 rows: starting, successful deactivation,
finished with JOB_RESULT=done, and resource summary. All belong to the same
machine, boot, unit and invocation, with increasing clocks and journal sequence.
The unit and plan were sealed before that invocation. SHA-bound fixture copies
are included for offline tests; production reads only the fixed root-owned
immutable evidence paths, never those source fixtures.

At actual validation time, root must still supply genuine current state. The
adapter checks the exact installed unit hash and all recorded current sandbox
and command fields, plus loaded state, MainPID=0 and an empty cgroup. It requires
all current collected counters to match their genuine zero values. Historical
identity is emitted separately; the actual terminal map is preserved verbatim.

It queries the full current-boot unit journal without --lines, tail, since, or IID
filtering and requires exact parsed equality with the complete hash-bound sealed
journal. Missing retained history, extra rows, a later invocation, conflict or
failure rejects the adapter. Two journal reads and three identical manager
snapshots bracket validation. Current boot and machine must match the actual
historical journal. A unit reload, changed command/sandbox, changed original
receipt, surviving process or partial/positive counters also rejects this exact
collected path. No generic zero-counter relaxation or fabricated exit time is
introduced.

The result remains capability-origin evidence only. Fresh complete resource
admission, protected live runtime floors, genuine actual launch/IID, completed
first guard fire, active guard timer, captured launch, failed-epoch history,
terminal qualification, final archive verification and canonical sidecar gates
remain unchanged. The controlled target is not an epoch-completion checkpoint.

## Qualification plan

Source-only review and direct rustfmt / diff checks can run without Cargo. Wait
for the explicit shared Cargo grant after the holding-restoration and lifecycle
owners finish; do not contend with their target. Then use the shared absolute
target, locked offline release profile, incremental off and two jobs:

1. Run the canary227_capability tests, including five new collected-adapter tests.
   They pin the actual fixture bytes, preserve collected zeros, and reject changed
   receipt/plan/unit/artifact bindings, sandbox/current identity, missing/extra or
   conflicting PID 1 rows, bad ordering and malformed parsers.
2. Run the complete R2 test suite and strict all-target Clippy.
3. Commit the qualified source, build only the release R2 executable, and freeze
   a new candidate with complete tracked-file / literal dep-info provenance and
   build-time direct Rust/native input hashes before releasing Cargo.
4. Root reviews/seals the exact candidate. Root alone performs future actual
   metadata validation as part of fresh admission; no positive admission or live
   readiness is implied by the source fixtures or existing sealed evidence.

No Cargo, actual capability retry, host/resource poll, service operation,
Bank/snapshot/archive body read, R2 access or admission was performed for the
source-only implementation task.
