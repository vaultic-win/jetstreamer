# Recovery epoch 204 context across a terminal canary event

Source-only successor of qualified b7d12bd8. No Cargo/build, target/cache access,
source staging, runtime, new resource/guard poll, body read or R2 mutation occurs.

The genuine cycle 414 terminal event fleet is
`/var/lib/jetstreamer/horizon-canary227-terminal-fleet-cycle414-be9b-v1/fleet.json`,
SHA 6170afad4acfada22a12d90f4707183074d0345e6851828ad656864e520bdceb.
Its sealed plan is in the separate matching `horizon-canary227-terminal-fleet-spec-`
directory, SHA 8a297d54269860acaa7abfb3fe70a8e23fab21550bf365c6bc516da78f80da50.
Its metadata_event directly binds the real canonical canary proof, SHA
dc1472406b789b4f44a455a31bb4330685c656b4b3d75957f3777d26464fcd02.
The prior fleet is genuine recovery cycle 414, a116a2b4662a2fe47b0b5e26cf8b5299dfd95406bed089349a04a7e7446df298.

The existing reader accepted only canonical fleet paths and private recovery
204 event paths, and required plan.json/event.json beside the latter. Merely
adding the canary fleet prefix would therefore still reject its real sealed
plan and direct proof layout.

This patch adds one exact event kind: a root-private fleet.json under the
terminal-canary fleet namespace, a separately sealed plan.json with the exact
same suffix under the fleet-spec namespace, and the canonical proof.json path.
Nested paths, empty or foreign suffixes, alternate filenames, generic events and
foreign proof/plan bindings fail. Recovery event rules and writers stay unchanged.
The actual fleet remains root-owned mode 0600 in its canonical mode-0700 parent;
its single-link file hash/identity and parent identity are rechecked. Plan/proof
inputs retain strict root-owned canonical single-link non-writable sealed reads.
The patch does not copy this fleet into a canonical namespace or rewrite it.

Historical traversal reuses the existing shared canary predecessor validator,
including real launch/result/journal/cleared-PID proof and failed-repair/no-credit
checks. It passes the actual accepted fleet recorded_unix_seconds as the original
transition time. A later read cannot invalidate genuine historical evidence
merely because the event is older than five minutes; original event timing must
still be valid relative to its own proof and predecessor. Current WorkContext
observer freshness and live peer checks remain separate and unchanged.

An additional shared raw-plan projection check preserves every original field,
including future unknown fields. Only output, previous_fleet, metadata_event and
the exact gate 227 evidence/next_action fields may differ; the existing typed
predecessor validator independently constrains those gate changes. Recovery 204
claim, history, frame/ETA, observer, clocks, unrelated gates, floors and guards
must be exactly unchanged. Predecessor traversal remains iterative, detects
cycles and accepts mixed recovery/canary chains only through these explicit
validators. No generic fallback or resource/ownership release is introduced.

Tests use pure schema fixtures, never an actual terminal success. They exercise
real historical recorded time, mixed private lineage, raw claim/history/guard
preservation, namespace and paired-plan rejection, canonical proof path/digest
substitution, observer/clock mismatches, unauthorized credit/failure-erasure,
foreign IID, and an event that was already too old at original acceptance. The
runtime callback is always the real shared saved_predecessor validator; fixture
callbacks do not qualify launch/result/journal evidence. Existing canary proof
and recovery current-context tests remain required in bounded QA. All new tests
are unrun until root reviews and transfers the target lease.
