# Exact 204/205 sampled-output consumer and coupling audit

The new consumer is source-only on isolated branch
`epoch204205-output-credit-consumer`, based on `0036d820` and contract commit
`fd2bc1bb`. Its implementation is `93e00eb6`; no main checkout edit, live host
observation, archive scan, job, maintenance operation or R2 request occurred.
The final reference-tightening changes are included in that implementation.

Agent 207 agreed the exact 13-field `output_file` object and seven-field raw
metadata passes in `output-credit-contract.md`. The corrected producer source
is `3e932681`, directly based on the deployed `42bac936`; its sealed observer is
`/var/lib/jetstreamer/horizon-exact-prefix-output-observer-78dc39c3-v2/jetstreamer-horizon-observe`,
SHA256 `78dc39c3b8cf3e4198e6d2b35348ba764fe1c2ceecbd12cc536090ae8315facd`.
The earlier observer `ed8bc466...` is superseded and must not be deployed.
Root assigned the corrected observer the sole scheduled cycle 356 at 10:15 UTC;
this source task did not inspect or produce that future observation. No new
output allocation or fit is established by a source fixture.

## Separate selected admission profile

The legacy command, spec and old observer behavior remain unchanged:
`admit-canary227-v1625` continues its existing validated current-stat output
accounting. The new command is:

```
admit-canary227-v1625-output-metadata-v1
```

Its strict spec uses schema
`jetstreamer-private-epoch227-v1625-canary-admission-output-spec-v1` and mandatory
`output_metadata_profile: "sampled-output-204205-v1"`, alongside the same
observer/fleet/canary_plan/input_capability/resource_proposal/protected_guards/
output bindings. The new route rejects an old spec, a missing profile or a
fallback profile. The old route rejects the new field/schema. No blanket
change to all old metadata receipts or legacy resource handlers is introduced.

For every actual active exact 204/205 owner, consumption requires one successful
coordinated observation and one mandatory `observation.output_file`. It checks
original unit/IID/PID/start ticks, every original producer/controller RSS
bracket, exact output-only path outside the scratch tree, stable file identity,
mode/UID/link count, append-only logical and physical observations, all declared
booleans, raw min allocation and the original 128 GiB credited-output cap.
Unknown/omitted/unsafe fields fail the new route. A measured zero can be valid;
zero is never a fallback for missing data. Logical bytes only enforce the
append/truncation check and never become physical credit.

Actual admission reopens all path components with O_PATH/O_NOFOLLOW and pins
original descriptors while checking subsequent names. It reads metadata only.
The current producer command, original PID/start/IID/cgroup and zero restarts
are bracketed independently; replacement, parent/leaf symlinks, hard links,
truncation, wrong filesystem, current within-bracket physical regression and
cap excess fail closed. A physical reduction since the earlier sampled bracket
can only reduce credit, never inflate it. The final namespace reopen detects
replacement after the producer bracket while original inodes remain pinned.

The result is:

```
new_output_credit = min(sampled pass 1, sampled pass 2,
                        current pass 1, current final reference,
                        old validated live output credit)
new_growth = old_complete_growth + old_output_credit - new_output_credit
```

This **replaces**, rather than adds to, the existing output credit. It cannot
reduce the existing remaining-growth claim below the legacy algorithm. The
existing scratch measurement must match the same outer observation; whole-root
credits cannot be processed as separate output credits. Repeated consumption
of a decorated measurement is rejected. All other owner growth, original 225
baseline/reservation, complete owner census, guard set, capacities, metadata,
capability, VMA/pressure/memory checks and effective floors remain delegated to
the existing strict admission. In particular native 223's 2 TB floor remains
in `protected_floor`; neither 2.35 TB nor a reduced native floor is introduced.

The admitted receipt retains the existing schema for current capture readers
and adds the explicit profile plus complete before/after replacement evidence
only for this route. Existing admission retry recovery cannot cross profiles.
The source writes no admission until both actual before/after checks succeed.

## Park / maintenance remains a real gate

The new route requires an explicit terminal/absent park census entry with
original unit name, zero PID/restarts, empty cgroup and loaded/not-found
inactive/failed shape. A missing, malformed or live park entry is rejected.
Recorded live Foundation park/restore/retirement services are not silently
reclassified as replay owners. Existing fresh owner census also rejects an
unaccounted live competitor; the output extension does not weaken it.

This is **not** a concurrent park accounting adapter. It cannot promote the
live 6 GiB park into a zero-growth auxiliary or authorize a future maintenance
launch. Root must retain complete-owner/fresh-admission serialization for any
subsequent park/restore/retirement handoff. A source boolean is not a new lock
or runtime dispatch guarantee.

The already qualified cb69 Foundation maintenance route independently uses
`singleton227_admission`'s validated current physical output accounting. This
patch does not change that shared legacy function and does not require this
new observer/consumer to let an otherwise qualified legacy restore or
retirement proceed. Once a new canary is live, any subsequent admission still
must recognize its actual claim through a qualified peer reader; that is an
owner-coupling requirement, not a retroactive sampled-output prerequisite.

## Admission / capture / guard / peer coupling audit

- **Admission:** new selector/spec explicitly consumes sampled output. The
  retained old algorithm first validates complete owner/growth/guard accounting;
  the extension may only increase the resulting remaining growth by replacing
  a larger live-only credit with a smaller conservative credit. The same
  protected floor is required in resource plan/proposal and recorded admission.
  Before/after evidence and original observer/fleet hashes remain durable.
- **Capture:** `canary227_capture::protection` requires the bound actual
  admission schema, exact canary plan/proposal/capability, admitted floor and
  total incremental claim, unchanged owners, successful actual guard and
  admission-to-launch age no more than 900 seconds. The immutable captured
  launch retains the complete `fresh_resource_admission` binding, so the
  profile-specific evidence is not lost. Current capture does not independently
  replay the extension's arithmetic; it trusts that hash-bound qualified
  admission writer as it trusts the original writer. Its launch record does
  not copy the new profile field into top-level identity. Do not interpret that
  omission as permission to mix an unqualified writer or strip its evidence.
- **Guard:** the actual `90e6fe78...` guard contract binds the exact launched
  IID, new resource-plan hash/command, admission-derived free-space threshold,
  300 GB whole-root cap, VMA cap and cooperative target. It does not grant new
  output credit during replay and needs no independent output-metadata parser.
  Its actual first PID1 success and active timer remain separate capture gates;
  no planned threshold or source test supplies them.
- **Fleet event/history:** `canary227_event` rehashes the bound admission and
  carries the exact actual launch forward while preserving original failure
  and every other claim/gate. `canary227::launch_matches` and the generic
  diagnostic handlers recognize this exact selection-v2 namespace, not an
  arbitrary new epoch 227 owner. The new admission does not create a launch,
  fleet event or resource-observation replacement.
- **Status and terminal:** the current canary status/terminal modules bind the
  same launch and guard. Target 98091122 remains noncanonical; downstream full
  replay/verification/upload allowances and the original failed repair gate
  remain present. No archive sidecar or readiness is created by this extension.
- **Future competing admissions / maintenance:** the current
  `prefix223_native20_admission::roster` whitelist and shared growth/limit
  readers do not contain a general selection-v2 **canary peer** adapter. They
  safely reject an unmodeled canary rather than price it as zero. Existing
  launch recognition alone does not supply its complete future incremental
  growth or remaining hard-memory accounting. A future integrated generation
  must model the exact new canary before permitting additional simultaneous
  admissions/maintenance. Account whole-root growth as 300 GB minus the minimum
  of coordinated/current same-IID whole-root allocation, retain its separate
  16 MiB control metadata, and authenticate actual guard/timer/caps. Do not
  reuse full 210/full 227's 471.8 GB profile or peel the owner from raw evidence.

The consumer source therefore does not, by itself, justify canary deployment.
Before recommending launch, root still needs the actual future metadata receipt,
complete fresh guards and actual resource fit, park/maintenance idle proof,
qualified/sealed matching helper generation, exact plan/proposal/admission,
actual canary first-fire capture and an explicit policy for any later competing
admission until its peer accounting is qualified. No fresh proposal numbers or
future observer/admission/canary hashes are invented here.

## Final source qualification

Final consumer code, including the post-bracket namespace/reference tightening
and lint corrections, passed the full release R2 suite: **754 passed, 0 failed,
48 ignored**. This includes the six dedicated allocation/reference/park tests
and the new strict-vs-legacy admission selector regression. Strict release
Clippy passed for both production and test targets with `-D warnings`.
Rustfmt and `git diff --check` passed. Existing ignored operational tests were
not enabled. No production helper was built, sealed, deployed or executed.

Commands used the coordinated shared target with `CARGO_INCREMENTAL=0`,
`CARGO_BUILD_JOBS=2`, empty `RUSTC_WRAPPER`, and locked/offline release mode:

```
cargo test --locked --offline --release -j2 -p jetstreamer-r2
cargo clippy --locked --offline --release -j2 -p jetstreamer-r2 --bin jetstreamer-r2 --tests -- -D warnings
```

Cargo is released after those completed checks. The matching producer source
and this consumer remain distinct separately qualified generations; preserving
the wire contract does not permit replacing the corrected producer with its
superseded candidate or mixing unrelated admission/helper runtime identities.
