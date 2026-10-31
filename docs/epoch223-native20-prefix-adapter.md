# Exact native 20 prefix adapter

This adapter covers only the already sealed `d18fd429` supervisor, actual plan
`c293ceb8`, and unit
`horizon-qualify-223-v1620-root-prefix-resource-full-v1.service`. Its private root
is `/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1`.
It retains the431,523-slot prefix and477-slot uncovered suffix. The production
runner, worker, parent, input snapshots and previously armed jobs are unchanged.

The actual no-worker capability succeeded. Its root-owned immutable copy is
`/var/lib/jetstreamer/horizon-native223-full-prefix-capability-a2c01ef4-v1/capability.json`,
SHA256 `a2c01ef4188dd2b87e172b91dd3d705b877523f89dd407eff59d64f5e4c6964a`.
Both its exact full worker and the successful 58ab bounded warmup proof are
required. The native 25 prefix or first 16 worker cannot substitute for them.

The separate guard is sealed at
`/var/lib/jetstreamer/horizon-native223-prefix-guard-044ccba7-v1/jetstreamer-horizon-standalone-guard`,
SHA256 `044ccba70304c6d5690d2628c1ca08586462efdcc2d9f278903ee8bab0da6b3f`.
Its opt-in feature admits only the exact full-prefix unit, whole private root,
471,798,691,840-byte root envelope, 3.5M VMA bound, and floor at least 2 TB.
It rejects the capability owner and scratch-only300-GB substitution, native-main,
bounded-stop and measurement exemptions. Existing sealed guards remain intact.

## Admission and capture

`admit-prefix223-native20 SPEC --spec-sha256 SHA --self-sha256 SHA` accepts schema
`jetstreamer-private-epoch223-native20-prefix-admission-spec-v1` with `observer`,
`fleet`, `protected_guards` (a unit-to-bound-receipt map), and `output`.
Output must be `admission.json` in a root-owned private
`/var/lib/jetstreamer/horizon-native223-prefix-admission-*` directory.

The complete accepted census may contain only the exact unchanged 204,205,225
and full 227 invocations, plus the already authenticated full 209 and native 228
profiles. It refuses another active 223, an unknown owner, a restarted/replaced
old owner, missing observations or guards, and observed owners omitted from the
fleet. It selects each current completed protective fire through PID1 history,
requires the corresponding timer active, and preserves every existing guard's
floor. No derived arithmetic subcensus is published as an accepted fleet.

The optional 228 adapter reuses its native origin, exact live sandbox and guard
contracts, reserves remaining hard memory, and credits none of its300-GB scratch
cap. Reviewed existing 228 admission helpers account for the four old owners and
an optional full 209, including its exact whole-root allocation and raw-systemd
versus kernel-page-rounded memory gates. All input owners survive both live
censuses. Fresh free disk and memory bracket the repeated growth calculations.

The actual plan is fixed:225-GB memory max,150-GB high, swap 0, two Rayon threads,
CPU800%,480-GiB available-memory reserve,471.7987-GB whole-root envelope,2-TB
protected floor and2.4718-TB initial free disk. Admission also enforces the 90%
host target, 1.5x century RSS policy and existing pressure limits. If the sum of
century floor plus protected growth or any unchanged guard floor exceeds 2 TB,
this generation is refused. It does not lower a healthy guard, alter the sealed
plan or reuse an old observer after its30-minute validity expires.

`plan-prefix223-native20 SPEC --spec-sha256 SHA --self-sha256 SHA` is a separate
read-only admission-control entrypoint. Its sealed spec uses schema
`jetstreamer-private-epoch223-native20-prefix-planning-spec-v1` and only
`observer`, `fleet`, and `protected_guards`; there is no output-file field.
It prints a JSON report to stdout and performs no writes, starts, stops, or R2
requests. Root may preserve that stdout separately as private planning evidence.
The helper and spec must be root-owned, immutable, and SHA-bound as usual.

Planning reuses an existing accepted coordinated observation within its original
30-minute validity. It authenticates the complete owner roster and latest
completed protective receipts, then brackets the actual protected output-file
credits, whole-root guard credits, free disk, available memory, and complete live
unit census. These are admission-control checks; they do not run a new replay
poll, replace the accepted fleet sample, or change the routine polling cadence.
The report gives the minimum proposed protected floor, initial free-space
requirement, and actual and sample-inclusive disk/memory shortfalls. It takes
the larger of both growth brackets, preserves every inherited guard floor and
the original2-TB baseline, and retains the whole candidate envelope. Capacity
failures are reported as numbers; identity, freshness, pressure and evidence
failures still refuse planning. Reporting above 2 TB never changes the actual
admission command's sealed 2 TB refusal.

Saved 337 alone establishes bounds, not a current admission: even maximum legal
128-GiB output credit for each 204/205 and full observed whole-root credit for
227/209 require a protected floor of 2,087,041,699,031 bytes. Taking no unproven
current output or guard credit instead gives 2,523,170,868,439 bytes. The exact
entrypoint resolves this range using authenticated current receipts and actual
output allocations. It does not choose a new floor generation, edit a sealed
plan, or lower an existing healthy guard. If its computed floor exceeds 2 TB,
root must separately seal a new higher-floor plan, rebind the adapter's exact
plan path/hash and floor constants, and qualify that generation before launch.
The runner already accepts a plan's higher initial-free minimum; its internal
2-TB floor remains an additional baseline check and the separately sealed
whole-root protective guard must enforce the new higher floor.

After root separately launches an admitted owner and its protective service,
`capture-prefix223-native20` accepts schema
`jetstreamer-private-epoch223-native20-prefix-capture-spec-v1` with exact bound
`admission`, `guard`, `guard_plan`, and `output`. Output must be `launch.json`
under `/var/lib/jetstreamer/horizon-native223-prefix-capture-*`.
The protective unit is `horizon-native223-prefix-protective-v1.service`, with
matching timer and receipt directory
`/var/lib/jetstreamer/horizon-native223-prefix-guard-receipts-v1`.
Use the guard's default full-command description so its completed manager
history can be authenticated. Capture proves the real IID/PID, exact first
one-worker guard, whole-root scope, raw requested systemd caps and private
sandbox, then repeats the complete owner census. Historical capture bindings
remain independently revalidated when accepting the new diagnostic claim.

No admission or capture command starts a unit or mutates R2. Both retain
canonical-prefix/restart/suffix/assembly/full/plugin/publication gates as false.
The 223 repair remains open.

## Fleet, observation and status

Register the captured owner as a `DiagnosticClaim`, with epoch 223, the exact
unit/IID, whole private root as `scratch_path`, and hash-bound launch receipt.
Use the existing first-guard `admission_transition_guard` mechanism, preserving
all previous claims and gates. The fleet reports `private-known-root-prefix`,
never an ordinary replay or complete epoch. The generic coordinated observer
already supports this one-worker diagnostic; no new polling loop is added.
At the next normal observation add range`223-223`, bind controller and producer
to this same unit/IID, and measure the whole root. Do not fabricate a resource
sample for its launch event.

`status-publish-prefix223-native20 PLAN --plan-sha256 SHA --self-sha256 SHA`
uses schema `jetstreamer-native223-prefix-status-plan-v1`. It supports an exact
`launch-event` followed by normal `observation` models on the shared30-minute
cadence. It authenticates the real registered diagnostic and original monotonic
start, measures only its direct private `output/epoch-223.jet`, and publishes
legal `verification`/`replay` phases through the reviewed authenticated publisher.
Absent private output has size 0; symlinks or replaced/shrinking files are refused.

The all-stage estimate requires positive allowances for all 11 sorted keys:
`archive_close`, `assembly`, `boundary`, `full_verification`, `native_restart`,
`plugin_verification`, `prefix_reread`, `readback`, `sidecar_commit`, `suffix`,
`upload`. Finishing the known-root prefix therefore retains a positive estimate
for restart, missing suffix, assembly, independent checks and R2 delivery.
Rates may survive transaction/account counter resets only when the same slot
window is independently monotonic. Normal status reconciliation and inactive
cleanup recognize this exact receipt schema and owner; neither a missing status
nor a prefix artifact closes the repair.

Source tests cover the real saved capability, wrong worker/span/runtime and
premature authority, complete owner census, larger existing floors, overflow,
raw systemd caps versus page-rounded substitutions, direct partial archive
measurement, ETA phase transitions and all missing restart/suffix/assembly
allowances. At preparation time these new R2 tests were **not run** because root
reserved the Cargo window for228/full209. Explicit Rust formatting and diff
checks do not replace that build qualification. Request a build window before
compiling/testing/sealing the metadata helper or using this source operationally.

The shortest fully wired full-epoch delivery path may still be 209. This adapter
does not displace a healthy owner or claim a launch slot merely because its
source is prepared. Independent prefix reread, native restart/cursor mapping,
suffix and assembly, full/plugin checks, upload/readback and final sidecar
remain the separate gates described in `epoch223-native20-next-root-plan.md`.
