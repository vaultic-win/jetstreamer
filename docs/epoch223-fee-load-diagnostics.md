# Epoch223 native account-load failure

The retained cold-prefix invocation5c5a9e56… failed during warmup on the native
v1.6.25 result `InvalidWritableAccount`. Its wrapper reports that result through
`fee_collection_results`; the label does not establish a fee-payer defect. In
the pinned native `accounts.rs`, this error can identify a writable upgradeable
account without its loader, or a writable executable account. The failing
transaction and its observed bank accounts are needed before choosing a repair.

When `JETSTREAMER_HISTORICAL_TRACE` is enabled, a candidate worker now logs the
already-fatal transaction's signature, index, raw message header, effective
writability, invoked/passed account roles, native account owner, executable flag
and lamports. These are explicitly **after native commit** observations; other
transactions in that wave may already have committed. They are not preimages,
replay completion, or authority to skip a failed transaction. The original error
still terminates the request. The diagnostic builder only reads bank state.

The preserved invocation's journal places this failure in the initial warmup:
the rejected batch spans slot 96,335,539 entry 515 through slot 96,335,541
entry 5, before recording starts at 96,336,000. The next diagnostic should
therefore stop after that warmup window under a fresh bounded admission, rather
than attempt the entire epoch prefix. An in-flight entry's logged signature is
not necessarily the transaction that failed inside the batch; use the new fatal
load trace to identify the actual transaction and account state.

The opt-in `epoch223-fee-load-warmup-diagnostic` worker build admits only the
cold snapshot at 96,335,538 and entries 96,335,539 through 96,335,554. This
16-slot envelope covers the observed batch with room for parent batching while
staying below recording. It rejects the tail bootstrap and all later input
before bank mutation. The existing full-prefix qualification feature keeps its
original envelope; transaction execution and the fatal fee/load result are
unchanged. Build this candidate explicitly, since the shared Cargo release
filename can otherwise refer to a different feature set:

```sh
cd historical-runtime/v1_6_25
cargo build --release -p jetstreamer-historical-worker-v1-6-25 \
  --features epoch223-fee-load-warmup-diagnostic
```

This build is not launch authority. Bind the resulting exact binary in a fresh
native input qualification, isolated bounded supervisor, full-fleet admission
and invocation guard before a chain run. A scope-limit rejection instead of
the fee/load trace is diagnostic evidence, not successful replay or permission
to widen the window silently.

The healthy225 worker and all sealed deployments remain unchanged. Before any
new223 chain experiment, build/seal the candidate with its exact historical
toolchain, requalify the native snapshot/input capability, and freshly admit a
bounded invocation with an exact guard. Preserve the old failed invocation and
artifacts. Use the captured transaction and canonical source metadata to resolve
the discrepancy; do not weaken loading, writability, fee collection, checkpoint
or full/plugin gates to continue replay.

## Reproduced warmup and finalized transaction

On 2026-10-23, invocation `e94cafadd43a4ad1bacea7da20d2cb4b` restored the
cold snapshot and reproduced the native error at bank slot 96,335,539. Its
failure and complete journal are preserved under
`/var/lib/jetstreamer/horizon-warmup223-terminal-v4`; this attempt ended on the
native fee/load result, without a supervisor scan failure or a completed target.
The first fatal transaction is
`1waA5SJxAYc1BxmbgscTLfkYuvEUy6VeFpgNceqoYkGDMqLao6QQMZV2ewQ1vuUVEmXSj1GenoByrPtWxTqt6X9`.

The raw finalized `getTransaction` response reports the same slot, a successful
transaction (`meta.err: null`), fee 5,000, a legacy message, and header counts
1 required signature / 0 readonly signed / 4 readonly unsigned accounts.
Its exact response SHA-256 is
`11f1a2c2a5e9255f1b0100103a3f3e563c7ca4f0440278e1e6083f365afd2261`.
Preserve the raw bytes; do not roundtrip balance arrays through floating point.

The native post-commit trace records account index 8, the Token program
`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`, as executable, owned by
`BPFLoader2111111111111111111111111111111111`, writable, passed to an
instruction, and not a top-level invoked program. Index 18,
`9KEPoZmtHUrBbhWN1v1KWLMkkvwY6WLtAVUCPRtRjP4z`, is writable and executable
under the upgradeable loader. Both account keys match the finalized message.
The pinned v1.6.25 loader rejects the writable executable condition and also
rejects writable upgradeable-owned accounts without that loader in the message;
the pinned v1.6.20 loader lacks those rejection branches. The observations
support a historical runtime-boundary discrepancy, rather than a fee-payer
diagnosis, but remain post-commit observations rather than loaded preimages.

Do not repeat the unchanged v1.6.25 cold warmup or launch its long prefix.
Qualify a v1.6.20 prefix ending at the independently known 96,767,522 root,
including the independently audited hard-fork markers, or a genuinely supported
retained-prefix recovery route. Keep the v1.6.25 suffix comparison separate:
its successful tail does not qualify the earlier runtime. Cold-input capability,
SourceExact outcomes, canonical root, native restart/cursor mapping, assembly,
independent full/plugin verification and publication gates still apply. No
runtime promotion or completed-epoch claim follows from this diagnostic.

## Separately built v1.6.20 prefix candidate

The parent feature `epoch223-v1-6-20-prefix-qualification` selects the original
v1.6.20 descriptor and worker override. It accepts only focused epoch223,
bootstrap96,335,538 through the known96,767,522 root, and an isolated
`qualification-223-v1620-prefix-*` root. It rejects full-epoch/tail requests,
v1.6.25 namespaces, cohorts, inherited leases, maintenance/recovery entrypoints
and unrelated diagnostic feature combinations. Its planning-only
`--epoch223-prefix-preflight` traverses the actual no-worker runtime and both
canonical checkpoint gates. It neither restores a Bank nor authorizes replay.

The historical v1.6.20 worker's separate `epoch223-prefix-qualification`
feature closes input to that exact bootstrap and prefix. It caps shrink debt at
the pinned validator background-service bound; native account loading, fees,
transactions and Bank hash algorithms are unchanged. The narrower
`epoch223-prefix-warmup-diagnostic` build admits only the first16slots, rejecting
later input before transaction decoding or Bank mutation. Default historical
worker builds retain their original range and shrink behavior, and every
already sealed deployment remains unchanged.

An opt-in ignored test,
`runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment`,
loads the exact hash-bound immutable cold snapshot through this native worker,
restores the independently audited hard-fork markers, freezes at the bootstrap,
and checks its canonical accounts commitment, unchanged write cursor and zero
bootstrap writes. It prints the native tuple with integer formatting. Run it
only in a separately admitted, sealed128-GiB sandbox with an owner-only fresh
`native-input223-v1620-*/scratch` directory supplied through
`JETSTREAMER_EPOCH223_V1620_TEST_SCRATCH`. The separately built
`epoch223-v1620-native-input` observer supervisor may instead pass the literal
`/tmp`: the test requires a real tmpfs there, creates a fresh owner-only test
directory, and retains its lifetime through native load/freeze. That supervisor
keeps the 128-GiB hard limit, 112-GiB high limit, private 512-GiB tmpfs with one
million inodes, exact UID1000 child, complete protected-owner census and
15-second memory/tmpfs guards. Its separate native20 harness, unit and receipt
namespaces cannot borrow the v1.6.25 snapshot profile. Merely compiling this ignored test is
not native input qualification. The exact test executable, source/input hashes,
terminal journal and result still need durable evidence before an entry replay.

The separate `jetstreamer-epoch223-v1620-warmup-resource` binary pins the
v1.6.20 parent and first16-entry worker, its own plan/result/stop namespaces and
the `qualification-223-v1620-prefix-warmup-*` scratch prefix. Both warmup
binaries share storage guards and entry-bounded command construction; each
retains independent runtime, revision, executable hashes and worker override
checks in the actual planning preflight. The v1.6.20 warmup cannot qualify the
known root or borrow v1.6.25 evidence. Its compilation and unit tests do not
replace fresh coordinated admission and invocation-bound VMA protection.

The first16-entry v1.6.20 diagnostic also requires the hash-bound cooperative
parent stop. Only the exact sealed narrow worker enables this stop; the full
prefix worker does not. The parent splits its transport batch after96,335,554,
without adding that slot to the canonical checkpoint set. After SourceExact
outcomes, account writes and the complete-slot response have passed, it requests
orderly shutdown, emits the private completion marker and stops itself. The
supervisor freezes the full process group, captures resources, then resumes and
drains it. Periodic warmup progress alone cannot trigger a successful capture.
The worker still rejects slot17 before decoding or mutation; neither the stop
nor the diagnostic resource receipt qualifies the known root or publication.

The separate `epoch223-v1620-root-prefix-resource` utility profile prepares the
full native20 prefix using the exact long worker and both canonical roots. Its
300-GB scratch planning allowance is separate from output, host reserve and
other owners' growth; it does not inherit the older25 worker's shrink-debt
reservation. A planning-only `--storage-capability` requires the actual parent
pre-worker barrier. The independent prefix rereader binds the native20 private
namespace to that full worker and revision and rejects the first16-slot worker
and native25 substitutions. Neither profile can claim restart, suffix,
assembly, full-epoch verification or publication. Keep the full prefix dormant
until the bounded warmup and fresh full-fleet admission/guards pass.

## Native20 bounded warmup registration and dashboard lifecycle

The sealed `horizon-223-v1620-warmup-envelope480-v1` package pins the
cooperative parent and first16-entry worker. It reserves a 300-GB scratch
increment, starts only above 2.3-TB free disk and 608-GiB MemAvailable, and stops
its own group below the protected 2-TB/480-GiB floors. The actual systemd owner
requires 128-GiB maximum/112-GiB high memory, zero swap, no restart and the exact
private scratch/output root. This envelope admits the three unchanged
204/205/225 owners, with either the exact registered live native207 or its
independently authenticated successful terminal207 proof and a complete census
showing only those three remaining owners. The optional native207 path retains
the same reserves. Full227 or any other live owner
requires a fresh complete claim calculation; this package is not approval to
reuse an old census.

`admit-warmup223` and `capture-warmup223` accept the separate
`jetstreamer-private-warmup223-native20-admission-spec-v1` with exact `observer`
and `fleet` bindings. The admission checks the accepted sample, full owner
census, existing guards, native20 input proof and planning capability. Capture
requires its genuinely running invocation and fresh invocation-bound VMA/disk
guard before it writes `launch.json`. The event retains `entry_replay:true`,
the existing private-warmup fleet phase and all unqualified archive gates.

Immediately reconcile that captured launch into the existing accepted resource
sample, then publish one generic pipeline status model through
`status-publish-pipeline`. Its wire phase is `verification`, its claim phase is
`private-warmup-reproduction`, its origin is the immutable native20 launch, and
its elapsed clock is the actual PID1 invocation start. Measure the exact
`output/epoch-223.jet`: absent means zero bytes; an actual empty or partially
written regular file is measured as such. Do not fabricate a zero-entry native
test receipt. Include evidence and a positive current best estimate through
prefix, suffix/restart, assembly, full/plugin verification, upload and readback
to the canonical sidecar.

Guard admission and native20 capture select the latest completed oneshot from
its PID1 manager history. A guard's current `InvocationID` may name a newly
started invocation whose `sample-IID.json` is not written yet, or may already
be cleared. Require the exact start, printed receipt, successful deactivation
and completed job events for the selected invocation, with matching unit,
boot identity, receipt bytes, ordered clocks and the existing freshness bound.
Bind PID1's full finished-job command to the immutable executable hash and
current exact `ExecStart`; any available kernel `_EXE`/`_CMDLINE` must agree.
Those optional kernel fields can disappear when a short guard exits before
journald reads `/proc`. Keep the default `systemd-run` command description for
this guard so PID1 preserves its full command. Preserve that history in
admission/launch evidence.
An incomplete newer invocation does not hide the latest completed success; a
later failure or protective stop prevents fallback to an older success. The
existing guard fingerprints, producer identity, timer and resource gates still
apply unchanged. This is a guard-history read, not another resource poll.

Refresh that same status model only from each existing 30-minute coordinated
observation, with its current fleet bindings and measured file size. Do not add
a second polling timer. At `resource.json`/`failure.json` or actual manager
termination, stop publishing its old countdown, retain the loaded terminal unit
long enough to capture genuine terminal fleet evidence, and promptly invoke
the ordinary authenticated, conditional inactive-status cleanup if no active
replacement/handoff exists. Keep the status for an evidenced active downstream
owner instead. The warmup result is not an uploaded epoch: canonical completion
still requires all independent archive gates, and completion cleanup follows
sidecar commit.

### Native20 terminal-event adapter

`capture-warmup223-terminal` consumes a sealed
`jetstreamer-warmup223-native20-terminal-spec-v1` with `running_origin`,
`observer`, `fleet` bindings and an `output` named `proof.json` under a fresh
root-private `/var/lib/jetstreamer/horizon-warmup223-native20-terminal-*`
directory. Run it only after the existing `systemctl start --wait` handle or
another genuine manager event reports termination. It reads manager history
and terminal metadata, without taking another resource observation.

Capture preserves exact journal bytes and the actual resource/failure output
no-clobber, retaining its original path and digest. A failed invocation with
no output records confirmed absence rather than inventing a failure receipt.
Success requires its original registered launch, exact bounded worker/input
fingerprints, clean manager termination, successful resource receipt and the
verified complete-slot marker. Failure and cleared-IID termination are supported.
The earlier unregistered failed startup is retained as separate hash-bound
operator/manager/journal history. Every full-prefix, native-restart, suffix,
assembly, full/plugin, runtime-promotion, sidecar and R2 gate remains false.

The metadata event keeps the accepted observer sample and all existing owner
claims. Only epoch223's next action/evidence may advance; its repair gate stays
`failed-needs-repair`. The inactive adapter authenticates that event and the
original status owner even if systemd cleared its IID, rejects live/restarted/
replacement owners, and rechecks latest PID1 history for a later invocation.
Ordinary conditional status deletion, authenticated absence, repair-backlog and
no-active-handoff checks remain mandatory. Terminal metadata never counts as
archive or sidecar completion.

Unit and preflight checks are preparation. Actual native cold-input proof,
fresh full-fleet admission, invocation-bound memory/free-space/VMA protection,
the bounded warmup comparison and eventual canonical-prefix completion remain
outstanding until their respective invocations succeed. A16-slot result is not
a measured full-prefix peak or an epoch archive.
