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

Unit and preflight checks are preparation. Actual native cold-input proof,
fresh full-fleet admission, invocation-bound memory/free-space/VMA protection,
the bounded warmup comparison and eventual canonical-prefix completion remain
outstanding until their respective invocations succeed. A16-slot result is not
a measured full-prefix peak or an epoch archive.
