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
