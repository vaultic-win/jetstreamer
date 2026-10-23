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

The healthy225 worker and all sealed deployments remain unchanged. Before any
new223 chain experiment, build/seal the candidate with its exact historical
toolchain, requalify the native snapshot/input capability, and freshly admit a
bounded invocation with an exact guard. Preserve the old failed invocation and
artifacts. Use the captured transaction and canonical source metadata to resolve
the discrepancy; do not weaken loading, writability, fee collection, checkpoint
or full/plugin gates to continue replay.
