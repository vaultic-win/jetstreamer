# Epoch 136 corrected/capped inputs

The original136–139 cohort stopped at epoch136 slot59,183,097, entry197,
transaction113: canonical `ProgramFailedToComplete` versus the deployed worker's
`ComputationalBudgetExceeded`. Preserve its99,718,944,924-byte partial archive.
Its old `abe395…` worker lacks the corrected builtin table, as did the old141
worker. That provenance is a lead, not proof that corrected136 execution passes.

The sealed host package
`/usr/local/lib/jetstreamer/horizon-epoch136-capped-inputs-20261023-v1` binds the
corrected parent, capped v1.4.25 worker `fce05d55…`, genesis, original failure,
source manifest, checkpoint names and retained bootstrap. The1,930,905,776-byte
bootstrap at58,751,483 has SHA-256
`0d78ac8daa69790f984ccfaddb01b6a497eb05cc7222533b94b4353dd8abc767`.
Its MD5 matches the original manifest's generation1634786431177741.

Build `jetstreamer-epoch136-input-capability` from `jetstreamer-horizon-observe`.
The only CLI is `PLAN --plan-sha256 HEX --self-sha256 HEX --storage-capability`.
Run the sealed binary as the isolated `sol` user in its exact closed service and
private directory from the source constants. The plan schema is
`jetstreamer-private-epoch136-input-capability-plan-v2`, with only `schema`,
`unit` and `run_root`. All input paths and digests are compiled into the tool.
It rehashes every input, binds exact bootstrap/root generations and runtime,
verifies both checkpoint names, and fsyncs a no-clobber private capability
receipt. It launches no process, initializes no Bank, restores no snapshot and
samples no host resources. The normal coordinated observation remains separate.

The trusted post-bootstrap root is59,183,944 with accounts hash
`HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8`. Output from58,752,000 through
that root spans431,945 slots;55 epoch slots remain afterward. Root qualification
would not cover that suffix or prove a complete epoch. Input-capability success
does not qualify restore, strict reexecution of the failed transaction, canonical
checkpoint, scratch peak, replay launch, runtime promotion, full/plugin checks,
sidecars or R2 publication.

Before replay, freshly admit the exact invocation and install/prove its guard,
preserving all production reservations, live141 remaining growth and the century
floor. Account for output separately from scratch unless an actual whole-root
stop covers both. A stop smaller than the existing99.7 GB output cannot represent
a complete136 budget. A smaller experiment must remain explicitly bounded and
private; do not restart the old failed cohort or discard its retained output.
