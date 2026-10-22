# Epoch 223: read-only hard-fork metadata evidence

The exact epoch-223 singleton invocation `04ef9d97a36446d49b452d982cb0be46`
failed at slot 96,542,806, entry 40, transaction 0. Finalized RPC reports that
signature `2EZUUdThX1NSxiyFKnRS6Bn4ptkLAySmmCsQpVToH9MbjdkXEUYPLqzLumcLkG12FoNi4tNE2jrnxVfKigFNCdNu`
successfully voted for slot 96,542,804 and bank hash
`5x6cLLsvsEbgbQxQNPoT1LvbTfYrx22kpXyzRxLKAMN3`. The pinned runtime's vote
error `Custom(2)` is `SlotHashMismatch`. A missing externally supplied restart
marker is a hypothesis to investigate, not permission to force that hash,
ignore the vote, or repeat a replay without qualification.

Build the isolated `snapshot_hard_forks` example with the pinned Rust 1.51
toolchain from `historical-runtime/v1_6_20`, enabling only
`snapshot-hard-fork-metadata`. This optional feature exposes native serialized
bank metadata decoding; ordinary workers do not enable it. The example hashes
the complete immutable snapshot before decoding, uses the existing bounded
raw-tar guard, requires the recognized version and exact bank member/slot, and
writes a no-clobber, fsynced private JSON receipt. It neither extracts account
stores nor restores/freezes a Bank. Its receipt explicitly denies snapshot
verification, replay and publication authority.

The input snapshot path and SHA-256 and the running example's SHA-256 must be
bound independently through the normal immutable deployment. Use the retained
generation-verified pre-223 and post-restart snapshots to compare persisted
hard-fork lists. Metadata alone does not qualify inserting a marker into a
worker: review upstream hard-fork semantics, add regression coverage, retain
all canonical checkpoint/plugin gates, and use a fresh guarded qualification
before any runtime-route promotion or publication. Never change a live worker.

The retained partial epoch-223 archive lacks the normal footer magic; the
ordinary immutable verifier rejects it during opening even with zero selected
slots. That is expected incomplete-container evidence, not a full archive scan
or corruption verdict. Preserve the original bytes. Any diagnostic bucket
recovery or restarted prefix/suffix assembly needs a separate reviewed path;
do not synthesize a canonical footer or segment manifest to make it publishable.

On high-core hosts, run legacy tests serially with explicit bounded Rayon and
PoH thread settings. Parallel synthetic Bank tests can exhaust a test unit's
task ceiling; preserve such failures and diagnose their actual thread-pool
errors without altering production replay limits or ignoring semantic tests.
