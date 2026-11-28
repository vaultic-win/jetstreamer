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

The first immutable metadata audit failed closed at the original 128-MiB bank
member bound. A separate bounded tar-header inspection found the retained
pre-223 bank member is 209,733,719 bytes; the corresponding retained post-restart
member is 222,117,899 bytes. The diagnostic-only cap is therefore 256 MiB,
with the one-past-cap rejection regression retained. This changes no
ordinary snapshot restoration limit or replay semantics; qualify a new auditor
generation and preserve the initial failed audit.

The next audit rejected the real tar ordering: its version member follows the
bank member. The metadata reader now buffers at most the bounded bank member,
finishes the guarded member census, validates the recognized version, and only
then decodes the bank bytes. No accounts are extracted. Regressions cover both
member orders and missing, unsupported, and duplicate version/bank members.
Preserve the second failed audit; neither failure establishes a hard-fork list.

On high-core hosts, run legacy tests serially with explicit bounded Rayon and
PoH thread settings. Parallel synthetic Bank tests can exhaust a test unit's
task ceiling; preserve such failures and diagnose their actual thread-pool
errors without altering production replay limits or ignoring semantic tests.

## Observed metadata and candidate correction

The sealed v3 auditor succeeded against both retained snapshots. The pre-223
receipt SHA-256 is `a046d0b4fdb856dd55a87cf3c7cf3486817d22d3259023bf027b7b3aba4f831b`;
the post-restart receipt SHA-256 is
`3b49f4f5d1c108feedba0a5b1bbce1a5bbc35e71bbd02a76a323eb6906bfe152`.
Both are in the host-private `horizon-snapshot-fork-metadata-receipts-20261022-v1`
directory as `pre223-v3.json` and `post225-v3.json`. The former contains markers
13,334,463 and 53,180,900, each with count one. The latter additionally contains
**both** 96,542,804 and 96,542,805, each with count one. The decoded pre-223 Bank
hash matches the original successful bootstrap checkpoint. Metadata is not a
replacement for full snapshot verification.

The same sealed auditor also inspected the exact tail bootstrap at slot
96,767,522 (snapshot SHA-256
`dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1`).
Its private `horizon-223-tail-hardfork-audit-20261022-v1/metadata.json`
receipt SHA-256 is
`b56472075e586b61af0e56796e7d91c8fe6a14900bc13fa599a7206cf8dbed75`.
It contains all four markers, each with count one, parent slot 96,767,521,
and serialized Bank hash `EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB`.
This independently confirms the tail's persisted marker list; it does not
verify the snapshot accounts, freeze a Bank, or qualify the 477-slot replay.

The v1.6.20 candidate now restores these known future markers after loading a
verified snapshot and before creating child Banks. It first validates the whole
list: reject unknown markers, counts other than one, and any absent marker that
should already have applied at the snapshot slot. Only then register missing
future markers. Existing markers are never registered again, and an already
frozen snapshot Bank is not rehashed. This uses upstream `HardForks` and Bank
hash semantics, not an injected hash, fabricated PoH boundary, or ignored vote.
Regressions bind the observed pre/post lists, both adjacent restart boundaries,
the two-marker parent jump, idempotence, and fail-before-mutation behavior.

This remains an unqualified correction until the fresh guarded replay crosses
both restart slots, reproduces canonical transaction outcomes and the terminal
root, and passes the normal independent archive/plugin/publication gates.
Keep the original failed invocation and archive preserved; no source change or
unit test closes the incident or authorizes a sidecar or upload.

Do not blindly reuse the old complete-epoch launch after this correction. The
retained `horizon-qualify-224-singleton-bounded-8a4f843-v3.service` journal
independently records v1.6.20 failing at slot 96,767,526, entry 8, transaction 7
(signature `3RrSHaC4s6asQJAY3b62dXL5YDRGVTDwqqwtS623RpTwx9648RiwHyYq6BecDGfMHqMGkRPLJEgwhehmM8M6vPTr`).
That warmup slot is actually in epoch 223's final 477 slots, beyond its trusted
root at 96,767,522. The later v1.6.25 epoch-224 invocation starts from that root.
Its existence is not an epoch-223 suffix/assembly qualification. Before a new
long replay, bind a complete prefix-through-root and separately qualified
suffix/assembly path, or establish a single worker that demonstrably passes
both boundaries. Never spend another full replay assuming this marker fix
also fixes the distinct later compatibility gate.
