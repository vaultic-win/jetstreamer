# Complete epoch141 boundary collection

`jetstreamer-epoch141-boundary-collect` is the independent consumer of the exact
owner-bound full-census PoH diagnostic. It does not run while that diagnostic is
live or accept its provisional target files as completion. Its immutable plan
uses schema `jetstreamer-epoch141-census-boundary-collection-plan-v1` and binds
`diagnostic: {path, sha256}` plus an empty root-private `output_directory` directly
under `/var/lib/jetstreamer/horizon-epoch141-boundary-collection-UNIQUE`.

Both `--check-only` and `--run` require the exact diagnostic invocation at clean
terminal success, its complete 18,283-target/84,597-boundary manifest, original
owner intent, closed native acquisition and reviewed typed/native clock. They
independently revalidate the complete finalized metadata collection, including
every original request/response binding. Missing, failed, duplicate, reordered,
changed or differently owned inputs fail closed. No full plan can be bound
before the genuine diagnostic completion digest exists.

`--check-only` validates those complete top-level bindings and paths but does not
read target boundaries or write output. `--run` additionally checks every target
receipt against its exact raw-acquisition binding and finalized parent/hash
metadata. It requires complete canonical tick ordinals, exact clock-bounded PoH
work, the independently finalized final hash and global uniqueness across all
84,597 hidden/final boundary hashes. Failed groups never contaminate coverage.
Every diagnostic target is rehashed after collection, and all top-level/finalized
bindings and the terminal owner are rechecked before output.

The no-clobber outputs are `boundaries.json` with schema
`jetstreamer-epoch141-decoded-gap-boundaries-v1`, and `collection.json` binding its
digest and provenance. Each group records its visible target slot, finalized
parent and ordered `{tick_ordinal, hash}` boundaries. Counts must equal 18,283
groups, 84,597 total boundaries and 66,314 hidden boundaries. Output remains
private and explicitly grants no ancestry/liveness/source-completeness claim,
runtime-boundary use, replay, route promotion, publication, retirement or remote
mutation. A separate reviewed private runtime qualification and the ordinary
canonical-root/full/plugin/delivery gates still remain.

Use a separately sealed nonrestarting, network-denied sandbox with read-only
inputs and only the exact OS-filesystem output root writable. The collector
enforces a ten-minute execution bound, 32-MiB boundary output and 16-MiB result
caps within a 64-MiB output envelope above a 100-GiB OS reserve. It rejects the
Horizon data filesystem. A 1-GiB hard memory ceiling is sufficient for the bounded
metadata/hash-set collector; fresh admission still precedes launch. Interruption
preserves intent and any partial output: never erase or overwrite it to retry.

Retained first-target fixture tests prove only the consumer's five-boundary
interpretation, not complete-census success or runtime qualification. Source
tests and sealing alone authorize no collector launch or runtime deployment.

The routine monitor can retain a completed collection in the optional
`census141_poh.collection` binding. Adoption uses the distinct
`jetstreamer-census141-boundary-collection-monitor-handoff-v1` schema with the
unchanged original `launch` and exact `collection` bindings. It rejects owner
replacement, duplicate adoption, partial counts, altered source/output digests,
or any acquired authority. The helper rehashes the complete diagnostic and
collected boundary bytes. Its successor namespace includes `census141-boundaries`
and its repair next action advances to version-specific consumer/root
qualification; epoch141 remains failed-needs-repair, never remote-ready.

For a candidate readable bundle, seal the non-sensitive boundary JSON as a
root-owned0444 member beneath a non-writable0555 deployment directory, leaving
the original private tree and provenance receipt private. The deployment sealer
must independently copy/rehash the exact collected bytes with no replacement.
Readability and sealing do not authorize using the hashes in a production Bank.
The existing epoch208 consumer is v1.6.16-specific: do not transplant its runtime
shape assumptions into the v1.4.25 repair without checking this source's entry,
tick, parent-jump and canonical-root behavior independently.

## Pinned v1.4.25 Bank semantics regression

The test-only worker module `recovered_boundary_bank_fixture` uses the first
collected group's five distinct hashes (slot60911776, finalized parent60911771).
It normalizes that five-slot jump to a small synthetic Bank with the pinned
v1.4.25 implementation and 64 ticks per slot. It compares boundary-filled ticks,
different non-boundary tick hashes with identical boundary hashes, and the
incorrect final-hash-only construction. It checks hidden blockhash queue entries,
frozen Bank roots, and the next child's SlotHashes, not just the final blockhash.

Run from `historical-runtime/v1_4_25` with the pinned toolchain, `--offline
--locked`, and `RUST_MIN_STACK=134217728`; filter the worker test binary by
`pinned_bank_gap_boundaries_preserve_queue_root_and_slot_hashes`. Keep build jobs
and debug output bounded under the host's existing build policy.

This is a version-specific unit regression, not an epoch141 runtime consumer,
snapshot/root qualification, source-chain proof, or complete-census ingestion.
It wires no new runtime input, changes no production worker behavior, and grants
no replay, route-promotion, publication, or R2 authority. An actual source adapter
must still preserve transaction order, PoH verification and exact finalized
parent relationships, consume the complete authenticated census, and pass the
private canonical-root path before promotion is considered.

## Complete pinned-SDK read-only consumer diagnostic

The separately gated `epoch141-boundary-consumer-diagnostic` worker feature
builds `jetstreamer-epoch141-boundary-consumer`. Invoke Cargo from the historical
`worker/` directory: pinned Cargo rejects feature selection at the virtual
workspace root. The executable has one fixed input, the sealed readable candidate
`horizon-epoch141-boundary-input-candidate-20261022-v1/boundaries.json`, with the
independently pinned collected SHA-256 `e371b3546d62e5fdac79a497607b61ea2647c3c5d410157b3ff456709f78be4a`.
It accepts only `--self-sha256 HEX`, rehashes its running executable, opens the
input without following a symlink, and requires a root-owned, non-writable,
single-link regular file below the 32-MiB cap. Descriptor/path identity is checked
again after consumption.

Using the pinned v1.4.25 SDK `Hash`, it strictly decodes all 18,283 groups and
84,597 boundaries, enforces ordered in-scope targets and exact parent-jump counts,
requires canonical 64-tick ordinals and base58 encodings, and rejects zero or
globally repeated hashes. Synthetic complete-census tests also reject missing or
reordered targets, invalid parent arithmetic, wrong ordinals, duplicate/invalid/
zero hashes, foreign parents and unknown fields.

Run a separately sealed binary in a nonrestarting, read-only, network-disabled
sandbox; no credentials or writable campaign paths are needed. Its stdout is a
diagnostic result, not a durable qualification receipt. Preserve the exact unit
invocation, result, executable digest and stdout separately before using this
as qualification evidence. The program loads no Bank, executes no transactions,
reads no source entries, and is not connected to the replay worker. Full source
adaptation and actual canonical-root qualification remain independent gates.
