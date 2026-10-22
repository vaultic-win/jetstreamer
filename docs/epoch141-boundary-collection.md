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
