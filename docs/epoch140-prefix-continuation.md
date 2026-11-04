# Epoch 140 private prefix continuation: qualification work

The original 103,138,915,297-byte archive remains unchanged and private. Its
independent full PoH scan and separate anchored ordered-chain pass succeeded.
The chain receipt is `horizon-private-anchored-chain-verification-v3`; it does
not establish a complete prefix manifest or authorize continuation/publication.

The intended retained prefix is slots 60,480,000 through 60,911,751 inclusive
(431,752 slots). The remaining suffix has 248 slots through 60,911,999. Native
snapshot restoration matched the cut's consensus tuple with zero bootstrap
writes, but the actual suffix worker must repeat that check before entries.
The original raw cursor 28,029,693,043 and restored native cursor 28,087,370,409
are independent namespaces: neither may be forced to equal the other.

## Existing implementation boundaries

- `reencode_archive` exports whole archives or bucket subsets. Bucket subsets
  deliberately omit provenance and retain the original declared range; they
  cannot stand in for an exact checkpoint prefix.
- `reencode_archive_prefix` is a library-only primitive for a proper, dense,
  uninterrupted V2 prefix. It retains the source bootstrap, worker digest,
  metadata policy and raw update order, narrows provenance/header range and
  segment-local epoch slot count, preserves a nonzero incoming PoH anchor,
  and rejects discontinuous slots or stored links. Its semantic output digest
  must match an independent reread. It does not hash-bind paths, admit disk,
  create files/manifests/sidecars, prove a checkpoint, or authorize operation.
- `jetstreamer-segment-recover` implements a different delayed-reaping profile:
  legacy v1 full receipt, owner-only archive, common private root, and specific
  failure/journal schemas. Do not chmod the retained 0440 archive, relabel its
  v2/v3 receipts, or manufacture old-profile evidence to use it.
- `checkpoint_continuation.rs` is explicitly build/input-bound to epoch 213,
  Solana v1.6.16 and its 457-slot suffix. Do not broaden or reuse those flags
  for epoch 140. The reusable archive merger's V4 restart provenance keeps
  independent raw cursors and normalizes update versions in recorded order.
- The checked-in v1.4.25 worker snapshot/entry guards cover this intended
  interval, but source inspection is not proof about any newly sealed worker.

## Remaining gates

Qualify a dedicated Rust, hash-bound private prefix-export/manifest profile
against the actual sealed full, anchored, bootstrap-journal, cut-journal,
raw-cut and native-restoration evidence. It must bind source identity/digest,
the exact cut tuple and actual observed raw write range; independently reread
the exported prefix before returning a usable proof. The observed cut's
post-phase count minus one agrees with 20 journal-drained writes, but that
single observation is not a generic arbitrary-mid-checkpoint derivation.

Then qualify the dedicated v1.4.25 actual-worker restart and suffix path,
canonical-root coverage, V4 assembly, independent full/plugin verification,
and explicit provenance-aware canonical import. The ordinary terminal-root
obligation remains even though the restart cut is near the epoch end.

Any large copy, restore or assembly needs fresh admission for its complete
incremental peak while protecting all live growth claims, ongoing epoch-141
ledger retention, and the century floor. Keep outputs private and sidecar-free
until every independent gate passes. No replay, assembly or publication is
authorized by this document or by passing library tests.

## Read-only selected-prefix audit

`jetstreamer-epoch140-prefix-audit` is a separate fixed-input audit of the
original archive through 60,911,751. It makes no large prefix copy: its
`jetstreamer-epoch140-private-selected-prefix-audit-v1` result explicitly binds
the original 432,000-slot source and a distinct 431,752-slot selection. It is
not a `HistoricalSegmentManifest`, a shortened archive, or a continuation
approval. A future selected-range consumer must explicitly support that
distinction rather than pass the whole original archive to a prefix-only
manifest reader.

The immutable plan binds the exact sealed full, anchored-chain, bootstrap
journal, cut journal, raw-cut and native-restoration receipts by their actual
digests. The tool rehashes the whole source before and after independently
decoding the selected prefix, checks every selected slot and incoming bucket
anchor, and verifies the exact complete raw-write range. Per-slot sorting is
used only to detect missing/duplicate versions; the semantic event digest
retains original wire order across epoch, pre, transaction and post phases.
The original source's previously established full PoH proof remains separate;
the audit does not pretend to perform another full PoH scan.

Invoke a separately sealed root-owned executable and owner-only immutable plan:

```text
jetstreamer-epoch140-prefix-audit PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]
```

The strict plan schema is `jetstreamer-epoch140-private-prefix-audit-plan-v1`.
It contains `unit`, six `{path, sha256}` bindings named `full`, `anchored`,
`bootstrap`, `checkpoint`, `edge`, `native`, the `output` receipt path, and
`minimum_free_bytes` / `minimum_available_memory_bytes`. Pre-create an empty
root-only `epoch140-prefix-audit-UNIQUE` directory directly under this host's
private campaign root; the result must be named `prefix-audit.json`.
`--check-only` validates the exact profile, source identity/header and admission
without a large source hash, decode or output. Prove that mode under the same
sandbox before the real non-restarting persistent service. Real execution
authenticates its exact systemd invocation and PID, retains a shared source
lock, and enforces the reserve/runtime guard throughout reads. Use a bounded
memory cgroup and a oneshot timeout longer than its six-hour internal bound.

A distinct `jetstreamer-epoch140-private-prefix-audit-plan-v2` can bind an
explicit integer `maximum_runtime_seconds` from 21,600 through 86,400 inclusive.
It requires a `horizon-epoch140-prefix-audit-runtime-*.service` unit and a matching
private result-directory basename (the unit name without `horizon-` or
`.service`). The v1 profile still has its fixed six-hour bound and rejects this
override, even when the supplied value is six hours. V2 does not change the selected source, slot
range, checkpoint, write-cursor, semantic-digest, full-hash or provenance gates.
It retains the same minimum disk floor and available-memory requirement.
Runtime and reserve failures report distinct errors with the observed bound;
the small result additionally records the plan schema and runtime allowance.
Use a separately sealed package and exact-profile sandbox check before any new
attempt, and set `TimeoutStartSec` above the plan's runtime allowance. A longer
runtime is not permission to reduce the protected floor, restart an active audit,
reuse an attempt directory, or retry after a reserve stop. Fresh admission and a
credible complete-scan runtime budget remain required; no new scan is authorized
by this profile alone.

No input, archive, sidecar, existing manifest or remote object is modified.
The small no-clobber result and its directory are individually fsynced.
Failure preserves all previous evidence and has no automatic retry authority.
Actual suffix-worker restart validation, selected-range assembly/provenance,
normal full/plugin/root gates and canonical import remain outstanding.

## Selected-range assembly primitive (not an operational approval)

`merge_checkpoint_restart_with_retained_prefix` is a separate library entry
point for one selected original prefix plus one independently restarted
suffix. Its first `RuntimeSegmentSource::retained_prefix` binds the **whole**
unchanged original container hash, the selected checkpoint blockhash and a
`RetainedPrefixSelection` with original/selected slot counts and the independent
digest of original selected wire events. Source header, V2 provenance and epoch
metadata retain their original range. No prefix-only manifest is fabricated.

The source container must cover the entire destination range. Only its proper
prefix is decoded into the first generation; an explicit bounded bucket reader
stops at the cut even inside a bucket. Epoch, pre, transaction and post writes
are checked and normalized in their original event order. The original tail
is excluded, but remains committed by the whole source digest. The source
selection's event digest is checked before moving to the suffix. Independent
raw/native cursors remain represented by the V4 handoff and normalization maps.

Ordinary V3 and complete-source V4 assembly reject selected-prefix inputs.
The new entry point requires two generations, a proper first-source selection,
a complete second source, and an explicit V4 assembly profile ending in
`/retained-prefix-selection-v1`. It writes no file or receipt itself and grants
no canonical admission, replay, root, plugin, sidecar or publication authority.

For epoch 140, 248 slots describe only the remaining **epoch-140 output** after
the cut. That count is not permission to stop at the epoch end without the
ordinary trusted-terminal-root obligation. The dedicated replay may need a
larger compatible verification cohort. The retained 11-target gap audit covers
only 60,911,751..60,912,005; a wider execution interval needs its own complete
gap census and exact-state recovery. Never extrapolate that bounded evidence
to an entire later epoch or use the earlier cut root to erase a required gate.

## Post-cut root and complete gap census

The retained root preflight at
`/usr/local/lib/jetstreamer/deploy-epochs136-147-target4-20261011-v2/preflight-136-147-target4-v4.json`
(whole-file SHA-256
`ec62e2ce730a28033e5626e7afdb59c2b6e73a2ce188ae1040a77a7a09e396c3`)
names the first post-cut root at slot **61,328,765**, with accounts hash
`8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY` and snapshot generation
`1634786682225857`. This is 417,014 replay slots after the restart cut, not
248 slots. It lies within the v1.4.25 candidate envelope but is not a qualified
continuation endpoint merely because a retained planning report lists it.
Fresh cloud identity and exact-worker capability remain independent gates.

Before recovery, census the entire 60,911,751..61,328,765 inclusive interval.
The Rust `jetstreamer-horizon-gap-audit` offers a first-stage `--census-only`
mode for that purpose. It binds immutable finalized `getBlocks` request and
response bytes through a separately sealed plan, validates every integer and
the exact endpoints, and writes a private no-clobber `gap-census.json`.
Use the distinct `jetstreamer-horizon-finalized-gap-census-plan-v1` plan schema
with no `rpc_batches`; the original full-audit schema cannot select this mode.

Its `jetstreamer-horizon-finalized-gap-census-v1` receipt contains gap
**candidates** and expected boundary counts, not independent target-parent
checks or hidden PoH hashes. It explicitly denies full-audit completion,
replay, runtime promotion and publication. Obtain finalized metadata for all
listed post-gap blocks, bind their exact parents and visible hashes, then
complete the ordinary audit/recovery path. A small earlier 11-target receipt
must not be broadened or relabeled to cover this wider interval.

For RPC backends that time out on a single large `getBlocks` request, use
`--paged-census-only` with the distinct
`jetstreamer-horizon-finalized-paged-gap-census-plan-v1` schema. Its `pages`
array contains `{first_slot,last_slot,request,response}` entries; both bindings
are immutable `{path,sha256}` files. At most 512 pages may cover the exact
global interval, with no missing, overlapping or reordered pages and no page
wider than 50,000 slots. Each original request must bind that page's exact
finalized interval and match its original response ID. Skipped page endpoints
are allowed; the global endpoints must be present. Derive gaps across page
joins as well as within pages. Do not synthesize an HTTP/RPC response by joining
JSON with shell or a floating-point parser.

The resulting `jetstreamer-horizon-finalized-paged-gap-census-v1` receipt binds
every actual request/response pair and retains the same non-authorizing
first-stage semantics. Timeouts and error responses are preserved separately;
they are not empty pages or evidence of a completed census.

## Bounded finalized target metadata collection

`jetstreamer-epoch140-gap-metadata-fetch` is a separate root-only, fixed-census
collector for all 18,283 targets in the sealed next-root census (SHA-256
`11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f`).
It does not run a Bank, read a `.jet`, recover hidden hashes, contact R2 or
grant replay/publication authority. Its strict plan schema is
`jetstreamer-epoch140-gap-metadata-fetch-plan-v1`, with `unit`, `census` and
`curl` `{path,sha256}` bindings, and a root-private `root` directly beneath
`/var/lib/jetstreamer-epoch140-gap-metadata-UNIQUE`. Seal the collector, exact
curl executable and plan with the normal Rust deployment sealer.

Invoke `PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]`. Both modes
authenticate the exact non-restarting systemd MainPID/invocation. The check
unit is the production unit name with `-check` inserted before `.service`;
it makes no network requests or output writes. Pre-create the root-owned
0700 output root and prove that mode under the intended sandbox before launch.

The endpoint is fixed to the public mainnet Solana RPC. Requests contain at
most three finalized, rewards-free, metadata-only `getBlock` calls. The
collector pins every ID, exact parent from the census, and both canonical
32-byte hash encodings. It uses a two-second successful-batch delay and
bounded backoff on partial/error responses. Curl gets a 45-second timeout;
the owner independently kills/reaps only its own child after 50 seconds and
bounds response capture to 64 KiB (plus a diagnostic overflow byte). Six
hours, 10,000 attempts, eight consecutive no-progress attempts, a 1-GiB
output budget and a retained 1-GiB private-filesystem reserve are hard stops.

Actual request bytes, bounded captured response bytes and attempt errors
remain private. Per-target checkpoints are immutable and atomically published
without replacement only after finalized metadata validates. A deliberate
resume takes the same output lock, rehashes all checkpoint/request/response
bindings and repeats the parent/hash checks; file presence alone never skips
a target. An interrupted partial stays diagnostic. No automatic restart or
unconditional output replacement is supported.

The final `complete.json` is written only after an independent reread of every
verified target checkpoint and original RPC binding. It proves finalized
parent/visible-hash metadata collection, not hidden PoH recovery, native
live-state completeness, a terminal root, prefix qualification or publication.
The retained ledger reports data through slot 61,344,045, covering the planned
61,328,765 root, but its bounds do not replace complete native MANIFEST/WAL/CF
validation and exact entry-chain recovery for every target.

## Complete-census native candidate acquisition (not yet operationally qualified)

The native runner has a distinct
`jetstreamer-epoch141-ledger-native-full-census-plan-v2` profile. The existing
`jetstreamer-epoch141-ledger-native-plan-v1` remains exactly 11-target-bound;
neither a wider census nor new collection fields can be passed as that profile.
The new profile keeps every existing source, complete-retention, independent
tar-census, column-family, admission, private-path and output binding. Its
`gap_audit` must bind the fixed complete paged census SHA above. It additionally
requires `finalized_collection_plan` and `finalized_collection_receipt`
`{path,sha256}` bindings, plus an exact service `unit` in the
`horizon-epoch141-native-full-census-*.service` namespace.

The metadata consumer requires the actual collector `complete.json`, all
18,283 ordered target bindings, and the fixed census/plan/owner/authority fields.
It independently rehashes every target checkpoint and original finalized RPC
request/response and repeats the exact parent/hash checks. A partial collection,
mere checkpoint presence, changed digest, duplicate or reordered binding is not
admissible. The native check unit is the exact production name with `-check`
before `.service`; both modes authenticate their own MainPID/invocation and
non-restarting service policy. Check-only still performs no native database open
or receipt writes.

The complete profile uses one read-only native database session, not 18,283
full-database rehashes. It hashes the complete retained census before open and
again after close, requires the complete native column-family allowlist and
every live SST reference, and retains checksum-verified logical reads with WAL,
version and tombstone resolution. For each target it reads complete SlotMeta,
plans every contiguous data shred using the unchanged bounded v1.4.25 decoder,
then reads all those shreds plus an identical SlotMeta recheck. Each batch retains
the 65,536-query, 64-MiB-return and 1-MiB-per-value ceilings. The entire session
allows at most 36,566 batches, 16,777,216 exact lookups and 8 GiB returned values;
these are hard ceilings, not a claim that the retained source fits. Any suppressed
batch failure poisons the session and prevents a successful final summary.

Fresh admission must separately reserve 32 GiB above the existing protected
filesystem floor. Actual combined private output is capped at 24 GiB, with the
legacy 224-MiB per-record bound retained. Logs and results must be root-private
on the campaign `/home/sol` filesystem, disjoint from retained inputs and the
compressed source. Use the existing CLI, separately bound executable/plan and
fresh admission hashes, persistent non-restarting systemd execution, hard
memory/CPU/task/time ceilings and the required least-privilege traversal
capabilities. Do not admit it merely because the old 256-MiB profile fit.

Each `target-candidates/slot-N.json` is explicitly provisional, immutable
no-clobber diagnostic output, not a completed session. The distinct final v2
receipt appears only after all targets succeed, native close and complete input
rehashing pass, every output is independently reread, and all top-level inputs
are rebound. A failure preserves provisional outputs without a final completion
claim. A new attempt needs fresh isolated logs/results and fresh admission; no
automatic restart or in-place output replacement is supported.

Even a complete candidate receipt does not decode/authenticate PoH clocks,
recover hidden boundaries, prove original backup completeness or historical
liveness, qualify a canonical root, or authorize replay, assembly, publication,
sidecars or R2 mutation. Source tests are not actual-source sandbox qualification.
Keep this profile dormant until the live metadata collection and ledger retention
complete and a sealed exact-package check, fresh admission and independent
operational qualification have passed.
