# Old epoch166 retry6 held partial retirement

This is a separate source-only route derived from
`jetstreamer-r2/src/holding_epoch169_retire.rs`. Existing166 and169 profiles are
unchanged. No build, runtime qualification, holding completion, consumer closure
or deletion is claimed by this source handoff.

The exact source is the old retry6 run's `archives/epoch-166.jet`, device64512,
inode103678035, length56,173,984,550, allocated56,174,063,616 bytes, SHA-256
`c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85`.
The full pathname and modification timestamp are fixed in
`holding_epoch166_retry6_retire.rs`. The source is an incomplete private partial;
none of these routes publish or retire a canonical archive.

The existing sealed park plan is bound to digest
`a835a7adf66726ffbdc07eb13def1b917a9de799ff3dc9062ad7441cd182c640`, its eligibility
to `6d7243eb5912b92d96367f57c94633be768937158d16a07923669ea972e79a97`, and the
original inspection to
`c2eb4c497d23b0be00468eedc6eb8445659beb188c5bbe58bb8ec1845b6b7c7f`.
The inspection explicitly says the complete transitive consumer graph is not
qualified. This false field remains authoritative historical evidence; the new
gate requires a separate, fresh, fully evidenced closure.

## Routes and plans

Seal the helper and its build/source proof in
`/usr/local/lib/jetstreamer/horizon-holding166-retry6-retirement-20261119-v2`.
The helper's actual executable parent must be this directory. Then run its
census and seal the copied inspection, actual terminal proof, reviewed closure
and check plan in a new versioned bundle under
`/var/lib/jetstreamer/holding166-retry6-retirement-evidence/`. After check succeeds,
seal a separate execution bundle with the bound check receipt and execution
plan. These are normal Rust-sealed immutable bundles; never append to an already
sealed directory. Renew an expired closure in another versioned bundle. This
order avoids circular dependence between runtime deployment and its subsequent
census/review, and between the check receipt and execution plan. Main owns
sealing, source/build publication and native capability/admission checks.

- `holding-census166-retry6-consumers PARK_PLAN --spec-sha256 PARK_PLAN_SHA --self-sha256 HELPER_SHA`
  reads the already-existing exact park plan. It produces a real bounded
  metadata/reference graph in the holding state's `receipts/` directory. It
  reads no archive body, requires no R2 credential, and grants no retirement.
- `holding-check-retire166-retry6 PLAN --spec-sha256 PLAN_SHA --self-sha256 HELPER_SHA`
  requires complete custody and closure, hashes the exact local partial, and
  produces an immutable check receipt without moving or deleting it.
- `holding-retire166-retry6 PLAN --spec-sha256 PLAN_SHA --self-sha256 HELPER_SHA`
  requires a successful check at most900 seconds old plus fresh consumer closure.

The deny-unknown-fields retirement plan has schema
`jetstreamer-horizon-holding-retire166-retry6-plan-v1` and fields `mapping`,
`eligibility`, `inspection`, `custody`, `park_terminal`, `consumer_closure`,
`prior_check`. Every binding is `{path, sha256}`; `prior_check` is null for check
mode. The inspection may be an immutable, byte-identical sealed copy of the
original. The mapping and eligibility must be the exact original sealed paths
and digests. Every supplied proof is re-read, hash-bound and checked for custody.

`park_terminal` must be genuine saved native evidence with schema
`horizon-closed166-retry6-park-terminal-v1`, `unit`, `invocation_id`, `park_plan`,
`helper`, and `native`. The expected unit is
`horizon-closed166-retry6-park-20261119-v1.service`. Bind the real helper path/hash,
exact park plan, actual invocation ID and complete native properties. The
runtime checks the saved and current native invocation, successful exit,
zero PIDs, no queued job/restart/trigger, and exact `holding-park` command.
The original invocation is fixed to `afc04ba6096f4826836919c2020dcdc6` and the
genuine saved start event at
`/var/lib/jetstreamer/root0832-holding166-event-20261119-v1/EVENT.json`, digest
`d5beb401ed0e015f371a7123fa34c6772f2d7f88b854d4cb1a01c4c8b2f0a0bb`.
The event's helper and plan must match the terminal proof. The start event does
not assert terminal success or completed custody; those remain separate gates.

## Transitive consumer closure

`holding_epoch166_retry6_consumers.rs` enumerates immutable text metadata under
`/usr/local/lib/jetstreamer` and the15 fixed systemd/user/cron definition roots.
It follows reverse references to the exact source, run and destination until a
fixed point: a unit pointing to a wrapper pointing to a plan is included even
when the unit never mentions the archive. Every discovered node, content digest
and dependency edge must match the reviewed graph. Added or changed transitive
consumers fail the gate. Unrelated new packages/units do not invalidate the
digest of the relevant closure.

The census covers the enumerated text extensions and caps itself at200,000
entries,20GiB total inspected metadata and64MiB per text file. A native inventory
on this host found136,772 entries and104,491 metadata files totaling15,425,505,635
bytes, with a66,027,261-byte maximum. Admit the census separately at32GiB memory;
the4GiB compiler allowance is insufficient for this in-memory graph. Root-controlled
writable installed files are stable-read for dependency discovery; any such file
in the relevant closure still fails the immutable-metadata gate. Native binaries,
computed paths and future/recovery behavior are separately reviewed; the tool
does not claim textual scanning proves their absence. It rejects unresolved
aliases, unqualified writable metadata, oversized records and unknown special
files. Diagnose any such failure without truncating the census or claiming
missing references are absent. The exact new lifecycle package is excluded
from the reverse scan to avoid self-referential proof hashes; its helper/spec
paths and bytes remain separately bound by the normal lifecycle entry gate.
The versioned evidence directory is outside the enumerated executable metadata
root; it is not a new broad exclusion from that scan. The review must still
cover dynamic/future consumers, and must not place executable definitions in
an evidence bundle.

The emitted census is not a completed review. Construct the sealed review only
after inspecting actual discovered nodes and native/dynamic dependencies. The
review schema is
`horizon-closed166-retry6-transitive-consumer-closure-v1`; the complete shape is
the `Review` structure in the source. It requires:

- The exact source/digest/length, copied inspection, park plan and actual park
  terminal proof, with a timestamp at most1800 seconds old.
- The exact metadata and definition roots and fresh census digests.
- Every discovered node with exact outgoing edges, real semantic/source
  evidence and a qualified disposition. A staged definition cannot be waived
  as inert evidence. Closed consumers must have actual inactive, unqueued
  owners; the successful park invocation is handled separately.
- Actual compiled consumer images, reviewed sources and terminal owners.
  The exact original166 node and actual park helper must both be covered.
- Concrete bound inputs and conclusions for all seven classes:
  producer/controller, libraries/relative inputs, sealed launch plans,
  timers/paths/cron, future builds, recovery, and live accounting/witness roots.
- No unresolved edges, excluded future reopening during the transition, and
  preservation of all existing resource promises and witness ancestors.

The earlier path list `/tmp/epoch166retry6-indirect-reference-paths-20261119.txt`
already identifies many old observer/status configs. It is an investigation
lead, not a closed graph. Their actual transitive consumers and semantics still
need review. Do not infer that an inactive original producer proves that every
observer, wrapper, recovery tool or staged plan can tolerate archive removal.

## Preservation and interruption

Both existing locks are opened without creation/truncation and held to the end:
the host local-mutation lock inode101135013, then the exact destination epoch
lock inode103678014. Their device, ownership, mode, inode and contents metadata
are rechecked. The original run, scratch root and contents, cohort-state bytes,
inputs, archives directory and ancestors are preserved. Checks target this old
destination; independent166 retry8 and167 lanes are not globally required to stop.

Before mutation, the tool validates the durable whole-readback holding receipt,
authenticated owner and manifest bytes, then rechecks the exact object HEAD,
ETag, length and metadata digest. It repeats custody checks before both move and
unlink and after completion. It never modifies or deletes remote objects.

Immutable INTENT, MOVED, UNLINK-INTENT and COMPLETE receipts bind the exact
custody, park invocation, source and preserved run. Move uses descriptor-relative
`renameat2(RENAME_NOREPLACE)` into the fixed private quarantine; unlink is limited
to that exact inode after fresh checksum and ETag proof. A crash after move or
unlink is recoverable only through the corresponding durable predecessor.
Missing files without unlink intent, duplicate source/quarantine, substituted
inodes and rewritten receipts fail closed. Fresh check/consumer evidence may be
generated for a partially completed transition, including after a durable
unlink, without resetting the original chain. Completed repeated execution
revalidates absence, custody and closure.

No DATA promise is ended and no free-space credit or replay authority is issued.
Completion reports censused allocation only. Main must separately measure actual
reclamation and perform the existing accounting/admission transition.

## Main's remaining qualification

1. Finish holding and retain genuine whole-readback custody plus exact terminal
   park evidence. Neither was claimed as present by this source-only work.
2. Run offline package tests, strict Clippy and production build with the exact
   predecessor configuration. The actual holding169 artifact proof records
   `jetstreamer-r2` features `[]` and rustc flags `[]`; this package does not
   declare native210/native227 features. Those features belong to other campaign
   helpers and must not be invented for this build. Preserve all retained holding
   routes. Publish all changes to `origin/account-updates` before admission.
3. Seal the new lifecycle helper/evidence normally. Run the read-only census,
   inspect all discovered graph nodes, qualify native/dynamic/future classes,
   and seal the truthful complete review.
4. Exercise positive, negative, changed-node/edge, interrupted move/unlink,
   repeated completion, remote mismatch and shared-lock scenarios in an isolated
   native qualification. Admit the metadata scan, parallel three-digest hash,
   receipts and runtime resources while preserving live growth reservations.
5. Perform actual check, review it, then the separately qualified execution.
   Preserve receipts and revalidate real reclaimed capacity before using it.

The separate source-only scratch-retirement profile still requires the original
partial during its preservation/hash check. If partial retirement happens first,
that future scratch operation needs a separately qualified holding-aware
preservation path or an admitted restore. Do not silently treat that dependency
as resolved by this partial-only route.

## Census parser successor

The v2 runtime replaces full `serde_json::Value` construction with a streaming
Serde visitor. It retains raw path scanning and only rescans decoded strings
when JSON escapes can introduce additional paths. Decoded edges are committed
only after the complete JSON document validates; duplicate object keys retain
the predecessor's last-value behavior. Escaped keys, Unicode surrogate pairs,
aliases, malformed/trailing JSON and raw delimiters have equivalence coverage.
The installed corpus is still retained in memory, so the 32 GiB census envelope
and all graph limits remain unchanged. Real census timing must still demonstrate
that check and retirement fit the original freshness clocks. Build this successor
in the admitted DATA target: the old ROOT compiler cache has been retired to
make room for chronological audit readback. Preserve the immutable v1 runtime;
the new census includes any relevant old runtime metadata in its reviewed graph.
