# Epoch 141 original-entry transaction equivalence

`jetstreamer-epoch141-source-equivalence` is a private, fixed first-target
diagnostic for slot 60911776 (parent 60911771). It never launches replay,
changes a runtime route, publishes an archive, or accesses R2.

The tool binds the exact retained raw-shred target and its prior complete PoH
diagnostic, plus independently qualified typed/native snapshot clock evidence.
It makes one bounded finalized `getBlock` request to the fixed mainnet RPC,
retaining the request and exact response bytes (base64 plus SHA-256), including
failure responses. The parent, previous hash and final hash must match the
retained finalized anchors. Transactions must be explicitly legacy and have
canonical base64 packet-sized wire encodings.

The shared `horizon_legacy_source` helper compares every original transaction
byte in complete assembled batch order with the independently obtained source
sequence, then reexecutes the complete original PoH chain. It retains every
original tick, transaction entry, hash and hash-work count, and maps original
entry indexes to source transaction indexes without normalizing or regrouping
transactions. A mismatch returns no partial mapping. Slot-wide byte, entry,
transaction and hash-work limits remain independent; guards can abort work.

The root-private no-clobber completion includes the full entry/index mapping,
counts and input/response digests. This is only first-target wire equivalence,
not complete 18,283-target equivalence, native live-state completeness,
signature verification, canonical ancestry, Bank-root qualification or
publication authority. The running producers must remain untouched.

Before use, seal the executable, its hash-bound plan and a digest-matching curl
copy with the normal Rust deployment sealer. Use schema
`jetstreamer-epoch141-first-source-equivalence-plan-v1` with `curl: {path, sha256}`
and an empty root-owned mode-0700 `output_directory` directly beneath
`/var/lib/jetstreamer`, named `horizon-epoch141-source-equivalence-*`.
Run in a bounded non-restarting systemd unit with only that output writable,
read-only private inputs and minimal private-path traversal capability. The
tool requires its own supplied executable and plan SHA-256, the real systemd
invocation ID, a 30-second RPC deadline and a 90-second overall work deadline.
Normal root/plugin/full-span and publication gates remain separately required.

## Complete immutable original-entry bundle

`jetstreamer-epoch141-original-bundle` prepares input from the exact completed
18,283-target acquisition and successful complete-census PoH diagnostic. It
does not refetch source, retry native acquisition, execute replay or promote a
route. Each target/raw receipt is reopened by its bound digest; original
SlotMeta endpoints, structural entries, tick counts and finalized final hash
must still agree. Existing private evidence remains unchanged.

The output contains `original-entries.data` and `index.json`. Each data record
is a little-endian u32 batch count followed by a little-endian u32 length and
the complete original padded bytes for each batch. Framing avoids placing
millions of batch lengths in the JSON index. Each sorted index row binds the
slot, finalized parent/anchors, exact offset, framed length, batch count and
record SHA-256. The complete index binds the source/acquisition/PoH digests,
source interval, independent clock and whole data length/digest. All records
must cover the data exactly, without gaps, overlaps or duplicate targets, and
cover precisely 18,283 targets and 84,597 boundary slots.

Preparation is non-restarting, bounded to two hours and 32 GiB of data, with
64-MiB per-slot and 16-MiB index bounds. It preserves at least
4,397,099,539,910 actual free bytes on the output filesystem while preparing
input, rather than consuming a replay's protected growth. Its sealed plan
uses schema `jetstreamer-epoch141-original-bundle-build-plan-v1` and an empty
root-private `output_directory` directly beneath
`/home/sol/.jetstreamer-private`, named `epoch141-original-bundle-*`.
Run it with only that directory writable and a bounded memory/CPU sandbox.
After fsync it independently rereads and hashes the complete data before
writing the index and no-clobber completion. An interrupted attempt remains
partial evidence, not a usable bundle; do not restart into its occupied output.

The library's `OriginalEntryBundle::open` consumes only separately sealed,
root-owned, singly linked, non-writable files with independently supplied
index and data SHA-256 values. It hashes the entire data member before returning
an open bundle. Every slot reread rechecks both the descriptor and pathname
identity and its record digest/framing. A missing index row means the slot is
outside the recovery census, not proof it was skipped. Loading succeeds only
for this exact complete qualification profile; it never authorizes execution.

Before a parent can use a returned slot, it must collect the entire independent
source transaction sequence, pass `bind_v1_4_25_source_entries`, preserve the
corresponding transaction status/index attribution, and send the original
entries through the normal strict worker checks. No partial source slot may
mutate a Bank first. Private canonical-root and ordinary full/plugin/publication
qualification remain outstanding even after bundle preparation succeeds.

## Separate parent qualification adapter

Build `jetstreamer-node` with only the diagnostic feature
`epoch141-original-entry-qualification`. Ordinary builds reject its input flags;
the diagnostic build rejects ordinary execution and unrelated diagnostic modes.
Its four explicit inputs are:

- `--epoch141-original-index=PATH`
- `--epoch141-original-index-sha256=HEX`
- `--epoch141-original-data=PATH`
- `--epoch141-original-data-sha256=HEX`

The only admitted CLI shape is epoch 141, explicit snapshot verification,
bootstrap 60911751, replay start 60911752 and qualification end 61328765, with
explicit output/destination/scratch descendants of the private root. Cohort,
recovery, carried-state and handoff routes remain forbidden. This checkpoint
artifact ends before the full epoch end: it is not a full epoch 141 archive and
must not receive a production plugin receipt, canonical sidecar or publication.
Its generation profile is distinct from ordinary old-faithful-to-horizon output.

The scheduler holds every recovery target until source block metadata, all
declared entries and the entire transaction sequence are present. Decoded source
parent/previous/final hashes must match the bundle anchors. It checks contiguous
transaction grouping, encodes every current-SDK legacy transaction to canonical
wire bytes and passes the full original-entry/source/PoH binding before consuming
one source transaction. It then maps original entry groups to the exact owned
source transactions and their status, fee-reconstruction and ancillary metadata.
Only the source entry count is replaced in buffered archive block metadata;
transaction count, rewards, hashes and timestamps remain unchanged. Both orders
of metadata arrival are supported, but emitted metadata cannot be rewritten.

Normal strict worker checks remain unchanged. Original ticks, hashes and work
counts are sent through the existing historical protocol; no PoH-bypass message
or synthesized hidden tick is introduced. Scheduler accounting still describes
the complete source stream while worker/recorder entry indexes describe the
original entries. A source parent edge may not mark any pinned recovery target
skipped, and completion requires exact equality between the full target census
and the uniquely byte/PoH-matched target set, including unrecorded warmup.

Partial-source/mid-slot resume and duplicate recovery targets are unqualified
and fail closed; this is a fresh, non-restarting qualification route. Passing
unit tests or the ignored real-first-target wire-conversion regression does not
admit replay, prove the canonical Bank root or promote the normal runtime route.
The actual sealed parent/input capability probe, fresh resource admission,
invocation-bound reserve/VMA guard and canonical-root qualification still precede
any full-span and publication work.
