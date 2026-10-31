# Native SST decoder capability

Run the explicitly enabled, pinned decoder test with:

```sh
JETSTREAMER_SST_DUMP_TEST_BIN=/absolute/sealed/sst_dump \
  cargo test --locked --release -p jetstreamer-utils \
  --features sst-capability-tests --test sst_decoder_capability \
  -- --ignored --nocapture
```

The optional feature keeps native RocksDB test dependencies out of ordinary
utility builds. The test uses isolated disposable databases only. It proves
uncompressed and LZ4 prefix decoding, internal versions, point deletion,
column-family identification, and range-deletion table properties against the
exact supplied executable. It does not qualify a production ledger generation
or prove support for other compression formats.

The fixture deliberately starts a covering range tombstone in the slot before
the queried prefix. A native logical database lookup returns no value, while
the point-prefix scan still exposes both old and newer point versions. Thus
even a complete scan of every SST followed by greatest-point-sequence selection
can incorrectly resurrect deleted data. A prefix iterator alone cannot establish
the full set of covering range tombstones.

The `native_readonly_resolves_manifest_and_wal` test separately exercises native
read-only logical resolution of a deliberately crash-shaped LZ4 database. Its
fixture process syncs unflushed WAL writes and exits without database destruction.
It requires the complete CF set and checks an outside-prefix range deletion,
point deletion, updated WAL value and WAL-only key. A second disposable copy omits
WALs: even when native open succeeds, that copy must not be treated as a complete
backup. This qualifies fixture behavior only, not an archived ledger or a shred
decoder. Run it with the same explicit feature and `--ignored` test flags above.
With the pinned native decoder, the omitted-WAL copy does open and resurrects old
SST values; a read-only subset-CF open also succeeds. Therefore authenticate the
complete generation-bound manifest/WAL/live-file census independently of native
open success. The test also rehashes CURRENT, MANIFEST, WAL and SST inputs after
the complete logical read to detect input mutation.

An archival recovery must either preserve CURRENT/MANIFEST, relevant WALs, and
the complete live file set for native read-only logical resolution, or use an
independently qualified range-aware reader that accounts for every covering
range tombstone as well as internal point versions and deletions. A bounded
one-SST-at-a-time scan may collect candidates, but must not label them live or
complete until those independent gates pass. Unknown column families, unknown
record types, unsupported compression, truncated scans, unresolved duplicate
versions, or missing manifest/WAL evidence are failed gates, never absence proof.

Even correctly resolved shred records remain diagnostic inputs until the exact
pinned historical layout, complete ordered entry/tick chain, independently
finalized parent and final PoH hashes, and ordinary checkpoint/plugin/publication
gates have all passed. Do not equate PoH hashes with Bank or SlotHashes hashes.

`horizon_ledger_tar::collect_rocksdb_tar` is the bounded diagnostic collection
core for a complete **flat** RocksDB tar. It retains every regular member, not
only selected SSTs: CURRENT, its nonempty MANIFEST, all archived WALs, all table
files, OPTIONS and ancillary files appear in a sorted length/SHA-256 census.
The caller explicitly supplies the archive root and independent file-count,
individual-file, total-output and zero-trailer limits. Unknown members are
preserved; links, devices, sparse/GNU/PAX extensions, nested/foreign paths,
duplicates, missing end markers and nonzero/excess trailers fail closed. New
files are no-clobber, read-only and individually fsynced, followed by directory
fsync. A failed partial tree is preserved and cannot be reused as a completed
collection.

This core accepts an already decompressed reader. It has **no production caller**
and does not authenticate a compressed cloud generation, bind an original
backup's completeness, provide a resumable download or perform fresh resource
admission. Those remain mandatory before actual ledger collection. Its result
explicitly denies source-completeness, live-state and publication authority.
The native read-only fixture test above also collects an entire crash-shaped
database tar, compares every source member byte-for-byte, verifies all native
CF/live-file references against the census, resolves outside-prefix range and
point deletions plus WAL-only updates, and rehashes every collected input after
native resolution. This is disposable-fixture qualification only, never evidence
for epoch 141 or any real ledger generation.

`horizon_ledger_bzip::collect_bound_bzip2` adds a diagnostic local-input binding
layer. It accepts only a canonical absolute, singly linked, non-writable regular
file owned by root or the effective user, with independently supplied compressed
length and lowercase SHA-256. It hashes the entire bounded compressed input before
collection and again while decoding every bzip 2 stream, then rechecks both the
descriptor and named path identity including ctime. The decompressed tar collector
still enforces every file, aggregate and trailer limit. Tests cover multistream
input, wrong digest/length/budget, unsafe inputs, truncation, corrupt checksums,
compressed garbage, concatenated tars, expansion bounds and preserved partial
diagnostics. The input is never modified.

This remains a library with no production caller. The expected digest is not its
own cloud-authentication evidence: a generation-bound download/verification
receipt, fresh resource admission, persistent guarded execution and durable
result receipt must still be supplied by a reviewed caller. Neither a successful
compressed binding nor a complete tar census proves original-backup completeness,
native live state, correct PoH boundaries or publication eligibility. No actual
epoch 141 source has been collected by these fixture tests.

`horizon_ledger_tar::census_rocksdb_tar` and
`horizon_ledger_bzip::census_bound_bzip2` run the same complete member parser and
compressed-input binding without writing decompressed files. Every member is
fully read and hashed; CURRENT, MANIFEST, WAL, path, count, expansion, end-marker
and trailer gates remain unchanged. The result explicitly records
`files_retained: false`, while successful extraction records `true`. This permits
measurement of a complete flat archive's logical extraction footprint before
admitting retention, without passing a partial scan off as complete. It does not
predict filesystem physical allocation, supply native database inputs, or prove
source completeness/live state. A real census still requires a persistent bounded
caller, immutable generation binding, fresh CPU/RAM/I/O admission and durable
receipts. The library tests do not constitute a census of the real epoch 141 input.

`jetstreamer-epoch141-ledger-census` is the private offline runner for that census
only. It requires independently supplied executable, immutable plan and fresh
admission-receipt hashes. It binds the exact successful compressed-source
verification, retained inode/ctime identity, fixed generation/length/digest, and
an admission manifest/receipt whose file census names this exact executable.
Admission must be no older than 300 seconds at start. It does not call GCloud or
download anything. Its protected free-space threshold cannot be lower than the
source verifier's original threshold; the guard checks at least once per second
of input consumption, plus before and after the scan. A persistent service must
also enforce its own wall-time, CPU, memory and I/O limits because a read callback
cannot interrupt a blocked syscall. All decompressed members are discarded after
hashing. Only complete decoder/tar EOF and unchanged input identity permit the
root-private fsynced no-clobber result. `--check-only` tests local bindings without
scanning or writing. This source alone does not prove an operational deployment,
real census, source completeness, native liveness, PoH recovery or publication.

`jetstreamer-epoch141-ledger-collect` is a separate fixed full-retention profile
sharing the census executable's source, admission, guard and receipt gates.
It additionally requires a separately hash-bound successful **complete** census
of the same frozen compressed inode and source verification. Its immutable plan
binds a separate empty root-private same-filesystem destination and an incremental
peak budget covering every member's rounded allocation plus 64 MiB of slack.
Fresh admission must cover that entire budget **above** the unchanged protected
free-space threshold. This scheduling estimate does not equate logical lengths
with exact physical allocation; the actual-free-space guard remains mandatory.

The collector prehashes and fully decodes the input again, retaining every file
through the reviewed no-clobber tar core. A result is written only if all names,
lengths, digests, CURRENT/MANIFEST/WAL bindings and compressed identity match the
prior complete census exactly (except the explicit `files_retained` bit).
The census-only executable rejects retention plans; neither executable exposes
a command-line mode override. Guard failure preserves partial diagnostic output,
never reuses or deletes it and writes no successful collection receipt.

This source is not an operational deployment or real collection result. Seal and
qualify the exact executable, run fresh complete admission, and prove its initial
guard under a persistent bounded non-restarting sandbox before real retention.
Original-backup completeness, complete actual CF set, native read-only resolution,
trusted clock and all post-gap PoH/canonical/publication gates remain separate.
No live sealed census deployment is changed by this source refactor.

The native crash-shaped fixture also compares direct-tar and digest-bound
multistream-bzip2 collections byte-for-byte, then performs the complete-CF native
read-only resolution against the compressed collection. It checks live-file
references, range/point deletions and WAL-only values without modifying either
the retained compressed input or the collected member census.

With the optional `sst-capability-tests` feature,
`horizon_ledger_native::resolve_native_candidates` provides a reusable diagnostic
core for bounded exact-key lookups against a retained complete collection.
It refuses a census-only result, unknown/omitted column families, missing or extra
members, writable/linked/mutated inputs, and mismatching CURRENT/MANIFEST/WAL
bindings. Every member is streamed through SHA-256 before native open and after
native close; inode/ctime identities must also remain unchanged across the entire
resolution. Native manifest live-SST references must match the retained census's
names and lengths. Read checksum verification is explicit. Native logs go only
to a separate empty private directory. Each requested value is bounded before
copying the pinned native slice into the aggregate bounded result.

This core preserves the distinction between diagnostic candidates and trusted
source state: it always denies original-backup completeness, historical live-state
and publication authority, even when the native read succeeds. Its caller must
independently authenticate the census, qualify the expected complete family set,
admit and guard full retention/native memory/I/O/runtime, decode SlotMeta/shreds,
and validate complete entry/tick/PoH chains plus canonical anchors. There is no
operational native recovery caller yet. The native fixture exercises this core
against an entire collected crash-shaped database, including outside-prefix range
deletion, point deletion, updated WAL and WAL-only values, and rejects an omitted
family allowlist. These remain disposable-fixture tests, not epoch 141 evidence.

`jetstreamer-epoch141-ledger-metadata` is a separate, read-only exact-generation
gate for `60911751/rocksdb.tar.bz2#1634789748052739` in the regional ledger
bucket. Its immutable plan and running executable require separate SHA-256
arguments. It pins the system GCloud script digest, clears supplementary groups
and drops to the configured operator UID/GID before an exact generation-bound
metadata lookup through the operator's login configuration. The 60-second child
and bounded stdout/stderr readers cannot turn into a bulk transfer. Normalized
and raw metadata must agree with the fixed object, generation, 189,943,475,031-byte
length, CRC32C, MD5 and versioned identity. Conflicting aliases fail closed.

Its root-private, fsynced, no-clobber receipt records the systemd invocation and
raw-response digest. It does not authenticate downloaded compressed bytes,
establish original-backup completeness or grant resource admission, collection,
replay, publication or R2 authority. Use a persistent non-restarting oneshot with
the operator configuration writable for token refresh, a 90-second start timeout
and the UID/GID-drop plus `CAP_KILL` capabilities. The latter lets the root parent
kill and reap its own unprivileged SDK child at the bound. An ignored root-only
sandbox test exercises the actual shared UID drop and timeout path with a
disposable sleep child, and proves no-clobber receipt writes beneath a valid
root-private directory. Do not apply the older metadata observer's
epoch 203–212 capability assumptions to epoch 141.

`jetstreamer-epoch141-ledger-download` provides a separate **fresh-attempt-only**
private transfer wrapper for that same fixed generation. It shares the existing
metadata, UID/GID-drop and receipt primitives with the metadata executable; the
previously sealed metadata deployment is unchanged. Require independent plan and
executable hashes, the exact passed metadata receipt and a passed performance
admission receipt whose file census binds this downloader and metadata receipt.
The admission filesystem must match the staging filesystem, and its free-byte
threshold must cover the complete compressed input plus 64 MiB of transfer slack
above the plan's protected older-growth/century-floor threshold.

The SDK is only the byte transporter. The wrapper pins its script before exec,
uses the operator's exact login configuration, reobserves the generation before
and after transfer, and independently streams the complete file through CRC32C,
MD5 and SHA-256 in Rust. SDK success alone is not verification. Transfer runs in
its own disposable UID1001/GID1003 process group with empty supplementary groups.
The wrapper explicitly disables sliced downloads and pins SDK process/thread
counts to one; operator configuration cannot silently enlarge the transfer's
temporary-file or process envelope. Check the current SDK's property definitions
and download selector before operational deployment.
`waitid(WNOWAIT)` retains the leader identity until group cleanup, avoiding a
reaped-PID/PGID reuse window. Every second the wrapper checks actual free space,
elapsed runtime, regular-file identities and bounded aggregate staging length.
A guard trip writes a durable stop intent before killing/reaping that owned
group, then writes completion. It never stops a replay or controller.
The first passing check writes a separate fsynced initial-guard receipt binding
the invocation, child PID and the exact free/staged byte sample that passed.
Require that receipt and its actual sandboxed service before unattended transfer.

Give the staging directory a canonical root-owned mode-0711 parent so the
unprivileged SDK can traverse it; keep receipt parents root-owned mode 0700.
The wrapper creates the staging leaf no-clobber and refuses an existing attempt,
including a failed partial. After SDK termination it freezes that leaf and the
completed compressed file as root before independent hashing. A successful
root-private no-clobber receipt binds the generation, three digests and file
identity. No retry may discard or overwrite a partial: reviewed SDK tracker or
same-generation resume support is still required before reusing a failed attempt.

Before operational use, seal the exact build, qualify the ignored root SDK-drop/
process-group test under the actual minimal sandbox, run fresh complete resource
admission and bind all older growth claims/guards. Use `Restart=no`,
`KillMode=control-group`, sufficient start timeout and only the capabilities needed
for traversal, UID/GID drop, ownership freeze and owned-child kill. The wrapper's
tests are not production download evidence. A compressed download receipt still
does not prove complete backup contents, native live state, recovered PoH hashes,
runtime compatibility or publication. Bounded complete tar collection and all
subsequent native/PoH/canonical gates remain independently required.

`horizon_legacy_shred::assemble_v1_4_25_padded_batches` provides bounded,
diagnostic-only data-shred assembly for revision
`893cc7647248a3536fb6e6d0b5e51c71446b862d`. It requires a complete contiguous
slot starting at shred zero, the independently resolved SlotMeta last index,
consistent parent/version metadata and the last-in-slot flag. Missing/coding
shards, ordering errors and oversized output fail closed; there is no FEC repair.

The pinned `Shredder::deshred` concatenates payload bytes 88 through 1138 of
every 1228-byte data shred, including padding. It does **not** clip each fragment
to `DataShredHeader.size`. The unit tests encode the fixed-int header layout and
protect this historical behavior, batch boundaries and allocation/identity gates.
They are not an upstream-runtime differential or real-ledger qualification.
Entry-vector decoding, padding checks, complete tick/PoH verification and all
canonical boundary gates still follow; no source completeness, runtime route,
publication or R2 authority is conferred by assembled bytes.

`horizon_legacy_entry::decode_v1_4_25_padded_entries` is the next diagnostic
stage. It bounds total bytes, entries, transactions and signatures; decodes
fixed-integer entry-vector framing and complete legacy transaction wire shapes;
rejects noncanonical ShortU16 lengths and nonzero trailing padding; and derives
the pinned signature Merkle root (leaf prefix zero, node prefix one, odd-leaf
duplication). It distinguishes tick entries from signature-free transactions.
It deliberately does not execute claimed PoH work, authenticate transaction
signatures, sanitize messages, verify tick ordinals, or establish any canonical
boundary. There is no production recovery caller. Complete generation collection,
native live-state resolution, chained entry/tick/PoH verification and the
independent canonical final blockhash checks remain required before recovery.

The pinned historical worker's test-only
`pinned_sdk_legacy_entry_wire_and_signature_merkle_fixture` checks synthetic
wire bytes with that SDK's actual Transaction/Message serialization and MerkleTree.
Run it from `historical-runtime/v1_4_25` with its pinned compiler and bounded build
jobs. Neither that synthetic fixture nor the modern decoder tests qualify a real
ledger, the upstream full Entry implementation, or a runtime route.

`horizon_legacy_shred::decode_v1_4_25_complete_slot_meta` bounds and decodes the
entire pinned fixed-int SlotMeta record, including both vector lengths, the
boolean, children and every completed-data endpoint. It rejects trailing or
partial records, unknown terminal indexes, noncontiguous consumed/received
ranges, oversized vectors and duplicate/invalid endpoints. Its complete-slot
profile is deliberately stricter than upstream `SlotMeta::is_full`: it also
rejects received data beyond the terminal range. The assembly wrapper requires
recorded connectivity and exact agreement between metadata and all assembled
batch endpoints. This proves parsing/binding only, not metadata provenance.

`horizon_legacy_poh::verify_v1_4_25_poh_chain` verifies each ordered decoded entry
from an independently supplied parent hash, carrying tick work across batch
boundaries. It executes the pinned ordinary-SHA/signature-root mixin semantics,
checks every tick's exact work, extracts every hidden/final slot-ending hash at
trusted tick ordinals and requires the independently supplied visible final hash.
It rejects incomplete/extra work, zero-work entries, disabled hashing, wrong
clock/scope/shape, reordered/corrupt chains and repeated boundary hashes. Hash
work is bounded before execution; a caller guard also runs within long entries.
Independent bounded execution and authenticated clock/parent/final inputs remain
caller obligations. It never infers missing boundaries, uses Bank hashes as PoH
hashes, or grants source, runtime or publication authority.

Tests cover the complete synthetic metadata→shred→entry→PoH path and a tampered
entry. The pinned Rust 1.46 v1.4.25 SDK `hash`/`hashv` fixture independently supplies
three golden boundary hashes and a bincode 1.3.1 SlotMeta wire digest, asserted by
the modern decoders. These are synthetic SDK primitive/layout checks, **not** a
real-ledger run, upstream full Entry-crate qualification, recovered epoch 141
boundaries or canonical checkpoint/plugin/publication evidence.

`horizon_legacy_recovery` binds the exact logical lookup set to the entire
independently supplied post-gap target census. The pinned blockstore keys are
eight big-endian slot bytes for `meta`, and two big-endian u64s (slot/index) for
`data_shred`; layout is checked against revision 893cc764's `blockstore_db.rs`
SHA-256 `7391732d9c41d09cdf4f1c9997c9ee37ccace9040aa5845249918084bcc0b046`.
An initial complete metadata query determines every owed contiguous data index.
A second native read must include unchanged metadata and every planned data key.
Each native call still requires the same complete admitted census, independent
family allowlist and the native core's full before/after integrity checks.

The bridge rejects missing, extra, reordered, substituted or absent logical
records before assembling all batches, decoding all entries and verifying all
target chains under one aggregate hash-work bound. It also rejects a reused
boundary across separate targets. Its eleven-target integration is synthetic,
not actual epoch 141 recovery or native provenance. Borrowed candidate records
are not authenticated merely because this bridge accepts them. Trusted real
clock, canonical anchors, backup/native evidence and persistent guarded receipt
production remain separate caller obligations; there is no operational native
recovery caller or runtime/publication promotion here.
The explicit native crash-shaped WAL fixture also writes eleven synthetic
SlotMeta/shred pairs, collects the complete database through multistream bzip 2,
performs both full-census native query stages and verifies all 33 synthetic
boundaries through this bridge. This is end-to-end disposable-fixture evidence,
not original-backup completeness or real historical PoH recovery.

`jetstreamer-epoch141-ledger-native` is a separate feature-gated, offline native
**candidate** runner. It requires exact source verification, a successful retained
collection and its independently bound complete census, the fixed authenticated
eleven-target gap audit, an explicit complete family policy and fresh admission
of the exact executable plus 256 MiB for outputs/logs above the unchanged protected
floor. Database, private logs and results must share the admitted filesystem.
Each of its two native reads rehashes the entire retained census before/after.
Topology-only query planning never invents or assumes a PoH clock.

The first metadata result is durable even when an absent/incomplete SlotMeta
prevents further planning. The second result preserves missing candidates or
metadata changes explicitly and exits unsuccessfully for either case. Candidate
bytes use bounded base64 rather than unbounded pretty-printed byte arrays. No
result proves original backup completeness, historical live state, trusted clock,
recovered boundaries or replay/publication eligibility. A candidate artifact is
not a successful terminal service receipt. Preserve failed attempts and logs;
do not reuse their paths, retry automatically or silently drop missing records.

Seal the exact executable and plan, qualify the actual sandbox/read paths, run
fresh admission and prove its first real guard before use. Enforce independent
CPU, memory, task and oneshot start-time limits; a read callback cannot interrupt
blocked native syscalls. The current tests cover source/census/target/admission
substitution, native fixtures and root-private no-clobber receipt writes only.
No real retained epoch 141 database or actual-source native run is established by
this source. Trusted clock/anchored PoH and all canonical gates remain separate.
