# Epoch 159: diagnostic legacy recovery, not replay approval

The retained failed 159–162 cohort is a source-level incident. Its first observed
canonical vote failure at 68,688,001 follows five source-obscured parent jumps
inside 68,687,833–68,688,001. The independent audit binds five post-gap targets,
11 skipped slots and 16 required ending-tick boundaries. This is not a census of
the complete execution span. RPC parents and visible final hashes do not recover
hidden intermediate hashes.

The candidate compressed source is generation-pinned:
`gs://mainnet-beta-ledger-us-ny5/68687833/rocksdb.tar.bz2#1634790146653938`,
179,174,594,397 bytes, CRC32C `CLbFDQ==`, MD5 `24oFLsJGTn+FhzIg3nDsyQ==`.
Retained metadata proves neither downloaded bytes nor actual target coverage.
No source download, native open or replay is authorized by this document.

## Explicit v1.5.6 diagnostic decoder

`jetstreamer_utils::horizon_legacy_v1_5_6` names the exact runtime revision
`01e4d0a1e9917701d1a148e1043b0ccf545c27f1`. It offers `plan_scope_queries`
and `recover_records`, reusing the bounded wire implementation after reviewing
the pinned upstream difference from v1.4.25:

- Entry, SlotMeta and signature-Merkle source files are byte-identical.
- Shred changes add instrumentation, derives and tests; header fields, flags,
  padded data region and deshredding are unchanged.
- Blockstore backend API changes do not change meta/data-shred key layouts.
- The transaction change is an import relocation, not serialized fields; the
  Message layout remains identical.

The source-pin test checks the exact Git revision and seven original source
file digests. Run it explicitly against a retained upstream checkout:

```text
HORIZON_V156_UPSTREAM=/absolute/upstream/checkout cargo test -p jetstreamer-utils --lib horizon_legacy_v1_5_6::tests::pinned_upstream_sources_match_reviewed_wire_semantics -- --ignored --exact
```

This is source-identity evidence, not a compiled historical-runtime differential,
an actual-source scan or a canonical checkpoint test. The five-gap regression
uses the real topology but deliberately synthetic hashes and a tiny synthetic
clock. Its 16 boundaries are not historical epoch-159 hashes. The complete
underlying legacy decoder/PoH suites remain required.

Both entry points retain complete exact-key censuses, metadata rereads, all
contiguous shreds, bounded padding/entry decoding, trusted external clock/anchors,
aggregate hash limits and unique boundaries. A failure returns no partial trusted
set. Every successful result still denies source completeness and publication.
The existing epoch141 fixed-input acquisition tools are not v1.5.6 operational
profiles and must not be relabeled to consume this source.

## Remaining operational gates

Determine the compatible full execution/root span first, then census every parent
jump over that span. The retained planning root 69,119,821 is 178 slots short of
the end of epoch159; it cannot establish full-epoch completion. Preserve the live
epoch160 singleton and do not launch an overlapping cohort to reach a later root.

Acquire or stream the exact generation only after fresh complete resource
admission. Independently establish full tar/LSM/MANIFEST/WAL/column-family/live-SST
coverage, native version/tombstone resolution and the actual source bounds.
Qualify the v1.5.6 decoder against independently generated historical-runtime
fixtures and real complete source records before treating candidate PoH hashes as
trusted runtime input. Require the ordinary canonical checkpoint, full archive,
current-plugin and authenticated R2 gates separately. No hidden boundary may be
invented or repeated, and the initial five-target audit must not be broadened into
a full-span receipt.
