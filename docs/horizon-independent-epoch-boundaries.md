# Independent epoch boundary expectations

`tools/horizon_epoch_boundaries.rs` prepares the current reader's independent
parent and terminal expectations before an epoch archive finishes. It reads
finalized metadata from `https://api.mainnet-beta.solana.com`; it never opens a
local archive, launches replay, verifies archive contents or mutates R2.

Run the sealed binary as root with `PLAN --plan-sha256 HEX --self-sha256 HEX`.
Use `horizon-independent-epoch-boundary-plan-v2` for epochs 101–300. The v1
plan accepts epochs 201–300. Both require an existing, empty, canonical
root-owned mode-0700 `output_directory`. A no-clobber intent prevents concurrent attempts from sharing
that directory. Preserve failures and use a fresh directory for another attempt.

The collector obtains the ordered block census for the first 1,024 epoch slots,
then reads the first block, its parent and the exact terminal slot. The first
block must point before the epoch boundary, its previous blockhash must match
the independently fetched parent, and the terminal parent must lie inside the
epoch. A skipped or unavailable terminal slot triggers a bounded tail and next-epoch
block census. The collector fetches the last produced block and first successor,
and requires that successor to name the exact last block as its parent with a
matching previous blockhash. Both plans retain the linked blocks and their RPC requests. A v2 plan emits a
v2 expectation after verifying the link. A v1 plan stops after saving the evidence.
Every blockhash must decode to 32 bytes. TLS validation remains enabled, redirects
are disabled, each request has a 30-second timeout, and each response is limited
to 1 MiB. The containing qualification service also needs a bounded runtime.

Raw responses and request records bind the endpoint, finalized commitment,
requested slots, response hashes and actual collection times. The resulting
`epoch-N.json` includes their exact paths and SHA-256 values and is compatible
with the current-reader plan's `epoch_expectations` map. Every output is created
without overwriting and fsynced with its parent. Seal the expectation and its
evidence before selecting it for a production delivery plan.

Tests reject unordered, duplicate, out-of-range or missing block censuses,
disagreeing parent hashes, invalid boundary relationships and malformed hashes.
These checks provide independent expectations only; full current-reader decoding,
plugin playback, authenticated remote playback and publication gates still apply.

## Epochs ending in skipped slots

`horizon-current-reader-epoch-expectation-v1` still requires a produced block at
the epoch's final slot. A v2 expectation requires a last produced slot inside the
epoch and a `successor` object containing `slot`, `response` and `request`. The
latter two are immutable path/SHA-256 bindings and must also appear in
`independent_evidence`. The request must name the public mainnet RPC endpoint,
`getBlock`, finalized commitment and the exact successor slot. The response must
match its request ID and name the expected terminal slot/hash as its parent.
The successor must lie beyond the epoch's end; malformed or missing evidence
fails closed.

The uploader passes this evidence to strict full verification using
`--expected-successor SLOT PARENT_SLOT PARENT_HASH`, together with the independent
anchor and expected terminal. The verifier requires its actual final decoded
block to match that parent and requires a genuinely skipped tail. This option
does not allow partial or internal-only verification, omit PoH validation, or
replace full local and remote plugin playback.

Epoch 251 provides a concrete case: its last produced block is 108863995,
followed by four skipped slots, and finalized successor 108864012 names that
block and its hash as parent. The immutable request/response evidence was
collected independently of the replay archive. The v2 collector plan binds the retained successor request and response to the
expectation. An exact terminal slot uses the v1 expectation format with either plan.

Qualification covers a synthetic full 432,000-slot archive with a skipped tail,
ordinary complete playback, and rejection of missing/wrong successors, partial
coverage, missing epoch metadata and bad PoH. A root-only ignored native test in
`current_reader.rs` accepts `HORIZON_TEST_TAIL_EXPECTATION` as a JSON path/SHA-256
binding and validates the real sealed epoch-251 evidence through production
argument construction. Run native playback with the qualified
`RUST_MIN_STACK=67108864` setting. These tests do not verify a canonical mainnet
archive or authorize R2 publication. Rebuild and qualify the uploader and reader
acceptance against the published source before using v2 for production delivery.

### Foundation qualification, 2026-11-19

Published source `db1c31fe4e6d462a8e45c18c61f6b331a9c1a1c6` passed
25 verifier tests, nine ordinary reader-gate tests, the explicit native test of
sealed epoch-251 evidence, Clippy with warnings denied, and the synthetic native
playback cases above. The 131,073-update historical-capacity probe also passed.
The verifier and fixture were rebuilt from a fresh archive of that exact Git
commit and reproduced the tested binaries byte-for-byte. The accepted dependency
manifest's 165 hashes were rechecked successfully. The plugin and reader library
sources remain identical to the preceding `135657fe` acceptance; the only changed
reader paths are the verifier and synthetic fixture examples.

The rebuilt uploader and acceptance dossier are sealed on Foundation at
`/var/lib/jetstreamer/horizon-skipped-tail-qualified-db1c31fe-20261119-v1`.
Uploader SHA-256 is
`02ae4dd1eafbb614b8ddf984817b3d544cbf68180e62613818fd49ff972c4ba4`;
verifier SHA-256 is
`f31ada10fd7e25247176c602f72fdaecff51d2fcb95bf40a6956f4db837f1e1f`.
The dossier retains build commands, systemd test/build evidence, native results,
dependency checks and the exact predecessor acceptance. Serial compilation and
native qualification used a 2 GB memory cap, zero swap and four CPU cores' quota.
An initial synthetic retry omitted the required worker-stack setting and failed;
its evidence is retained. The corrected invocation passed with the 64 MiB
thread-stack value bound into the acceptance.

Fresh dormant reader plans for 247–251 are sealed at
`/var/lib/jetstreamer/horizon-reader-delivery247-251-db1c31fe-20261119-v2`.
They bind the new acceptance and independent boundaries, including the v2
successor expectation for 251. These plans are preparation only: fresh terminal
handoff, delivery resource admission, verification, upload and remote playback
remain required. The running epoch-205 audit retains its original plan and
cannot establish latest-branch compatibility after this verifier source change;
preserve its work and requalify through the normal current-reader gates.
