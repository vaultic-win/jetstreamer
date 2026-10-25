# Epoch 223 parent 96,544,587: source-only causal regression

The finalized failed signature is a successful Vote in slot 96,544,588. Its
`5UsE976...` Bank hash differs from the replay parent `GRD2nwB...`. The saved
replay SlotHashes matches 535 successful finalized Vote instructions for Bank
96,544,586 (`3PMZX37...`); 343 successful finalized Vote instructions name
`5UsE976...` for Bank 96,544,587. These are voted Bank hashes. The independently
returned PoH blockhash `BrifEBc...` is a different commitment.

The reviewed raw evidence is sealed at
`/var/lib/jetstreamer/horizon-native223-e70a-finalized-vote-diagnosis-v1`.
Its 32-member seal plan is
`.codex/tmp-readiness/native223-e70a-finalized-rpc-v1/seal-finalized-diagnosis.json`,
SHA-256 `591d6a1bb52a55db1b19087f9bf8c4c18833eabeada02d78adb9ddfc7df58d0e`.
The exact diagnosis digest is
`1f9320d32c2ccf51a45731a0084a1f9e25875fc808c2fb30abede5cea77b00a6`.
Raw request/response/header bodies remain preserved.

## Concrete parent transaction and test boundary

Parent transaction 432, signature
`358YDY6TSXgU4X8Q1UzjPRrYTzBCz8CKE9tbS5neXZYWNPuo2bvWrcmji1RiWS8mbvokPxS5vF1TMP3Htymyruj8`,
is the block's only raw-writable called program case. SPL Token is key 3 among
17 keys, with three signers and four readonly unsigned keys. It is directly
called by instructions 1, 3 and 5 and passed to Raydium instruction 4. Finalized
pre/post program lamports are both 1,089,991,680.

The pinned 1.6.20 SDK treats key 3 as writable and non-loader; its runtime store
path includes the successful program account. The 1.6.25 SDK additionally
demotes a directly called program, excluding that key from this store path.
AccountsDb hashes slot-local dirty keys; Bank hashing incorporates that delta.
An unchanged extra program account can therefore affect the Bank hash.

The two wire fixtures and their public RPC provenance are in
`historical-runtime/fixtures/epoch223-parent432-provenance.json`.
Each worker's new test-only module calls its **actual public
Accounts::store_cached** path, scans the actual slot-local keys and checks that
only the old version stores key 3. Both reuse one shared regression source.

The Bank regression creates two independent synthetic parents with identical
initial state, stores the identical common account set, and stores one
unchanged program value into only one child. It asserts identical visible
fixture-account values, different actual AccountsDb slot deltas and different
frozen Bank hashes, with equal parent hashes, signature counts and PoH hashes.
It executes neither the historical Raydium transaction nor its Vote, and
restores no snapshot. Synthetic loaded values are explicit; this is not a
reproduction of mainnet Bank state or the counterfactual `5UsE976...` hash.

These tests have been prepared but not compiled or executed. The shared target
lease belongs to another repair. Formatting and source-diff checks do not prove
the assertions pass.

## Bounded qualification and patch proposal

After the target lease returns, run only the named three-test module in each
pinned Rust 1.51 workspace, serially, with bounded Rayon/PoH/Tokio environments
and a separately reviewed build-resource envelope. Use the existing locked,
offline dependency graph. Do not add the excluded vendored runtime crate as a
new workspace member, resolve a fresh dependency graph, run native snapshot
tests or start replay to qualify this fixture.

If those checks establish the predicted store/hash difference, review a
complete called-program demotion semantic correction within a private epoch
223 compatibility profile, or an already supported alternative private runtime.
Do not change only the emitted-account attribution map: lock selection,
load/rent, instruction/CPI writability and account storage must remain
consistent. A global SDK/runtime promotion is outside this proposal. The old
native bootstrap proof cannot qualify a different worker generation.

Before accepting a causal production correction, reproduce actual Bank
96,544,586 and then Bank 96,544,587 = `5UsE976...`, followed by the exact
successful Vote at 96,544,588, through a separately admitted bounded comparison
from a trusted canonical checkpoint. The failed partial archive is not a
resumable Bank. If only bootstrap 96,335,538 is trusted, disclose that replay cost
before launching. Do not force a hash, duplicate hard-fork markers, skip a vote
or relax transaction/PoH verification.

Complete prefix root 96,767,522, the 477-slot suffix, assembly, independent
full/current-plugin/boundary verification and sidecar commit remain separate
gates. No test, fixture or RPC response grants replay, promotion, publication,
retirement or R2 authority.

## Genuine active repair ownership and status

The terminated `e70a...` replay cannot own a repair countdown. Its stale status
was correctly retired. No deployed generic epoch 223 repair issuer exists.
`repair141.rs` / `repair141_model.rs` provide an analogous reviewed **native
task queue**, not permission to reuse epoch 141's fixed unit, paths, task slots,
ELF digests or publisher.

A narrow separately reviewed Rust `repair223` adapter should use its own exact
unit `horizon-repair-223-e70a-20261025-v1.service` and root-private namespace
`/var/lib/jetstreamer/horizon-epoch223-active-repair-e70a-v1`. Proposed entrypoints
are `repair-owner-223`, `repair-task-capture-223` and
`status-publish-repair223`. They are proposed commands, not existing issuers.

The queue must manage frozen, actionable tasks for actual wire-fixture QA,
actual account-store/Bank-hash causality, compatibility/native-input admission
and later canonical prefix/suffix/delivery. Every task intake must bind its
reviewed work plan, exact native task program and argv, zero-restart PID1 IID,
PID, process start ticks and eventual genuine result/log receipts. A hash-bound
Cargo/test task needs an exact reviewed native runner and resource envelope;
do not start a sleeper or a status-only child and call it repair progress.

The genuine queue capture must bind its running ELF, unit, PID/IID/start ticks,
source/evidence policy, accepted complete predecessor fleet and the original
failed owner. Fleet/status integration must append only this real repair actor,
retain all failed diagnostics and current 204/209/225 claims, and account for
the queue and any actual task's resources. The queue may supervise short gaps
between real admitted tasks; it must not invent successful tasks or silently
survive an unrecorded task failure.

The publisher must require this genuine owner independently of the estimate,
root-sealed reviewed positive stage allowances, authenticated conditional
publication/readback and durable status receipts. Wire phase is
`verification` for source/compatibility work. The definite numeric estimate
must include target/admission wait, remaining engineering/native-input work,
any full restart from the last trusted checkpoint, prefix root, suffix,
assembly, all independent checks, upload, whole-object readback and canonical
sidecar commit. Retain the authoritative original epoch clock from sealed
launch/status evidence; do not reset it to a repair poll or reuse the dead IID.

Publish the initial status immediately after genuine queue launch/registration,
then refresh from the sole 30-minute campaign observation. Preserve user-requested
out-of-band updates and failure/handoff events. No second resource polling loop
is needed. Queue failure must preserve the open repair and transition status
through a supported terminal/repair handoff. This issuer qualification is
required follow-up work, not a justification to leave active repair invisible.
