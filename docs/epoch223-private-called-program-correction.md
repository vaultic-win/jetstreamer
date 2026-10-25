# Private epoch 223 called-program correction candidate

This is source preparation, not a qualified historical fix. Baseline commit
`29b4a8bb17e47ee334305aa02bdad0d96eeb26a4` and its actual six passing tests
and two passing strict test Clippy checks remain unchanged in the separate
`native223-e70a-store-regression-worktree`. Their actual report is
`.codex/tmp-readiness/native223-parent432-qa-29b4-v1/actual-qa-handoff-v1.json`,
SHA-256 `ce60a8713a0ef60f1bd3a3c7416c0c1a3be8adb6d016b78a61480a6e1d8215e6`.
The synthetic Bank sensitivity is not the canonical mainnet Bank hash.

## Small correction and isolation

Vendor only the original `solana-program` 1.6.20 package from exact Solana
commit `77bdb45d4af61fc687161ec06cc0178ff79726d5`,
Git subtree `1721f71c78bb7e9a1158f4f57c3ea2a26320c125`.
Retain its source and root license; materialize its original build.rs symlink
as the identical regular file from pinned frozen-abi/build.rs, avoiding an
out-of-tree symlink in the vendored package. Four path dependencies become
Git dependencies pinned to that same revision; no versions are advanced.
The workspace patches this Git source for every transitive SDK user.
The prepared lock change removes that package's Git source and adds the
worker's direct dependency, preserving the old graph's package versions.
Cargo has not validated this prepared lockfile.

The sole SDK semantic addition to `Message::is_writable` is rejection of a key
whose index is a top-level instruction's `program_id_index`, gated by default-off
`epoch223-called-program-demotion`. It does not change the wire header,
serialization layout, signatures, sysvar-demotion feature flag, fee rules,
`is_non_loader_key`, loader loading, hard-fork markers, builtins, or Bank hashing.
It deliberately does not demote a program that is merely passed as an account
without being directly called. This is the specific 1.6.25 Message rule being
tested inside 1.6.20; it is not an assumption that all later runtime changes
are applicable.

The worker feature enables the SDK feature and exact existing private 223 prefix
scope. A compile-time assertion rejects disagreement between the worker and SDK
feature, including unexpected feature unification. The backend identity becomes
`solana-v1.6.20-epoch223-called-program-demotion-candidate`; the qualification is
still Candidate. No ordinary parent registry or publisher is edited to accept
it. The ordinary default build keeps its old identity and old writable behavior.
The feature cannot combine with other eras' qualification or singleton
diagnostic features through the existing prefix exclusion gates.

A separately selected `epoch223-called-program-bracket` feature caps entry
execution to 96335539..96544588 inclusive, rejecting 96544589 before decoding or
Bank mutation. It cannot combine with the sixteen-slot warmup. The full-root
candidate omits the bracket feature and retains end 96767522. Both require
the exact cold snapshot slot 96335538; neither supports resume from a partial
archive.

For the private semantic candidate only, a naturally frozen real Bank at
96544586 or 96544587 is compared to the sealed finalized Vote-derived canonical
Bank hash before rooting. A mismatch fails with both expected and actual hashes.
A match emits a diagnostic record. The helper never assigns, injects or overrides
a hash. These assertions do not synthesize a trusted restorable checkpoint.

## Writability use review

| Boundary | Original use | Effect of the shared Message correction |
|---|---|---|
| Message lock classification | SDK `get_account_keys_by_lock_type` | Same corrected predicate for read/write partition |
| Actual lock / unlock | runtime `accounts.rs` 788, 833, 848 | Corrected classification on both acquire and release; wave probes use Bank's same locks |
| Instructions sysvar | SDK `serialize_instructions`; runtime `accounts.rs` 177 | Passed Token metadata becomes readonly consistently |
| Account load / rent | runtime `accounts.rs` 211, 219, 228 | Keep non-loader participation; writable-only rent and sysvar rejection consult corrected rule |
| Native instruction privileges | `message_processor.rs` 587, 992 | KeyedAccounts and post-instruction checks use corrected rule |
| CPI caller privileges | `message_processor.rs` 672, 750, 850, 1035 | Derived readonly KeyedAccounts flow into caller-write privilege capture and escalation checks; no separate permissive override added |
| CPI generated messages / account copies | vendored BPF `syscalls.rs` 2266 | Uses the same SDK type and corrected predicate; executable copy exclusions retained |
| BPF ABI and copyback | vendored BPF `serialization.rs` 100, 137, 218, 264 | Consumes KeyedAccount writability already derived above; no ABI change |
| Successful and nonce rollback store selection | runtime `accounts.rs` 953, 967 | Actual `Accounts::store_cached` omits the demoted dirty leaf; existing result/nonce/fee guards retained |
| Bank fee-payer/non-loader handling | runtime `bank.rs` 549 | Existing first non-loader payer selection unchanged; sanitized program cannot be payer |
| Worker attribution | worker `writable_key_attribution` | Uses same corrected rule, not an attribution-only filter |
| AccountsDb / Bank hash | runtime native hash path | No hash algorithm changes; changed stored dirty-set membership is the proposed cause |

The CPI native path also accepts explicit caller privilege vectors; those are
captured from native KeyedAccounts, which now receive the corrected top-level
rule. The actual historical transaction and CPI still require the native
comparison; static review and wire-only tests do not establish execution success.
Upgrade/loader behavior elsewhere in the era is not implicitly qualified by this
case, and no upgradeable-loader exception is invented.

## Source checks and requested build review

New worker regression module has four non-native tests: exact original wire
signature/roundtrip plus writable lock/attribution/instruction-sysvar agreement;
actual native lock-manager sharing/unlock; passed-only program and original
sysvar flag behavior; and canonical hash comparison rejecting the old replay
hash and the unrelated PoH blockhash. Existing actual `store_cached` regression
expects Token included by default and excluded only for the candidate. Existing
225 wire expectations are feature-aware, but that does not admit replay of 225.

No Cargo, native input tests, replay, cloud bodies, fleet/resource polls or R2
operations have run for this candidate. Only direct pinned rustfmt on new test
source / modified vendored Message and `git diff --check` ran.
Ask the campaign owner to review this patch and envelope before ANY Cargo
command, including metadata or lockfile resolution.

Proposed first QA envelope: sequential commands, -j2, MemoryHigh 14 GiB,
MemoryMax 16 GiB, swap 0, CPUQuota 200%, TasksMax 512, RuntimeMaxSec 1800 per
command, at most 16 GiB changed/new artifacts across both default and candidate.
Target lease must be explicitly reacquired; root main target is not available.
The new SDK source identity will rebuild dependent Rust crates. Stop on an
unexpected native C/C++ dependency rebuild or cap exhaustion; preserve failures.

After approval, first confirm the pinned offline graph/lock resolves without
unrelated changes. Test the three `epoch223_parent432_store_regression` cases,
four `epoch223_called_program_demotion_regression` cases, candidate range test,
prefix out-of-range rejection, existing 225 wire rule, and candidate handshake
under default and bracket features. Run strict primary test Clippy using the
legacy Rust 1.51 suffix `--tests -- --no-deps -D warnings`. Check both full-root
and bracket feature combinations and negative cross-scope compilation. Do not
invoke ignored snapshot tests as part of this source QA.

## Nearest already cached trusted input

A read-only name census of the immutable package/private state roots plus
preserved source/terminal proofs identifies the closest evidenced pre-divergence
restorable snapshot as:

`/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst`

Length 9,815,262,303 bytes; SHA-256
`301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665`.
The matching genesis archive SHA-256 is
`133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945`.
The later cached snapshot 96767522 is after the mismatch and cannot seed its
counterfactual. Saved hashes at 96544586 and the e70a partial archive/scratch do
not constitute a trusted restorable Bank. No closer input was established.

The preserved actual native20 release-test journal reports this exact bootstrap
tuple: Bank `8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F`, accounts
`Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE`, last PoH blockhash
`9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa`, capitalization
503889539326183230, transaction count 27822879094, tick height 6165474496,
next write version 105933183112, zero replay entries and bootstrap writes.
The cold-input test is made available under the new feature and asserts that
entire tuple. Old binary success cannot qualify the new binary.

## Separately admitted historical comparison

1. Complete reviewed source QA; preserve old QA and commit immutable successor.
   Build/seal exact candidate worker and separately reviewed native runner and
   parent adaptation with new hashes. The old sealed runner hardcodes the old
   worker hash/backend and must reject this candidate. Do not widen or overwrite
   its package. Run exact no-worker capability proof for new parent/runner.
2. Implement and qualify genuine repair-owner/task capture and status issuer
   before advertising ongoing native repair execution. Bind live task program,
   frozen argv/plan, PID1 IID/PID/start ticks and terminal result, not dead e70a
   or a sleeper. Publish definite numeric sidecar-inclusive ETA with target/admission,
   engineering, input, restart, root/suffix/assembly/check/upload/readback
   allowances. Retain original epoch clock and sole 30-minute observer cadence.
3. Obtain fresh full-fleet admission from root, including 204/209/225, actual
   century floor, all live task caps and whole-root disk reservations. Reuse
   the old 225 GB max / 150 GB high, swap 0, CPU 800%, Rayon 2, PoH 1, Tasks 512,
   300 GB scratch planning plus 160 GiB output/overhead only as a proposed
   conservative envelope. Old 2 TB floor and 480 GiB available reserve are
   historical plan constraints, not freshly established host availability.
   Do not lower or claim them met without owner admission and pinned guard.
4. Run a new independently sealed bounded cold-input-only invocation, with exact
   new ELF and source snapshot/genesis hashes, dedicated fresh root/scratch and
   native test filter. Maximum 3600 s; no replay, upload or canonical sidecar.
   Require exact bootstrap tuple above, all feature/hard-fork validation,
   zero bootstrap writes and no replay. New result must succeed naturally.
5. Separately admit bracket execution from 96335539 through 96544588. This is
   209,050 slot numbers, not a two-slot replay. Preserved uncorrected progress
   was about 2.63 slots/s: approximately 22.1 hours before initialization and
   overhead. Propose a 36-hour hard bound, subject to fresh capacity review.
   Bind any reused local CAR input to complete immutable provenance; otherwise
   the later runner must pin/verify its established source read route. No new
   source body is fetched by this preparation.
6. The bracket worker must freeze and compare real Bank 96544586 to
   `3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso`, then real Bank 96544587 to
   `5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7`, without injected state or
   ignored verification. The runner must bind both actual diagnostic records,
   exact parent transaction 432, and exact original Vote wire/signature at slot
   96544588 entry 4 / tx 0 to native successful results. Require complete entry,
   transaction, fee and PoH verification for the entire bounded span and reject
   absent records. PoH `BrifEBc...` must never substitute for voted Bank hash.
   Freeze/retain actual terminal tuple at completed 96544588; fail closed on any
   prior mismatch. This diagnostic partial archive has no sidecar authority.

## Real root and delivery obligations after a passing bracket

The bracket is a causal comparison, not a supported resume snapshot. Current
1.6.20 worker refuses snapshot export. Unless a new native export/import path is
independently implemented and qualified, the next full-root candidate must
restart from 96335538, disclose the duplicate replay cost, and naturally finish
96767522 under a fresh full-root plan. Do not assume the diagnostic scratch is
resumable. Keep both real accounts and Bank commitments at the root:
accounts `3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7` and Bank
`EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB`.

Independently reread/qualify the 431,523 recorded prefix slots 96336000..96767522.
Then qualify the real native restart, complete 477-slot suffix
96767523..96767999, prove separate write cursor/event mappings and complete
432,000-slot coverage, assemble, and run independent full/current-plugin checks.
Normal R2 authenticated upload, whole-object readback, source revalidation,
canonical sidecar commit/readback and durable receipt remain mandatory.
Retire status only after committed sidecar or positively supported inactive
handoff. Preserve genuine repair ownership throughout; passing this candidate's
tests or bracket cannot close the failed epoch.
