# Current account-updates reader qualification

The publication requirement is archive readability by the latest fetched
`origin/account-updates`, in addition to full/plugin verification and authenticated
R2 byte readback. Source ancestry alone does not prove reader equivalence.

The existing delivery pins are `verify_archive` SHA-256
`6ff8a6be80712b258577c027bf3512274a9c7d9f326b77a5cb07906205125302` and
`horizon_pipeline` SHA-256
`853c8a3f7448a75afbeea1fdf6b6e6e4f0001e970162bc2ad3b05e01d29f3c5b`,
from `/var/lib/jetstreamer/horizon-components-bd100a55-source-v1`.
Its tracked-source manifest identifies `bd100a55305625c466fefa90427d4e61ae1c743c`.
Comparison with `3406f4c6f5895ffd81456136dc53d4a1cfc28427` finds substantive
transaction-decoder changes, including the bounded message-instruction arena.
These older pins cannot establish latest-reader equivalence merely because their
source revision is an ancestor. Existing verification receipts remain evidence
of what those exact binaries checked; they are not relabeled as latest-reader proof.

A newer retained candidate exists at
`/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1`:

- Source: `eabd0b6a78464130d1e30eff30bb75267502abde`, contained in account-updates.
- Full verifier: `3233765365f4ac3c221682dcae7d99bf4ba5f3da2eebb43c2d7d5491020c53ed`.
- Plugin pipeline: `0a93feed69b0ded0c4a3382ad6aa6fcbf644ebb76617a660fb574ccc3ccd1ae3`.
- The sealed source manifest reports a clean 3,512-file source tree. Its digest is
  `e389f94315910f81fc7e63337a62498b09ddafbe303d9b5e066b4290360eee55`.
- Actual binary hashes match the seal. Both captured Cargo fingerprints report
  empty package features and the GCC 15 / bfd linker flags.
- On 2026-11-18 the full verifier's bounded capacity probe decoded 131,073 pre
  updates successfully under `horizon-current-reader-capacity-probe-20261118-v1`.
- The plugin capacity probe decoded 71,524 records and 1,144,384 account-data
  bytes under `horizon-current-plugin-capacity-probe-20261118-v1`.

These probes are limited capability checks, not full canonical archive scans or
publication acceptance. Qualification still needs exact effective reader and
dependency equivalence against a freshly fetched account-updates revision,
normal sandbox/capacity qualification for the selected artifacts, and full/plugin
verification of each archive selected for publication. If equivalence cannot be
established, build and qualify the latest branch instead. Update uploader pins
only after that evidence is accepted; do not silently reuse old receipts.

The 34-epoch century-floor census normalized by `tools/horizon251-launch5` is
capacity evidence only. It explicitly sets
`latest_account_updates_reader_compatibility_proven` to false. No existing R2
archive has been modified by this audit, and no complete latest-reader audit of
all historical R2 archives is claimed.

The uploader's `sync_epoch` implementation was inspected at published commit
`db7a9bea562a5f18ce42de394e064d4675e54fa9`. It still permits the canonical sidecar
step after remote checksum proof and local revalidation without a receipt for
full playback of the actual remote archive through the current plugin. This
implementation does not yet enforce the skill's remote-playback requirement.
Do not select that path for a new archive publication until the Rust uploader
and coordinator enforce the required playback and current-reader evidence.
Status-only publication remains independently usable. Existing remote pairs
remain preserved; this finding is not evidence that their contents are corrupt.

The first implementation step adds `horizon_pipeline --verification-report PATH`
for single-epoch `--verify-only` runs. The plugin records observed minimum and
maximum delivered slots, including legitimate leader-skipped notifications, and
checks those boundaries alongside its existing coverage and callback checks.
After normal pipeline completion, the CLI writes a private, no-clobber, fsynced
JSON report containing the actual source, invocation, observed boundaries,
counts and stream digest. Missing reports, interruption or write failures cause
failure. The uploader must independently require clean process exit and bind
this report to its authenticated readback copy, reader artifact and current
branch evidence; the report alone grants no publication authority.

The bounded package `tools/horizon-playback-report-tests` compiles the production
report module directly. Four tests cover successful persistence, incomplete
coverage, invalid ranges, relative paths, existing files and symlinks. Full
plugin/pipeline compilation and execution remain separate qualification steps.
The uploader and progressive coordinator still need integration: actual remote
scratch readback, full playback, current-reader equivalence recheck, and receipt
enforcement before sidecar commit. No new archive publication is authorized by
this prerequisite implementation.

At the 2026-11-18 21:21:48 UTC coordinated sample, epochs 247–250 continued
advancing and epoch 251 remained in snapshot restore with no transaction rate.
All five status JSONs were refreshed through the native publisher with
authenticated readback. The full-range fleet census remained 34 ready pairs,
66 missing and zero anomalies, with no diagnostic incidents. Epoch 251's native
status now uses its actual producer start instead of the earlier repair-owner
elapsed time. Its 102-hour initial planning allowance includes two hours of
startup, 80 of replay and 20 of delivery/current-reader qualification; only
actual elapsed startup time was deducted while replay remains unmeasured.

The complete pipeline passed `cargo check --offline --locked -p jetstreamer
--bin horizon_pipeline --jobs 2` from the isolated published `3a410a30` checkout
at 21:42:43 UTC. The process completed normally in 10m10s under a 7 GB cap,
with a reported 4.5 GiB peak. This checks integration compilation; it does not
produce or qualify a playback executable.

The uploader/coordinator source now adds mandatory `--current-reader-plan` and
`--current-reader-plan-sha256` options for publication/verification. Other
commands retain their existing interfaces. The sealed plan binds the repository
and SSH origin, qualified reader source commit, exact full-verifier/pipeline
artifacts, a sealed Main acceptance with compiler/features/build evidence,
bounded threads, maximum archive length, private readback scratch and admitted
filesystem floor. Main acceptance must follow genuine captured-build and native
capability evidence; creating a plan alone supplies neither.

The gate fetches `account-updates` and conservatively compares the reader crates,
workspace manifest/lockfile, vendor inputs and compiler/build configuration.
It runs the full verifier and plugin on the staged local archive before upload.
It then requires whole-object authenticated R2 readback into a newly created
separate file even when a native checksum is available, freezes that file,
checks its length/SHA and plays it through the full plugin. It validates the
actual invocation, full observed slot range, counts, digest and clean exit,
then rechecks the readback identity/hash. Before the sidecar step it revalidates
the local source, checks the remote object's identity, fetches the branch again
and writes immutable playback acceptance. New canonical local delivery receipts
reference that evidence; existing historical receipts remain preserved. A
re-audit may retain an existing canonical receipt while writing its new playback
acceptance separately. Failed attempts preserve their readback files for diagnosis
and qualified cleanup. The ETag-only bypass is rejected.

`tools/horizon-current-reader-tests` exercises the production gate and coordinator
without the full uploader dependency graph. The source integration still needs
full-crate compilation, native end-to-end qualification, sealed deployment and
operational admission. No new publication has been performed with this code.

At published merge `72751e30`, the full uploader and its test targets passed
`cargo check --offline --locked -p jetstreamer-r2 --bin jetstreamer-r2 --tests
--jobs 1` from an isolated clean checkout. The gate's six tests and coordinator's
15 tests passed, as did strict Clippy for both directly compiled targets.
This is compilation and bounded unit/integration evidence, not a native R2 run.

The 21:51:54 UTC observation proves epoch 251 entered transaction replay at
1.888 slots/s alongside the four unchanged advancing owners. All five native
status objects now use measured replay rates and authenticated readback; the
range census remains 34 ready, 66 missing, zero anomalies and no diagnostics.
The memory model now selects nine desired lanes from five executing lanes.
Existing hard obligations plus host/control reserves still leave only 9.64 GB;
another 128 GB candidate does not fit without qualified reservation changes or
a released lane. No sixth lane was admitted.

An isolated release build from `72751e30` started in
`horizon-current-reader-release-build-20261118-v1.service`, invocation
`2d731ba76f644a62b6310a1d45143fa7`. It targets the full verifier, plugin pipeline,
uploader and progressive coordinator with one Cargo job, a 7 GB hard limit,
CPUs 48–55, 400% CPU quota, LTO disabled and 16 root codegen units. Verbose Cargo
JSON and compiler commands are retained in the unthrottled journal. Source
hashes, compiler version and the resource budget are under
`/home/ubuntu/.codex/diagnostics/horizon-current-reader-release-build-20261118-v1`.
The candidate build remains unqualified until normal completion, captured
source/artifact review, immutable sealing and genuine native capability and
end-to-end playback checks. It does not replace any live worker or guard.

Subsequent verifier-call review found that strict `--full` verification requires
an incoming anchor for non-genesis epochs. The initial gate invocation omitted
that anchor and would fail closed. Reader plans now require a sealed per-epoch
expectation containing the parent slot/hash, exact terminal slot/hash, optional
expected provenance digest and independent evidence. The gate passes those
values explicitly through `--anchor`, `--expected-terminal` and, when present,
`--expected-provenance-sha256`; it never derives the trusted expectation from
the archive being checked. Missing evidence or an incomplete epoch range fails
before upload. The currently running `72751e30` build predates this correction:
its reader artifacts can still be qualified, but its uploader must be rebuilt
from the corrected published source before deployment.

At the subsequent branch check, the main checkout fast-forwarded to
`bf365e75d2a424efe08c5757e17de63aac836943`, with zero commits ahead or behind
the fetched `origin/account-updates`. The boundary-expectation correction
`bed735bd` is contained in that remote branch. Comparing the running release
build's `72751e30` source against that fetched revision produced no differences
over the gate's complete conservative reader path set. This permits continued
qualification of those reader artifacts; it does not qualify the older uploader
or replace executable/readback acceptance. Historical archives still require
their actual latest-reader audit. Future changes to the relevant reader sources
or dependencies invalidate equivalence and require renewed qualification.

`reader_playback_qualification` is a native qualification example for the next
artifact build. It generates private synthetic epoch-251 fixtures with the full
432,000-slot range, two PoH-linked transaction blocks, legitimate intervening
skips, epoch updates and both orphan-update phases. It invokes the real pipeline
and strict full verifier, checks the report's exact invocation, boundaries and
all record/byte totals, and requires exit code 1 with no success report for
partial coverage and a missing epoch notification. A wrong-PoH fixture must fail
the strict full verifier. Expectations come from fixed inputs and canonical PoH
construction before archive serialization. Files are created without clobbering
an earlier attempt, and executable hashes are checked around each invocation.

The example passed metadata compilation and strict Clippy against the retained
full-pipeline dependency metadata. This is not yet native execution. Build it
with `cargo build --release --locked -p jetstreamer-horizon --example
reader_playback_qualification`, then run it with an absent absolute private root,
the qualified pipeline path and the qualified full-verifier path. Synthetic
acceptance never proves a canonical epoch or authenticated R2 readback. Adding
this example changes the conservative reader path set, so the subsequent build
and qualification must bind the new published revision; preserve the already
running build and reuse its dependency work after normal closure.

At 22:22:23 UTC all five replay owners were stable and advancing with zero
restarts. Native status publication and authenticated readback succeeded for
247–251. Fleet reconciliation found 34 ready pairs, 66 missing and zero object
anomalies. The final host-resident census was unavailable after membership churn
and a missing `VmRSS` field, so this observation does not establish a new memory
target or authorize expansion. The earlier target of nine is historical planning
evidence only. The saved failure lacks the affected PID/state, so its precise
cause cannot be established retrospectively. RSS observer source now records
that context and recognizes Linux's positive `PF_EXITING` evidence before zombie
state, while retaining complete-census retries and rejecting unexplained missing
fields. Thirteen fixture tests and strict Clippy pass; this observer change still
needs its own artifact/feature qualification before deployment. Existing guards
and the next 30-minute observation remain unchanged.

At 22:47 UTC the checkout and freshly fetched `origin/account-updates` both
resolved to `c1c9fe4898de188e59d064ab7ef508389931afa0`, with no tracked edits.
The corrected successor release build from published `ed61722d` completed
normally in 4m21s, using 4.4 GiB peak memory. Its source manifest remained
unchanged. The conservative reader path set, uploader and coordinator have no
source differences against that fetched branch. Cargo reports pipeline features
`["default"]`; the full verifier, native fixture, uploader and coordinator have
empty package feature lists. The complete Cargo journal and compiler artifacts
are retained, including fresh-cache artifact records.

The Rust sealer published the candidate binaries and build evidence at
`/var/lib/jetstreamer/horizon-current-reader-ed61722d-20261118-v2`:

- Pipeline: `e7356f5397d90f1a65a44ab322301e45cf88d23628f32ac172e1180a5f9fb9b9`.
- Full verifier: `d18723f637fca14622c22cff8303a3815b5e22ce3cf3963298d1a2374050e751`.
- Uploader: `411213a7193c73eb0f588c378e3458fd53ce0bd14aa67ced25c49542b6c766ec`.
- Coordinator: `dcd778ac618623ba56d5ab39cda226cde21052ced7cd394d13a2c9b37e157ba0`.

The actual native fixture invocation `8d33e99d733f488faa79001071312e47`
completed normally in 3.7 seconds with a 476.6 MiB peak. Complete synthetic
epoch playback and strict full verification both exited zero. Partial coverage,
missing epoch notification and invalid PoH each exited one as expected; failed
plugin runs produced no success report. Native results and the genuine journal
are sealed at `horizon-current-reader-native-evidence-20261118-v1` under the
same deployment root. The separate `horizon-current-reader-acceptance-20261118-v1`
accepts source/artifact correspondence and these reader capabilities only.
It does not establish canonical epoch integrity, authenticated R2 playback,
operational uploader acceptance or historical compatibility of the 34 pairs.
Those remain required next steps; no archive publication occurred in this check.

The RSS observer successor from published `663c476d` also completed qualification:
91 actual binary tests passed, with 12 unselected native-route tests ignored.
Direct strict Clippy passed for the production and test targets. Full-package
Clippy failed on 14 existing unrelated library warnings; that failure remains
preserved. Release compilation completed normally, actual package features are
empty, and the native 210/227 telemetry branches remain included. The sealed
artifact `3906038397ce2c6d6a60446988631b3a97f3256b246090009a8034dbdfcb91fe`
accepted the exact next observer config and rejected overlapping replay entries.
Its acceptance permits the next scheduled ordinary five-lane observation only.
Recovery of the missing RSS census remains unproven until that observation.

The scheduled 22:52:42 UTC observation subsequently completed both host RSS
censuses successfully, without discarded attempts in the final census. All
five owners remained stable and advanced. All five estimates were refreshed
and authenticated-readback verified. Full-range reconciliation again found
34 ready pairs, 66 missing, zero anomalies and no diagnostics. The current
memory estimate now validly selects nine desired lanes from five executing
lanes; this is a target, not admission. Existing lane hard obligations plus
host/control reservations remain 1,202,496,454,656 bytes against
1,212,136,964,096 total. Both reader builds and the native fixture have closed,
leaving 9,640,509,440 bytes of uncommitted hard budget, still insufficient for
a sixth 128 GB candidate without qualified reservation or policy changes.
Conservative available disk is 4,410,331,877,376 bytes. The next ordinary
observation is due no earlier than 23:22:42 UTC.

Historical-audit preparation must not assume that epoch 205 is retained in
`/home/ubuntu/horizon`: both its local archive and checksum were absent at the
privileged 22:44 check. Its prior full-verification receipt represents ordered
and internal-full checks. The 204–205 bridge binds archive identities and
successful adjacency verification, but contains no independent parent or
terminal blockhash expectations. Neither record alone supplies the new strict
uploader plan's external expectations. Obtain and bind independent source
evidence before exercising that publication path; never manufacture trusted
expectations from the archive being tested. A historical restore/readback must
use explicit scratch, retain remote identities, and leave existing R2 objects
unchanged.

At 22:57 UTC, independent HTTPS `getBlock` responses from
`https://api.mainnet-beta.solana.com` supplied epoch 205's boundaries. Slot
88,560,000 identifies parent 88,559,999 with blockhash
`2KxsnPENjXtiY2EYhtVnRQe4mESeVQ6nkMjQU1G94xoe`; a separate query of that
parent returned the same hash. Terminal slot 88,991,999 returned
`HuZtkhXnzaJ9BvDazHHSUgQWTFg3u2Uvf12AHBWqYuji`. These are external RPC
expectations, independent of the archive under test. The three raw responses
and retrieval context are sealed at
`/var/lib/jetstreamer/horizon-205-independent-boundaries-20261118-v1`.
The strict reader expectation is sealed separately with SHA-256
`3164efa2d021d46343eeac18464a2923bbaf8037bf998d2de3b5250ebc47799a`.

The prepared epoch-205 plan at
`/var/lib/jetstreamer/horizon-205-current-reader-plan-20261118-v1/plan.json`
has SHA-256 `4e29bcfa8ca775919b91c37e1fe53de656f0b2e7b3ccb3740b719105ce955e4e`.
It binds the qualified reader, independent expectations, two reader threads,
a 105 GB maximum archive, a 3 TB free-space floor and explicit private readback
scratch. Preparing this plan does not start an audit or authorize publication.
Root's branch fetch succeeded with the current loaded keychain socket and an
explicit SSH command selecting Ubuntu's host alias, key and known-hosts file.
The reader path set still matches the fetched branch through `eb81d477`.

Native tests of the actual uploader Cargo target started in
`horizon-current-uploader-native-tests-20261118-v1.service`, invocation
`bc067a97175e4cfdaf66af7ff60d5eba`, from the same immutable `ed61722d` source.
The 7 GB/one-job build reuses the closed release cache and preserves every live
worker. Its initial filter is `current_reader::`; genuine transport and restore
tests remain to be run from that resulting harness before selecting the new
uploader for the historical restore/readback operation.

That standalone uploader-target build subsequently failed before tests ran:
`bs58::decode::Error` lacks `StdError` when its `std` feature is absent. The
combined reader build had enabled that feature through dependency unification,
masking the uploader's implicit reliance on it. The boundary decoder now maps
the displayable decoding error explicitly, without requiring `bs58/std`.
The bounded production-module test package now selects only `bs58/alloc`,
matching this constraint, and tests malformed and wrong-length parent and
terminal hashes. All seven tests pass. The failed native build and journal
remain preserved; actual uploader-target compilation/tests must be repeated
from the published correction before operational use.

Published correction `823c2f19` subsequently passed all seven current-reader
tests in the actual standalone uploader target. That native build completed
normally in 2m18s with a 2.3 GiB peak, and the source manifest remained unchanged.
The same actual harness also passed ten tests selected by `restore` and the
instrumented transport test covering successful readback, digest rejection and
writer failure. Journals with genuine test output are preserved under
`horizon-current-uploader-native-tests-20261118-v2`; the selected transport and
restore services use suffix `v2` to capture output in the journal rather than
only forwarding it to the terminal. The production uploader release build from
that corrected source is the next qualification step, followed by immutable
sealing and the actual epoch-205 restore/readback audit.
