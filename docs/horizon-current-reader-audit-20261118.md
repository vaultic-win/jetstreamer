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
