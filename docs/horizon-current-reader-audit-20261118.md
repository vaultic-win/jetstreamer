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
