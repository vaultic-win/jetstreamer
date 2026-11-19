# Epoch 211 native input preparation

The test-only `worker/src/native211_input.rs` profile uses the shared v1.6.16
cold-input checks to restore and freeze epoch 211's exact bootstrap. It requires
the canonical accounts commitment, zero replay entries/bootstrap writes and
unchanged cursor, transaction count, capitalization, last blockhash and tick
height. Its ignored native test remains unqualified until an admitted execution
produces independent terminal evidence; another epoch's proof cannot qualify it.

The retained package is
`/var/lib/jetstreamer/horizon-focused-211-complete-span-store8-ca2e38b-v1`.
Its immutable snapshot body still exists even though the older private download
directory contains only a restore receipt. No new download is required on that
basis. The following digests are retained package/content-verification bindings;
preparation does not claim a new full body rehash.

| Input | Binding |
| --- | --- |
| Snapshot | `snapshot-91151575-xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx.tar.zst` |
| Snapshot bytes / SHA-256 | 8731506223 / `958a8e5aad2423350f04470dffbd90fd8d7e458f7f8e774e15dd86d43291b5fb` |
| Generation / CRC32C / MD5 | 1628983801891966 / `4Sr/GA==` / `mMBeym4d6L8xRT8awzc+Kg==` |
| Genesis bytes / SHA-256 | 20144 / `133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945` |
| Snapshot bindings SHA-256 | `f48751ee91ab153ab185b5e14967d1adfc4681b2a3c46402bce9339e1e60d681` |

The already prepared singleton manifest is
`/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight211-singleton.json`,
SHA-256 `eaf7f9fa4df1ae57303b655dd727c8bc5d7786d2f1fafeebb5832843133e7086`.
Its singleton fingerprint is
`sha256:d00f6c8ff2d66ec302aea39267ace8c28931d2602c9f5185c913eb5c96ab667b`;
the older complete-span source fingerprint is a different binding. The singleton
requires root 91583512 with accounts hash
`548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV`, all 487 post-root slots, and
432000 output slots from 91152000 through 91583999.

Before native execution, build and seal the optimized rustc 1.51.0 harness,
execute the small integrity regressions for both 210 and 211, and prove the exact
ignored selector listing. Reuse the locked/offline worker test build procedure
in [the singleton guide](epochs209-212-singleton-qualification.md), inside a
freshly authorized bounded build envelope. Bind the resulting artifact digest;
the existing epoch 210 test artifact does not contain this new selector.

On 2026-11-19 the independent harness built successfully with rustc 1.51.0,
locked/offline release dependencies, one Cargo job, incremental compilation
disabled, LTO disabled and 16 codegen units. The 2,000,000,000-byte memory cap,
zero swap and four-CPU build envelope remained in force. Both the 210 and 211
file-integrity regressions passed, and the exact ignored 211 native selector
was listed without executing a snapshot restore. The artifact SHA-256 is
`b0b1185584680eae2b644c38a0c7d3f4240e0f4af392caa8e419300f2ac17df5`.
This build configuration is distinct from the old 210 artifact; it does not
inherit that artifact's runtime qualification. The build recipe, verbose compiler
commands, source digests, resolver output and PID1 journal are retained under
`/home/ubuntu/.codex/diagnostics/horizon-native211-build-20261119-v1`.

Native admission, a persistent service, running and terminal capture,
fleet/status lifecycle and observer registration remain to be
implemented and qualified for 211. The 210 lifecycle supplies integrity and
terminal-capture patterns, but its admission depends on historical 209/227 peer
identities and is not a current-fleet admission route. A new admission must
preserve every actual live/terminal obligation, existing guard floor and actual
hard-memory cap, with fresh complete-fleet evidence and race checks. A future
producer completion releases no reservation until independently proved.

The `epoch211-native-main-guard` feature now provides the closed guard tuple
for `archive-211-v1616-native-input-actual-v1.service`, run root
`/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1`, and the exact
sealed harness at
`/var/lib/jetstreamer/horizon-211-native-input-9b29f0ac-20261119-v1/native-input-test`
with the digest above. It retains the 300 GB physical root and 3,500,000 VMA
ceilings, requires an actual MainPID greater than one, and admits no bounded
experiment exceptions. The separate candidate guard includes the existing
`epoch223-native20-prefix-guard` feature as well. This does not replace any
running guard or prove an actual first guard fire; the native service and
complete current-fleet lifecycle remain required before execution.

Publish all required source to `origin/account-updates` before admission. Native
success still does not admit full replay: the full singleton needs its own
capability, launch, guard and lifecycle bindings. Current-reader full/plugin
checks, authenticated upload/readback, full remote plugin playback, sidecar
commit and adjacent-boundary cleanup gates remain mandatory.
