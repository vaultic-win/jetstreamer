# Epoch 211 native input preparation

## Accepted native execution on 2026-11-19

The gated native input test completed successfully under invocation
`9267f2c2c64949c29b9da7c27a46df94` of
`archive-211-v1616-native-input-actual-v1.service`. The original MainPID was
1264515. Its first genuine protective timer completion opened the startup gate;
the test then restored slot 91151575, matched canonical accounts hash
`xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx`, and reported zero replay entries
and bootstrap writes. The single native test passed in 522.25 seconds, followed
by clean PID1 completion.

The qualified capture helper accepted the immutable terminal proof at
`/var/lib/jetstreamer/horizon-native211-terminal-proof-1836-v1/proof.json`,
SHA-256 `97b3ae139f81af08fed1f0e94ccd9606b838d742fb679939969dd79e0ae357e5`.
Its running origin, actual guard evidence, raw child/PID1 journal, original
admission and source provenance remain bound through that proof. The terminal
fleet event preserves the original resource sample and historical claim.

This supersedes the pending native admission/execution statements in the
preparation history below. Full singleton replay still requires its own
capability, current-fleet admission, guard and lifecycle qualification. Do not
rerun the successful cold-input test or treat its result as full-epoch proof.

## Preparation history

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
sealed gated harness at
`/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test`
with SHA-256 `2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773`.
It retains the 300 GB physical root and 3,500,000 VMA
ceilings, requires an actual MainPID greater than one, and admits no bounded
experiment exceptions. The separate candidate guard includes the existing
`epoch223-native20-prefix-guard` feature as well. This does not replace any
running guard or prove an actual first guard fire; the native service and
complete current-fleet lifecycle remain required before execution.

## First guard before restore

The new test-only `native211_gate.rs` runs before `native_cold`, including before
snapshot hashing. The bounded rebuild passed six focused integrity/startup-gate
tests, left the cold native test ignored, and listed its exact selector on
2026-11-19. Source hashes remained unchanged across the build. Evidence is in
`/home/ubuntu/.codex/diagnostics/horizon-native211-gated-build-20261119-v1`.
Native qualification remains required. The previously sealed `b0b118...` harness
and `61a4...` guard do not include this gate. The candidate guard now binds the
new harness digest; rebuild and qualify that guard, observer and lifecycle
profiles before execution. Do not launch the older ungated native selector.

The selected service must supply `JETSTREAMER_EPOCH211_STARTUP_PLAN` and
`JETSTREAMER_EPOCH211_STARTUP_PLAN_SHA256`. The plan is a root-owned immutable
single-link `plan.json` in a new
`/var/lib/jetstreamer/horizon-native211-startup-plan-UNIQUE` package. Its schema
is `horizon-native211-startup-plan-v1`. It binds epoch/unit/root/bootstrap,
snapshot digest, `harness` and `guard` path/digest objects, `admission`, exact
guard unit `horizon-native211-protective-v1.service`, 300 GB root/128 GiB memory,
the protected `minimum_free_bytes`, current boot ID, and absolute
`issued_monotonic_us` / `expires_monotonic_us` from `CLOCK_MONOTONIC`. The window
must be positive and at most 60 seconds. The gate never extends that deadline.

After launching the harness, the root launcher must capture its actual
`INVOCATION_ID`, MainPID and mapped image. The harness verifies its own actual
PID, exact cgroup, boot and mapped image while waiting; useful snapshot work
cannot begin during this wait. Bind and seal the actual native guard plan, arm
its genuine systemd timer, and require the first completed no-trip guard sample
under the intended sandbox. The guard must observe this harness as the unique
native MainPID, rather than an `ExecStartPre` sleeper. A capability-only sample,
fixed delay or `admitted:true` alone cannot open the gate.

The launcher must atomically seal a fresh, no-clobber package at
`/var/lib/jetstreamer/horizon-native211-startup-tokens/INVOCATION_ID` containing
`guard-admission.json` and its canonical 64-hex-plus-newline
`guard-admission.sha256`. The token schema is
`horizon-native211-first-guard-token-v1`: bind `startup_plan_sha256`, unit,
invocation, MainPID, harness, guard, boot, admission, original monotonic clock,
guard invocation, and separately sealed `guard_plan`, `guard_sample`, and
`guard_pid1_journal` path/digest objects. Preserve the guard sample's original
plan path/digest. The PID1 journal is the captured JSON array of actual manager
events, with `_PID:1`, `_UID:0`, the guard unit/invocation and original monotonic
timestamps; never synthesize those events. The gate requires unique ordered
start and successful deactivation within its original deadline, the full
no-trip native guard fields, resource bounds, and freshness. It rejects changed
or writable files, wrong owners, links, substituted owners/images, missing
proof and timeout before restoring a Bank.

The root admission producer is still required. Its immutable
`horizon-native211-current-fleet-admission-v1` receipt must bind the exact
observer, complete fleet and source-publication evidence, boot, harness/guard,
128 GiB memory, 300 GB incremental disk and preserved guard floor. It must declare
`mode: "native-cold"` and keep entry replay, replay launch, runtime promotion,
full-epoch qualification, canonical sidecar, publication and remote/R2 mutation
authority false. PID1 guard events must belong to the current boot. The launcher
must independently verify source containment, exact artifact provenance, all
live/terminal obligations and drain-backed release, current peer identities,
actual caps/free space and a fresh expiry before launch and token sealing.
The gate authenticates that root-written receipt and the actual first-guard
evidence; it does not replace the launcher's complete capacity validator.
Implement and qualify that launcher and genuine startup transaction before any
native execution. No environment option bypasses the gate.

Publish all required source to `origin/account-updates` before admission. Native
success still does not admit full replay: the full singleton needs its own
capability, launch, guard and lifecycle bindings. Current-reader full/plugin
checks, authenticated upload/readback, full remote plugin playback, sidecar
commit and adjacent-boundary cleanup gates remain mandatory.
