# Retry8 epoch166 candidate qualification

Built on 2026-11-19 under parent-authorized CPUQuota=200%, MemoryMax=2GiB,
MemorySwapMax=0, jobs2, sequential transient units. All Cargo output is on DATA
under `guard/target` (130MiB after qualification). No admission, producer launch,
replay-directory mutation, remote mutation or Git operation was performed.

Production artifacts in `guard/target/release`:

| Artifact | SHA256 | Intended immutable destination |
| --- | --- | --- |
| guard | 8a13e521a01cb0b58b582ab574d47336a45e20cc75d5dc0f95a43d5ab44588f7 | /usr/local/lib/jetstreamer/horizon-epoch166-retry8-original-slot-guard-20261119-v1/guard |
| prepare | 633f5a2f6944e5fda39f39d85682738211c95da17f1d78cf03c95c1cbd456c7d | /usr/local/lib/jetstreamer/horizon-retry8-166-prepare-20261119-v1/prepare |
| horizon-retry8-single166-launch-v3 | c0bacc1ca7b685fd6cc5bd72eb5ce1d9295330c8c73fe56951843594d7c6dfdb | /usr/local/lib/jetstreamer/horizon-retry8-single166-launch-20261119-v1/launch |

Guard release build: horizon-retry8-166-guard-build-20261119-v3.
Guard tests: horizon-retry8-166-guard-test-root-20261119-v1, 98 passed.
Preparer tests: horizon-retry8-166-prepare-test-root-20261119-v1, 216 passed.
Preparer production: horizon-retry8-166-prepare-release-20261119-v1.
Launcher tests: horizon-retry8-166-launch-test-20261119-v2, 7 passed.
Launcher production: horizon-retry8-166-launch-release-20261119-v1.
Root tests are necessary for inherited native read-only custody checks and private
fixtures. Initial unprivileged guard attempt passed94 and failed4; root execution
passed all98 without suppressing or weakening tests.

Guard dependencies corrected by making tempfile a production dependency. Historical
optional guard feature names are declared but disabled in the default artifact;
no extra epoch-native route was enabled. Preparer feature: preparation. Launcher
compiled with HORIZON_RETRY8_GUARD_SHA256 equal to the genuine guard digest above.
The three standalone Cargo.lock files must be retained with source. Original
external guard closure provenance is in guard/SOURCE_CLOSURE.json. The two emitter
fixtures are unchanged copies from retry7's emitter directory.

Next steps owned by parent:

1. Commit/push all required source and verify remote account-updates containment
   plus exact deployed-source equivalence before admission.
2. Seal the three production artifacts above with the qualified Rust deployment
   sealer and separately bound plans/self hash; verify resulting bytes and retain
   build/test/feature evidence. Sealing does not grant admission authority.
3. Produce root-owned precreated-root receipt schema
   horizon-three-next-roots-before-witness-v1: owner /root, primary_thread
   01a1af2a-9ce8-76a2-8939-b2112bd38f53, remote_mutations false,
   recorded_unix_seconds, roots (exact path/device/inode for166retry8,167retry7,
   170retry6). All future ancestor-changing scaffolding must precede witness
   qualification. Preserve existing stopped data and caps.
4. Qualify fresh native DATA witness using exact new guard; build its artifact
   proof schema horizon-epoch166-retry8-original-slot-guard-artifact-proof-v1.
   Add retry8_precreated_roots bound to the preparer plan; bind actual stopped166
   retry7 and167retry6 evidence and all closed units. DATA complete6794761027378,
   minimum floor6829053656882; audit remains additive24GiB4CPU, DATA0.
5. Capture fresh fleet/resource evidence, run preparer and launch --check-only
   under final identity/mounts. Launch plan schema horizon-retry8-single166-launch-plan-v1
   includes prior_stop_completion path/hash of actual166retry7 terminal event.
   Resolve all resulting gates before actual launch. No new root capacity credit,
   checkpoint resumability or admission has been established by these unit tests.
