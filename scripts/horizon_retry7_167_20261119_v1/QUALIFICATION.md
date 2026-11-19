# Epoch167 retry7 recovery qualification

The guard and preparer are built, tested and normally sealed. The launcher
production build and eight source tests pass. The refreshed native witness
passed actual preparation; full DATA capacity, two native launcher tests,
fleet admission and production launch remain pending.

Guard release image SHA256:
`e2821006426c497f25ecfdc8da26b63136d174a92c0ac15f78068bbc1078e581`.
Build target: `scripts/horizon_retry8_166_20261119_v1/guard/target/release/guard`.
The previously deployed epoch166 guard remains immutable and unchanged.

Native qualification units:

- `horizon-retry7-167-guard-build-20261119-v1.service`: production release,
  default features, successful.
- `horizon-retry7-167-guard-test-build-20261119-v1.service`: release test image,
  locked dependencies, successful.
- `horizon-retry7-167-guard-test-root-20261119-v1.service`: exact executable
  `guard-d2f95529e7f2911b`, **99 passed, zero failed/ignored**.

Builds were sequential, 2 CPU / 2 GiB memory / no swap / two Cargo jobs,
in the preexisting DATA target. Tests ran as root for inherited read-only private
custody fixtures. No producer or guard was launched or changed by qualification.
The new guard scope retains epoch167's 512 GiB whole-lane cap and the
6,829,053,656,882-byte raw floor. No reservation is released.

The guard deployment is
`/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-guard-20261119-v1`.
Its artifact proof SHA256 is
`6a334476cfefcd145163eaf3f4f3315969ba787bfc4a3d3652584a2155fcfa10`;
its normal deployment receipt SHA256 is
`0491b79a6c0982b876c51c62a56916cd2c52ff0dc9efd926f7a725a836e3b50a`.

Preparer qualification, November 19:

- `horizon-retry7-167-prepare-test-build-20261119-v2.service`: release
  test image with locked dependencies and `preparation` feature, successful.
- `horizon-retry7-167-prepare-test-root-20261119-v2.service`: exact executable
  `prepare-bd5a1c2bb7e5518f`, **298 passed, zero failed/ignored**.
- `horizon-retry7-167-prepare-build-20261119-v1.service`: production release,
  successful; image SHA256
  `44dcb706897b90da570f22637c20de661e591ba2cc14b82b41d1136f6b84128f`.

These builds/tests used the same sequential 2 CPU / 2 GiB / no-swap envelope
and existing DATA target. Their compile-time bindings use the exact guard,
proof and deployment receipt above, and guard source commit
`50f0a21c385ca38462b77bac770d6ed8cce594a2`.
The first preparer test run is retained (297 passed, one failure). The corrected
test fixture binds the current attempt instead of the historical booking's
attempt, and explicitly rejects a missing attempt. No production reservation
validation was weakened.

`horizon-deploy-prepare167retry7-20261119-v1.service` succeeded with actual
published source commit `ffc934b46ac9c42701c0583c1370fb484e280135`, contained
in the pushed merge `681c6125`. Both the source and runtime used the normal
deployment sealer:

- Runtime: `/usr/local/lib/jetstreamer/horizon-epoch167-retry7-live166retry8-prepare-20261119-v1`.
- Build proof SHA256: `d79b6622896c5427e21fad1291967db93918b74c95f9cd919ebd5ccd3dd0cf27`.
- Runtime seal SHA256: `f4cb684e6bffa6f2b9c2a9fc2e575cd2ae5321a1602b66998cb1d1f5ae46f75f`.
- Source seal SHA256: `2032dabfc0162b3cc141eff86f3a70f3e3541830ef21cdf6733f15d72d975e57`.

The launcher binds that exact preparer image/proof and source commit, plus the
qualified guard image. Native build/test units:

- `horizon-retry7-167-launch-test-build-20261119-v1.service`: successful.
- `horizon-retry7-167-launch-test-root-20261119-v1.service`: **8 passed,
  zero failed, 2 ignored**. The ignored tests require genuine fresh epoch167
  preparation; they have not passed and remain admission prerequisites.
- `horizon-retry7-167-launch-build-20261119-v1.service`: successful production
  release; SHA256 `201f331669734a9d80f6b247c37cd960aeff0bc39bf5d110584aeb5dfebfdfd8`.

Next steps: prepare the current measurement/witness/fleet inputs, complete the
native launcher tests and seal the launcher before actual guarded admission.
Before admission, publish all required sources to account-updates,
use the actual epoch166 retry8 identity and accepted current fleet, preserve
all earlier retained promises plus the audit allocation, and requalify native
DATA witness/preflight. Reuse the existing epoch167 retry7 root; no witness
ancestor directory creation is permitted beside the live166 producer.

Actual preparation attempts at 02:55–03:08 UTC November 19:

- `horizon-retry7-167-prepare-20261119-v1.service` failed with EMFILE under
  a 1024-descriptor soft limit. No producer launched.
- `...-v2.service`, IID `8e5e35a3fc1d45f5b1207e17282a959a`, used
  `LimitNOFILE=1048576` and passed that gate, then rejected the expired native
  witness. The native witness maximum age remains 120 seconds.
- `...-v3.service`, IID `8c0d1e74152b4819bb55dfb509beabc4`, used a newly
  captured own-image witness and normally sealed contract v2. It passed
  witness freshness and failed complete growth fit: available DATA
  7,413,741,199,360 bytes; required 7,447,501,842,226 bytes. The shortfall is
  33,760,642,866 bytes, before later producer growth. All reservations remain.

The v3 plan is `/var/lib/jetstreamer/root0308-prepare167retry7-20261119-v1/PREPARE_PLAN.json`,
SHA256 `0010d27ca6d879a1662383f302fcc402457422e4dbab5845e354bb5ea3af5f02`.
No new preparation receipt or epoch167 producer exists. Both failures were
immediately reassessed in conditional status-only R2 updates with authenticated
readback; latest receipt is
`/home/sol/.jetstreamer-private/r2-status-receipts/event-capacity-167-20261119-v1/RECEIPT.json`.
The reviewed 02:58 planning arrival is retained, less elapsed time: two hours
recovery/qualification, 72 hours replay and 30 hours delivery. These are planning
allowances, not measured completion bounds.

Next capacity action: qualify the closed 56,565,561,764-byte epoch169 local2
partial for holding or independently justified retirement. The new read-only
`scripts/horizon_epoch169_closed_prefix_20261119_v1` tool pins its exact inode,
checks the original owners and whole-run native references, hashes only a
consumer-free candidate, and preserves a private result. It explicitly grants
no deletion or resource credit; transitive reader references and any required
holding custody remain separate gates. Previously qualified snapshot152,
snapshot160, snapshot183 and six snapshot185/186 copies are already retired;
their historical allocation cannot be credited again.

At 03:16 UTC the normally sealed epoch169 local2 inspector completed. Both
native consumer censuses were empty; original owners remained inactive/dead;
the entire 56,565,561,764-byte file was stable and hashed to
`33f3b6d1622bb516ce90cc6a5b535038b2403b6056ddb15c49feaa0c70fb742f`.
Inspection receipt:
`/var/lib/jetstreamer/epoch169-local2-holding-review-20261119-v1/INSPECTION.json`,
SHA256 `1e64267d9d34edd6faeda2d303e977395a5288754bfe3e60b6d087f2ed8cefa6`.
Release build and strict selected-package Clippy succeeded; source commit
`1d07675f` was merged and pushed in `b63d29ef` before execution.

The next rotation transition actually started at 03:17:11 UTC:
`horizon-closed169-local2-park-20261119-v1.service`,
IID `3bc22adcd63a4b3fa2bcddad22260e4c`, initial PID 1778084.
It uses the existing qualified holding binary SHA256
`909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e`,
sealed plan `/usr/local/lib/jetstreamer/horizon-closed169-local2-holding-plan-20261119-v1/plan.json`,
SHA256 `7130ea293ba07365c01599f9eef7640eb1d702ad3def97f32fec89272973b8d8`.
The authorized prefix remains `node_02/`. Additional bounded transfer resources
are two CPUs, 2 GiB RAM, no swap, 256 tasks, IOWeight 10, and zero DATA staging.
Preserve those additive resources while this service runs. Plan 40 minutes for
upload, whole-object authenticated readback and local revalidation; a potential
restore separately needs the full 56,565,561,764 bytes and an estimated 20 minutes.
No custody completion, local retirement or disk credit is claimed yet.

After custody completes, qualify transitive reader closure and exact local
retirement without removing directories on witness ancestry. Preserve the newer
169 partial and the original169 witness members. Only actual retirement can
fund a new167 measurement, witness, staging and admission. The transfer's next
routine observation is no earlier than 03:47:11 UTC; completion events may be
consumed earlier. Do not repeat the park with a new identity or overwrite R2.

The chronological R2 audit's 03:17:28 check reported 53 of225 passed, zero
failed, epoch53 downloading. Its next routine check is no earlier than03:47:28.
Generation's sole observer remains03:28:09. That status cycle must use the
`event-capacity-167-20261119-v1/RECEIPT.json` override for167; its remote bytes
supersede the167 entry in the02:58 range receipt. Other18 status predecessors
remain the02:58 cycle. Preserve authenticated conditional ownership checks.
