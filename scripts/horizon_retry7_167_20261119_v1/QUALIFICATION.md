# Epoch167 retry7 recovery qualification

The guard is built, tested and normally sealed. The preparer has passed its
full test suite and production build; its source/runtime sealing remains pending.
Launcher, native witness, fleet admission and production launch are not yet
qualified.

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

Two launcher native tests require genuine fresh epoch167 preparation and remain
explicitly pending; they have not passed. Next steps: seal the preparer source,
runtime and actual qualification proof, bind those hashes in the launcher, and
finish launcher qualification. Before admission, publish all required sources to account-updates,
use the actual epoch166 retry8 identity and accepted current fleet, preserve
all earlier retained promises plus the audit allocation, and requalify native
DATA witness/preflight. Reuse the existing epoch167 retry7 root; no witness
ancestor directory creation is permitted beside the live166 producer.
