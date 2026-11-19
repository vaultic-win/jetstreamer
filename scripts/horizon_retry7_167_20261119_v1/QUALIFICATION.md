# Epoch167 retry7 recovery qualification

The guard candidate is built and tested. Preparer, launcher, native witness,
fleet admission and production launch are not yet qualified.

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

Next steps: normally seal the guard and its real build/test/source proof;
bind those exact hashes in the preparer; finish preparer/launcher fixtures and
qualification. Before admission, publish all required sources to account-updates,
use the actual epoch166 retry8 identity and accepted current fleet, preserve
all earlier retained promises plus the audit allocation, and requalify native
DATA witness/preflight. Reuse the existing epoch167 retry7 root; no witness
ancestor directory creation is permitted beside the live166 producer.
