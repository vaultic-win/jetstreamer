# Audit ROOT compiler-cache cleanup

This narrow successor to `horizon_holding141_build_cleanup_20261119_v1`
selects recognizable disposable compiler products in six existing ROOT cache
profiles. It does not retire archives, change R2, stop the audit, end DATA
promises, or admit replay workers.

Qualification passed all 38 tests, strict all-target Clippy and the production
build under the bounded serial DATA build envelope. Native consumer closure,
normal deployment sealing and positive check/execution remain required; no
compiler cache has been retired by this package yet.

| Fixed target | Device / inode | Owner / mode |
| --- | --- | --- |
| `/tmp/horizon-r2-chronological-audit-build-20261118-v1/debug` | 2304 / 6691407 | 1001:1001 / 0775 |
| `/tmp/horizon-r2-chronological-audit-build-20261118-v1/release` | 2304 / 6695563 | 1001:1001 / 0775 |
| `/tmp/snapshot183-retire-target/debug` | 2304 / 6709773 | 1001:1001 / 0775 |
| `/tmp/snapshot183-retire-target/release` | 2304 / 6709778 | 1001:1001 / 0775 |
| `/tmp/snapshot185186-retire-target/debug` | 2304 / 5383966 | 1001:1001 / 0775 |
| `/tmp/snapshot185186-retire-target/release` | 2304 / 6707389 | 1001:1001 / 0775 |

All seven top-level working executables and every alias of their inodes remain.
`evidence.rs` pins their original inodes and two-link custody and hashes them
before and after cleanup. No equivalence with a sealed image is inferred to
permit their removal. Every directory, depfile, fingerprint, generated source,
unknown file, lock, symlink inode, and group with an external hardlink remains.
Links between two selected roots count as external to each root and are retained.
Only recognized ELF, ar, Rust metadata, and raw LLVM products in Cargo output
positions qualify. The exact selection and reclaimed allocation come from the
native check; aggregate tree size is not a promised free-space gain.

The source retains descriptor-relative unlink, stable inode/link checks, full
selection rechecks, immutable consumer review, complete process/environment/
map/descriptor scans, staged systemd/cron checks, mount checks, no-builder gates,
and independent positive-check/execution proofs from the predecessor.
Nineteen existing locks are held: the shared local-mutation lock and all three
Cargo locks in each selected profile. Locks are neither created nor replaced.
The cleanup runs outside these selected trees. No compiler may reopen them
until the parent reconciles completion.

The source proof binds current committed reproduction sources, their dependency
manifests and lockfiles, and the exact deployed cleaner sources. Those current
sources are not asserted to be the original compiler inputs; original depfiles,
fingerprints and logs survive. The active audit must be proven independent of
these cached outputs by the native consumer review. Its sealed production image
and live work must remain untouched.

## Parent qualification

After the parent admits the build and the active retirement releases the shared
mutation lock, reuse the existing DATA target and TMPDIR. Do not build into any
selected ROOT cache:

```text
CARGO_INCREMENTAL=0
TMPDIR=/home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1/tmp
/home/sol/.cargo/bin/cargo test --locked --offline --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_audit_root_cache_cleanup_20261119_v1/Cargo.toml --target-dir /home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1 -j1
```

Run strict all-target Clippy and build with the same manifest, target, and jobs;
run rustfmt. Use the parent's qualified serial resource envelope, with no
implicit additional reservation. Publish the source to `account-updates` and
verify containment before deployment. Preserve the actual test/build outputs.

Seal the image to:

`/usr/local/lib/jetstreamer/horizon-audit-root-cache-cleanup-20261119-v1/cleanup`

Use the normal Rust deployment sealer with a separate plan/self digest.
Include immutable `artifact-proof.json` containing `source_commit`, exact
`production_sha256`, `tests_passed: 38`, `clippy_all_targets_passed: true`, and
`sources` mapping every tracked package file to its SHA256. These claims require
actual successful qualification. The cleaner verifies the ordinary seal and
source map at runtime.

Precreate root-owned mode-0700 output directories:

```text
/var/lib/jetstreamer/audit-root-cache-check-20261119-v1
/var/lib/jetstreamer/audit-root-cache-retire-20261119-v1
```

Seal separate immutable check and execution plans:

```json
{
  "schema": "horizon-audit-root-cache-partial-cleanup-plan-v1",
  "source_commit": "ACTUAL_COMMITTED_AND_PUSHED_REVISION",
  "cargo_lock_sha256": "ACTUAL_WORKSPACE_LOCK_SHA256",
  "indirect_review": {"path": "/SEALED/REVIEW.json", "sha256": "ACTUAL_SHA256"},
  "output": "/var/lib/jetstreamer/audit-root-cache-check-20261119-v1/check.json",
  "prior_check": null
}
```

The execution plan changes the output to the fixed retire directory and binds
its successful predecessor check by path and digest. Invoke the sealed image
with `PLAN --plan-sha256 SHA --self-sha256 SHA`. Negative consumer checks produce
negative evidence and refuse removal. Execution records an intent, repeats all
gates, removes selected groups, and writes a completion. An intent without
completion requires review; do not blindly retry fixed occupied outputs.

## Native consumer review still required

The root-owned immutable review has schema
`horizon-audit-root-cache-consumer-closure-v1`, owner `/root`, the exact ordered
six targets above, `no_current_or_staged_consumer: true`,
`no_reopen_until_completion_reconciled: true`, `terminal_owners_inspected: true`,
and explicit `retired_units` and `indirect_dependencies` arrays.

Its `classes` array contains all seven entries:

```text
producer-controller
libraries-and-relative-inputs
sealed-launch-plans
timer-path-cron
future-builds
recovery
live-accounting-and-witness-roots
```

Every row requires `no_local_outputs_required: true`, a concrete evidence-based
`reason`, and a nonempty `inspected_inputs` array of exact `{path, sha256}`
bindings to immutable root-owned evidence outside the caches. Review current
owners and old failed transient units; PID1 may retain commands after fragments
vanish. Each named retired unit must actually be unloaded, inactive, unqueued,
and command-free. Evidence inspection alone does not make a file cache-dependent:
`indirect_dependencies` separately lists actual dependent inputs, and may be
empty only when that has been established.

Review all live and staged consumers, including the audit, its playback/current
reader pipeline, snapshot cleanup receipts, accounting/Frame/witness readers,
prepared builds and deploy wrappers. Preserve required files at their original
paths. A historical mention alone is not a live dependency, but a live reader
of that historical metadata may be one. Do not suppress real process or staged
references to make the gate pass.

After successful retirement, measure actual ROOT availability and let the
existing audit retry naturally. Do not restart an in-flight download/playback.
Report actual regained space separately from selected inode allocation. The
completion grants zero resource credit and no new replay or remote authority.
