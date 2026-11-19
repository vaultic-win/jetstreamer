# Focused169 compiler output cleanup

The isolated build defines **31 tests** (18 policy/filesystem, 11 process-reference
and 2 staged-alias tests), strict Clippy on all targets, and rustfmt. The special
inode test uses a FIFO so the long isolated TMPDIR does not exceed the Unix socket
pathname limit. Native consumer review, check, deployment and retirement remain
separate gates; passing these tests grants no deletion or capacity credit.

The process reader accepts ENOENT or ESRCH only after a separate metadata read
positively establishes that the PID directory is absent. This also handles task
exit after a proc file was opened. A present or reused PID, permission error,
alias, or other metadata/read failure remains fatal.
The native check additionally exposed `/proc/2/environ` returning ESRCH for
`kthreadd`. Only a positively identified kernel thread with the same before/after
identity may treat that error as an absent userspace environment. Its links,
maps and descriptors are still scanned. Other errors and userspace tasks fail.
For terminal userspace tasks, a complete task-directory census must prove that
only the same terminal task remains; a zombie leader with other threads is not
exempt. The successor also verifies the task identity after this census.

The fixed profile selects these three existing DATA directories, by device,
inode, owner and mode:

| Directory | Device / inode | Observed allocation supplied by parent |
| --- | --- | --- |
| `/home/sol/.jetstreamer-private/epoch169-focused-route-20261117-v1/worker-test-target-v1/modern-target/debug` | 64512 / 112333487 | 35,823,198,208 bytes |
| `/home/sol/.jetstreamer-private/epoch169-focused-route-20261117-v1/worker-test-target-v1/debug` | 64512 / 111756192 | 1,926,774,784 bytes |
| `/home/sol/workspace/jetstreamer/target/release/build` | 64512 / 342236427 | 2,727,079,936 bytes |

These 40,477,052,928 bytes are total tree allocation, **not selected or promised
reclamation**. The native check computes actual selected allocation. Unknown
files, generated sources, fingerprints, dependency manifests, logs, symlink inodes, every
directory, every lock and externally linked inode group remain. If this narrow
selection is insufficient, report the measured shortfall rather than extending
the profile at runtime. No cargo-home contents are selected.

Only recognized ELF, ar, Rust metadata and raw LLVM compiler products at Cargo
output positions qualify. A group is selected only if every path is recognized
and its observed in-tree links exactly equal `st_nlink`. Allocation is counted
once per inode per tree. Cross-target links are external to each target and stay.
After a complete unchanged census, the retirer retains an opened group inode,
opens each parent component without following symlinks and compares every inode
and link count before each descriptor-relative unlink. Only a witnessed one-link
decrement permits the updated ctime; other metadata must remain stable. Each
parent is fsynced. The postcheck requires all selected paths absent, unchanged
preserved files, and the same directory paths/device/inode/owner/mode/link count.
Only directory timestamps, length and block allocation may change.

Six existing locks are held exclusively without creating or replacing them: the
shared mutation lock, both debug `.cargo-lock` files, modern debug
`.cargo-build-lock` and `.cargo-artifact-lock`, and release `.cargo-lock`.
All Cargo/rustc/sccache builders must be absent. Complete process, environment,
relative-input, descriptor, map and staged systemd/cron scans run under those
locks. A root-owned immutable consumer-closure review and exact inspected inputs
are mandatory; the scanner alone does not prove indirect closure. No positive
consumer is suppressed, including the old failed focused169 guard.

The fixture has retained base commit
`01a0ef21d311c5094f7395b4d38ec434bed9cc0f` and exact binary Git diff SHA
`cea888c75ff1c2c14e77a02289056f23e0574f421c2c47a4d01dac24935c0c39`.
Both match the preserved immutable source package
`/usr/local/lib/jetstreamer/horizon-epoch169-focused-source-20261118-v2`.
The root Cargo.lock and historical v1_4_25 **and v1_5_8** lock digests are pinned;
v1_5_8 is the actual historical test worker's runtime. Cleanup preserves all
source, patch/basis, test acceptance and terminal evidence. Workspace release
reproduction binds the current committed Cargo.lock and account-updates commit.
The retained fixture predates a Git rebase. Its exact tree and patch remain the
reproduction source; the cleaner separately binds published lineage commit
`9498953f33500675a7203c0f73cd6836a9f63f49` and the complete rebase delta. It does
not claim those trees are identical or authorize admission of the old fixture.

## Parent qualification and deployment

Reuse the existing, isolated DATA target; do not create new private-root siblings:

```text
CARGO_INCREMENTAL=0
TMPDIR=/home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1/tmp
/home/sol/.cargo/bin/cargo test --locked --offline --manifest-path /home/sol/workspace/jetstreamer/scripts/horizon_focused169_compiler_cleanup_20261119_v1/Cargo.toml --target-dir /home/sol/.jetstreamer-private/holding141-incremental-qualification-target-20261119-v1 -j1
```

Then run `cargo clippy` with the same arguments plus `--all-targets -- -D warnings`,
then `cargo build` with the same manifest/target/jobs. Suggested envelope is the
previous serial qualification's 1 CPU, 1 GiB memory, no swap, TasksMax128 and
15-minute execution timeout, subject to the parent's current funded build gate.
No tests or binaries may run from a selected cache. Do not start a new builder
between the positive check and retirement.

Commit/push the package and verify remote containment before operational use.
Normally seal the new executable to:

`/usr/local/lib/jetstreamer/horizon-focused169-compiler-cleanup-20261119-v7/cleanup`

The same package must contain root-owned immutable `artifact-proof.json` with
`source_commit`, `production_sha256`, `tests_passed: 31`,
`clippy_all_targets_passed: true`, and `sources` mapping **every tracked file in
this package** to its SHA256. Preserve the actual test/build/native evidence in
that proof. The runtime validates the ordinary deployment seal's cleanup and
artifact-proof member hashes/modes, the production digest and the exact committed
source map. Bind the normal sealer's own digest and its separate plan as usual.

Prepare root-owned 0700 directories:

```text
/var/lib/jetstreamer/focused169-compiler-check-20261119-v1
/var/lib/jetstreamer/focused169-compiler-retire-20261119-v1
```

Seal separate plan files. A plan has only these fields:

```json
{
  "schema": "horizon-focused169-compiler-partial-cleanup-plan-v1",
  "source_commit": "ACTUAL_40_HEX_COMMITTED_AND_PUSHED_REVISION",
  "cargo_lock_sha256": "ACTUAL_WORKSPACE_CARGO_LOCK_SHA256",
  "indirect_review": {"path": "/SEALED/ACTUAL_REVIEW.json", "sha256": "ACTUAL_SHA256"},
  "output": "/var/lib/jetstreamer/focused169-compiler-check-20261119-v1/check.json",
  "prior_check": null
}
```

The execute plan changes output to the exact retire directory above and binds
the preceding positive check by exact path and SHA256. Invoke the fixed image
with `PLAN --plan-sha256 SHA --self-sha256 SHA`. A check does no removal. Execution
writes a second check, durable no-clobber intent, repeats all gates, then unlinks
selected groups. An intent without completion requires explicit evidence review;
the fixed outputs prevent blindly retrying a partially completed transaction.

The review schema is `horizon-focused169-compiler-consumer-closure-v1`, owner
`/root`, exact ordered `targets` from the table, and positive
`no_current_or_staged_consumer` and `no_reopen_until_completion_reconciled`.
Its `classes` array must contain exactly:

```text
producer-controller
libraries-and-relative-inputs
sealed-launch-plans
timer-path-cron
future-builds
recovery
```

Each row needs `class`, `no_local_outputs_required: true`, a specific evidence-
based `reason`, and a nonempty `inspected_inputs` list of exact `{path,sha256}`
bindings to root-owned immutable evidence outside selected caches. A separate,
mandatory `indirect_dependencies` array binds actual cache-dependent input files;
use an explicit empty array only when the reviewed evidence proves none exist.
These dependencies are checked for live/staged consumers. Reading an independent
plan as evidence does not itself make that plan cache-dependent. Exact cache
command, environment, map, descriptor and staged references remain fatal.
Historical documents can describe old references without authorizing a live
reader. Do not fill the review with generic assertions or synthetic evidence.

Before check, preserve original producer and guard terminal evidence and close
the known failed guard through the parent's qualified path. The runtime requires
all three exact tests1 producer/service/timer names to be not-found, inactive,
dead, PID0, unqueued and without commands or triggers. It does not reset them.
Verify the sandbox can read process state and root-private evidence; keep mounts
at suitable ancestors, since a mount directly on a selected tree fails the mount
gate. Do not hide target references or widen permissions to bypass a rejection.

After successful retirement, remeasure actual DATA free space and feed it into
fresh admission/guard accounting. Completion reports zero resource credit and
does not lower any reserve or authorize replay launch or R2 mutation.
