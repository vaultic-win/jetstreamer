# Ubuntu debug dependency cache retirement

## Fixed build-script output profiles

Two additional profiles select only `target/debug/build` and
`target/release/build` under `/home/ubuntu/workspace/jetstreamer`:
`jetstreamer-horizon-ubuntu-debug-build-cache-plan-v1` and
`jetstreamer-horizon-ubuntu-release-build-cache-plan-v1`. They use the existing
identity-ledger, interrupted-subset and no-clobber receipt machinery, retain the
parent profile's Cargo lock and every original directory, and require no builders
or live/staged references across the **entire** corresponding profile. Preserved
source and Cargo.lock must match a clean, published revision. Existing whole-profile
checks remain read-only and cannot be used as retirement ledgers for these profiles.

The protected checkpoint-name rule remains in force. Four observed RocksDB
`checkpoint_impl.o` files are compiler objects; their exception requires their exact
profile, relative path and complete SHA-256. Debug build generations
`librocksdb-sys-37eeae80f930ac01` and `librocksdb-sys-718199d3bc47b9d1` have digest
`f53c0f2b84b90ab5423f2923bf2da073bdb15661b24457e7c34cd4a4263a42e8`;
release generations `librocksdb-sys-a545a441747427e1` and
`librocksdb-sys-a53c016568a6018c` have digest
`e6bf6a5539b644378595cd72bb03c103d485419bb753c44f8441448f58ac4d65`.
All four are independently identified x86-64 ELF relocatable objects at
`out/bfe5d317b023d6cf-checkpoint_impl.o`. A matching name with different bytes,
another generation/profile, a link, or an archive/snapshot/lock remains rejected.
The complete cache regression suite passed 32 tests, including wrong-content
rejection and existing interrupted-retirement, link-target and lock preservation.

The November 19 10:26 cleanup cycle found 37 stale linked build/test units from
superseded epoch-205/234/238/240–244 work. All were inactive, non-restarting and
without trigger, job or reverse dependency. Their `/etc/systemd/system` links were
disabled; original sealed unit files and hashes were preserved. Fresh read-only
checks of both complete workspace profiles then found no live/staged references.
Evidence is under
`/home/ubuntu/.codex/diagnostics/horizon-fleet-cycle1026-20261119-v1`.
Those checks do not themselves authorize deleting build outputs: run a fresh
positive check and separate retirement using the exact new profile and helper.

Both build-output retirements completed on November 19 at about 10:42 UTC,
using published source `1a85487e` and sealed checker SHA-256
`9fb10f85d82eb55faa6418f131139ba5c27186a66fe9d75734e8022c27b096ed`.
Fresh positive checks found no builders or live/staged profile references;
separate sealed retirement plans repeated those checks before deletion.
All original directories and parent Cargo lock inodes were preserved.

| Cache | Original allocation | Remaining directories | Completion SHA-256 |
| --- | ---: | ---: | --- |
| `target/debug/build` | 5,932,605,440 bytes | 2,195,456 bytes | `f0e5ab6514d049d5754c841fa1546da7181d13a561f08d7a098ea5b450a5e91c` |
| `target/release/build` | 7,601,123,328 bytes | 3,223,552 bytes | `3a0cc26b320b570c0850f8ba3a2697ebf76be15eb773961132865dd1b813f897` |

The two selected trees lost 13,528,309,760 bytes of unique-inode allocation.
Filesystem availability was 3,865,541,894,144 bytes at the first retirement
intent and 3,872,295,026,688 bytes at the second completion: a net increase of
6,753,132,544 bytes across that interval. Concurrent replay allocation/release
and external hardlinks mean this is not a cache-only physical savings measure.
The retained completion records are under
`/var/lib/jetstreamer/horizon-dev-cache-check-{debug,release}-build-retirement-20261119-v1`.
Plans, build/test journals and the aggregate summary are in
`/home/ubuntu/.codex/diagnostics/horizon-build-cache-retirement-20261119-v1`.
No replay data, archive, sealed runtime or R2 object was removed.

## November 19 release dependency retirement

The release dependency cache was retired through the current strict compiler
classifier, with source equivalent to published `b42f0488`. The original sealed
`6f4a1600` checker rejected the checkpoint-named executable
`jetstreamer_checkpoint_restore_probe-1fa5f8bd66f575cc` before deletion. Published
changes `8f5f4d5f` and `aa438812` already supplied exact dep-info/ELF proof for
that compiler output; no filename-only exception was added for this operation.

The current full observer library, checker binary and tests were built against
the retained dependency cache outside the selected tree. All 31 focused cache
tests passed, including the complete manifest classifier, interrupted subsets,
symlink targets and parent-lock preservation. The build invocation was
`13af38fd5820433aa500e40ba31f321e`, 7.656 seconds with a reported 446 MiB peak
under a 2 GB cap. The source manifest and dependency digests were rechecked.
The Rust-sealed checker is
`/var/lib/jetstreamer/horizon-cache-checker-b42f0488-20261119-v1/jetstreamer-horizon-dev-cache-check`,
SHA-256 `3e1e2b03b4493d2f5d45208ef9839aa933c2e885d79422fc41210a1fcd082a40`.

The positive native check, invocation `61393fddfbd8441791e8be5051dbead3`,
inspected 1,267 processes, found no active builders or process/staged references,
and bound 3,933 entries totaling 10,231,230,464 unique-inode physical bytes.
Its immutable ledger is
`/var/lib/jetstreamer/horizon-dev-cache-check-release-20261119-v3/check.json`,
SHA-256 `96c232eee8400b1a245e347744203beb377b89cb9198825757a3dccf5f93de3b`.

An initial retirement plan used a receipt-directory name outside the required
`horizon-dev-cache-check-` prefix. It failed before writing an intent or deleting
anything; its plan and journal are retained. The corrected, separately sealed
plan is
`/var/lib/jetstreamer/horizon-release-cache-retire-plan-20261119-v2/plan.json`,
SHA-256 `3e4925aebde297144a8369de78eeee81fd72d1af6ed21779ad85bb92dc9ea751`.
Actual retirement invocation `e7a447511ece4e69b89d64a737799fb5` completed in
30.548 seconds with a reported 35.8 MiB peak under a 256 MB cap.

The completion receipt is
`/var/lib/jetstreamer/horizon-dev-cache-check-release-retirement-20261119-v1/completion.json`,
SHA-256 `4b34dc132b88304f23e89e10a34921eeab5d8b991004fe94e3f21f600e70be71`.
Only the original empty directories remain, occupying 753,664 bytes. The
parent Cargo lock inode `13798479` was preserved. Available filesystem bytes
rose from 3,989,218,996,224 at durable intent to 3,996,304,044,032 at completion,
a 7,085,047,808-byte net increase while live replay continued allocating.
That event delta is distinct from the cache's 10.23 GB physical footprint;
external hardlinks and concurrent growth can affect reclaimed space.

The active epoch-205 reader dependency cache, all replay scratch, archive
inputs and sealed deployments remain outside this retirement. No replay or R2
mutation was authorized by it. Native build/check/retirement journals and plans
are retained in
`/home/ubuntu/.codex/diagnostics/horizon-cache-checker-current-20261119-v1`.

The Rust `jetstreamer-horizon-dev-cache-check` profile
`jetstreamer-horizon-ubuntu-debug-deps-cache-check-plan-v1` selects only
`/home/ubuntu/workspace/jetstreamer/target/debug/deps`. It cannot select another
directory, remove the parent profile or unlink `target/debug/.cargo-lock`.
The ordinary Ubuntu debug/release check profiles remain read-only.

Bind the preserved clean source HEAD and Cargo.lock SHA-256 in a native-sealed
immutable plan, together with a root-private no-clobber `check.json` output.
First run without retirement. Require a complete bounded cache census with no
archives, snapshots or sidecars, no active Cargo/rustc/sccache processes, no live
process command/map/link/descriptor references, and no staged unit references.
The staged census conservatively includes debug executables outside deps that
could load one of its dependencies later. Permission errors fail closed.

Only a separately sealed plan with `retirement.prior_check` naming and hashing
that positive check may remove the same cache. It rechecks the entire census,
source and lock, retains an exclusive nonblocking Cargo profile lock outside the
deletion subtree, fsyncs an intent, repeats the builder/process check and then
removes only the fixed dependency tree without following child symlinks. A
durable completion receipt records absence. Preserve both checks and the intent;
do not bypass a changed tree, running builder or staged dependency reference.

This is disposable compiler output, reproducible from preserved source and
Cargo.lock. It is not replay scratch, a source checkout, a private checkpoint,
an archive, immutable deployment or R2 object. Measure actual recovered free
space in the next coordinated observation rather than equating tree physical
bytes with the filesystem delta while other work runs. Cache retirement is not
replay admission: the full resource, compatibility, guard and publication gates
remain independent, and every active sealed producer must remain untouched.

## Distinct release dependency and debug incremental profiles

Two separately reviewed v2 profiles add exactly these Ubuntu compiler caches:

| Profile | Fixed target | Existing lock retained outside target |
| --- | --- | --- |
| `jetstreamer-horizon-ubuntu-debug-incremental-cache-plan-v2` | `/home/ubuntu/workspace/jetstreamer/target/debug/incremental` | `target/debug/.cargo-lock` |
| `jetstreamer-horizon-ubuntu-release-deps-cache-plan-v2` | `/home/ubuntu/workspace/jetstreamer/target/release/deps` | `target/release/.cargo-lock` |

The original read-only whole-release profile and previous debug/deps profile
keep their contracts. Neither new profile can select top-level executables,
build directories, another target, source, lockfiles, snapshots, Horizon
archives, sealed deployments, or private replay/checkpoint state. A cache member
named as an archive, sidecar, snapshot, checkpoint or lockfile refuses checking.
UID 1000 ownership and one filesystem are required throughout. Child symlinks
are inventoried and later unlinked without following their targets.

Use the same sealed plan shape: `schema`, clean `source_commit`, preserved
`cargo_lock_sha256`, root-private no-clobber `output` ending in `check.json`, and
no `retirement` for the first positive check. Root must seal both checker and
plan with the Rust deployment sealer and run the checker outside the selected
caches. Keep all builders and build-launch automation quiet. Both profiles
refuse every Cargo/rustc/sccache process, including builders for other profiles,
and retain the existing parent Cargo lock exclusively and nonblockingly through
all checks, unlinking and completion. They never create or unlink that lock.

Release/deps checks the entire same-workspace release profile for live process
and staged command references, since a top-level executable might load a deps
library later. Debug incremental is compiler-only state: its reference scope is
the exact incremental tree, with absolute and boundary-aware relative path
matching. Compiled debug programs outside it do not load incremental compiler
state. Both repeat complete process/staged-unit and builder checks immediately
before unlinking, without restarting or stopping anything.

The positive v2 check writes an immutable root-owned identity ledger (maximum
256 MiB, one million members, depth 128), binding source, lock, checker, profile,
target and Cargo lock inode. It records every directory/file/link identity and
symlink target; hardlink-aware unique-inode physical bytes are distinct from
allocation summed across pathnames. A later separately sealed plan may specify
`retirement: {prior_check: {path, sha256}}`. It must bind that positive ledger to
the same source, lock, checker and exact profile. Initial retirement requires
the current tree to match the full check, then fsyncs a new check and an intent.

Unlinks use identity-checked opened parent directories and remove only ledger
files or symlinks. Every original directory remains, including the selected
cache root. A completion proves that only those empty directories remain and
that the parent Cargo lock inode was preserved. It grants no replay admission,
archive deletion or remote mutation. Positive checks and retirement checks are
different immutable records; an interrupted run cannot refresh its authority.

Interrupted recovery requires the same sealed retirement plan, checker, source,
parent lock inode, original positive ledger and intent. All original directories
must retain their identities; remaining files/links must be an exact unchanged
subset. New compiler output, modified or replaced files, new hardlinks or changed
directories refuse recovery. Reduced hardlink counts from prior authorized
unlinks are allowed. A completed retry repeats the safety gates and verifies the
original intent binding before returning without additional deletions.

The October 24 audit measured about 40.41 GB in release/deps and 75.72 GB in debug
incremental; the entire release profile was only 44.73 GB, so it cannot yield 200 GB.
These are historical candidate footprints, not current reclaimability proofs or
promised free-space gains. Existing hardlinks outside the target retain their
data, and live lanes keep allocating. Root must review a successful fresh check
and exact plan before execution and measure actual free space independently.
Prefer retiring unused debug incremental first so ongoing release helper builds
retain their dependency cache; rebuilding a deleted cache consumes space again.

The exact observed first-level Cargo incremental crate directories
`jetstreamer_checkpoint_restore_probe-<13lowercasealphanumericID>` and
`jetstreamer_epoch140_checkpoint_journal-<13lowercasealphanumericID>` are compiler
output despite the word `checkpoint` in their crate names. Only those two
directory layouts, only at the first level of the selected debug incremental
tree, receive that name exception. Files, symlinks, nested or malformed versions,
other checkpoint names and release/deps get no exception. Real checkpoint,
snapshot, archive, sidecar and lock artifacts beneath either crate directory
still refuse the census. Rejections identify the offending relative path and
node type. The initial 392a9 checker correctly performed no deletion; its
overbroad substring refusal is preserved as failed check evidence.


## Exact checkpoint-named release compiler outputs

The shared release/deps profile also recognizes the first-level Cargo outputs
of `jetstreamer_checkpoint_restore_probe` and
`jetstreamer_epoch140_checkpoint_journal`. Recognition requires a 16-character
lowercase hexadecimal Cargo ID and the complete exact generated dep-info record
for the known source paths and output. Empty `.rmeta` placeholders require their
paired Clippy record; executable outputs require the paired non-Clippy record
and a valid bounded little-endian ELF64 x86_64 PIE container. The two crate names
alone never make a file disposable. Nonempty metadata, `.rlib` exceptions,
unknown crates, malformed IDs, nested nodes and symlinks remain rejected.

This restores the previously qualified shared compiler classifier and adds the
same ELF proof for the observed epoch140 journal binary. The failed older check
is retained. A new checker still needs its own sealed deployment and fresh
positive ledger before a separately bound retirement plan can run. Every existing
source, Cargo lock, builder, process, staged-reference and inode gate remains.
Dep-info witnesses are unlinked after their outputs so interrupted cleanup
retains enough evidence to revalidate each remaining compiler pair. Other cache
profiles keep their existing unlink order and protected-name rules.


The paired Clippy dep-info accepts exactly the two observed complete records:
`-D warnings` and `--no-deps -D warnings`, using Cargo's recorded Clippy separator.
All source/output paths, blank lines, environment keys and remaining bytes must
match. Unrecognized options or extra/missing records still reject; this does
not parse or generally allow arbitrary Clippy argument strings.

## November 19 incremental retirement

The existing sealed `6f4a1600` checker (SHA-256
`8116e74726102e97cc6bdfd9d67f748cea148c1e2a374e81731957edc33380d0`)
completed a fresh positive check and separately authorized retirement of the
fixed Ubuntu debug incremental cache. Both plans bound clean source
`a567bfef80d2ca103a672499868625a325d99636` and Cargo.lock SHA-256
`7ae1c48cfa7d127a40f993bdf892560a489aabc79ac5719af36f15bb7fe11f85`.
The positive census inspected 1,276 processes, found no active builders,
process references or staged unit references, and recorded 4,289 entries.

The immutable positive ledger is
`/var/lib/jetstreamer/horizon-dev-cache-check-incremental-20261119-v1/check.json`.
The separately sealed retirement plan is
`/var/lib/jetstreamer/horizon-incremental-retirement-plan-20261119-v1/plan.json`.
The completed retirement's evidence directory is
`/var/lib/jetstreamer/horizon-dev-cache-check-incremental-retirement-20261119-v1`;
its `completion.json` SHA-256 is
`cc8a1b8458f529dadc9eaaace386bbf81c6d169ae4a48873645cc1758cbf4667`.

The cache's unique-inode allocation fell from 5,524,897,792 to 606,208 bytes.
Every original directory and parent Cargo lock inode 12857456 was preserved.
Filesystem availability recorded immediately before and after retirement rose
from 4,046,490,783,744 to 4,052,439,687,168 bytes. This 5,948,903,424-byte
filesystem delta includes concurrent activity; it is not a cache-only savings
claim. No replay, archive, R2 object, reader dependency cache or sealed runtime
was removed. Additional lane admission still requires the independent resource
and recovery qualifications.

The November 19 05:54 control cycle also qualified and retired the fixed
`target/debug/deps` cache using the sealed `b42f0488` checker. Both plans bound
clean source `135657fed5f64532889ed6a48ea2b275597f1475` and the unchanged
Cargo.lock. The first check correctly refused a compiler still exiting after
an OOM; its failure was retained. A distinct check passed after that process
exited, finding no live or staged references. The separate retirement repeated
the guarded checks and completed under invocation
`69d9217cdfe74f2eb6a001e097d3d6d4`. The dependency directory is absent; the
parent Cargo lock inode `12857456` is unchanged.

The prior `du` measurement counted 18,046,844,928 unique-inode allocated bytes;
the checker's pathname-based census counted 20,690,976,768 bytes. Neither is
the filesystem delta. Available space increased by 12,953,042,944 bytes,
from 3,984,316,628,992 to 3,997,269,671,936 bytes, while replay and the new
epoch-205 audit continued allocating. Completion evidence is
`/var/lib/jetstreamer/horizon-dev-cache-check-debug-deps-retirement-20261119-v1/completion.json`,
SHA-256 `3b95437869e6f0049ed09a17a0708ff41e18d9aaccf12a788f59962f57227120`.
The compact space record and all failed/successful journals are under
`/home/ubuntu/.codex/diagnostics/horizon-source-retry-commit-20261119-v1`.
The original private reader dependency closure remains required by prepared
node builds. Mixed `.codex/tmp-readiness` trees still need exact consumer and
lineage review; this retirement does not authorize their bulk removal.
