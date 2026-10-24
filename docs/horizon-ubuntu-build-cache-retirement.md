# Ubuntu debug dependency cache retirement

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
UID1000 ownership and one filesystem are required throughout. Child symlinks
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
256MiB, one million members, depth128), binding source, lock, checker, profile,
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

The October24 audit measured about40.41GB in release/deps and75.72GB in debug
incremental; the entire release profile was only44.73GB, so it cannot yield200GB.
These are historical candidate footprints, not current reclaimability proofs or
promised free-space gains. Existing hardlinks outside the target retain their
data, and live lanes keep allocating. Root must review a successful fresh check
and exact plan before execution and measure actual free space independently.
Prefer retiring unused debug incremental first so ongoing release helper builds
retain their dependency cache; rebuilding a deleted cache consumes space again.
