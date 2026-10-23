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
