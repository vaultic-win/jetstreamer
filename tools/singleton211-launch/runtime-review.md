# Full211 shared integration review

This directory is source only. No compilation, test execution, qualification,
launch, Git operation or R2 mutation was performed by this child. Main owns
those transitions. Only this new crate and its documents were changed.

## Concrete source fixes

- The implementation lives in `src/lib.rs`; `src/main.rs` calls its public
  `run_from_environment`. This avoids nesting the binary crate as a library
  module and compiling its internal tests through two roots.
- `peer211.rs` binds the actual successful native211 proof, original running
  origin, original admission floor and PID1 terminal tuple. Its owner is checked
  before and after the complete native census, including absent old PID and
  drained descendants. The terminal reservation keeps the entire memory cap,
  disk growth and filesystem floor. Missing fleet history cannot silently drop
  a retained reservation. Pure negative tests cover changed owner, active
  membership and reduced obligations; they have not been executed.
- Native265 still requires its registered live owner. A later terminal265 is
  rejected until its genuine terminal proof and retained owner integration are
  added. Do not reinterpret it as a generic dormant reservation.

The native211 proof and original intent were inspected through the privileged
reader: both are mode0400. Keep their custody; the uid1000 held gate reads the
new mode0444 input capability and startup graph, not those private originals.
Historical lifecycle validation runs through the privileged reader.

## Gates that still block a production launch

1. **Shared integration:** the frozen packet's `integration.patch` and separate
   guard patch remain unapplied. Main must reconcile the current native265
   consumer/wrapper baseline, update the main lockfile and actual wrapper extern
   binding, then test and publish the exact dependency graph. This crate's
   copied lockfile is parsed but has not been resolved or compiled.
2. **Protective-stop qualification:** the Rust `qualify-guard` and
   `retire-qualification` routes are implemented but unbuilt and unexecuted.
   See [protective-stop.md](protective-stop.md). Main must qualify the exact
   artifact and sandbox using actual stop evidence, then seal and accept capture
   and retirement. Production admission now semantically validates that graph;
   flags or a native265 stop proof cannot satisfy it.
3. **Actual access and timing:** qualify the launcher as root with writable
   `/var/lib/jetstreamer` and `/etc/systemd/system` parents. Sealing creates
   temporary siblings; mounting only absent destination leaves writable fails.
   Keep the root evidence private. Prove PID1 bus access, read-only private
   evidence access, and the sealer's `umask 0022` path. The producer runs as
   uid/gid1000 with only its whole replay root writable and genesis projected
   read-only. Prove every input and startup graph read as that identity.
4. **Guard limits and stop path:** the generated guard is still 256MiB,
   64 tasks, 100% CPU and `TimeoutStartSec=15`. Native265 uses a different guard
   and 60 seconds; that does not qualify this budget. Measure the exact generic
   whole-root scan and real `/usr/bin/systemctl stop` path in the intended
   sandbox. No blanket capability widening or inferred stop success.
5. **Production equivalence:** prove the existing node/worker's complete actual
   source, dependencies and features against published `origin/account-updates`.
   Native211 success and a matching Cargo.lock alone are insufficient. Preserve
   the successful input test; do not rerun it.
6. **Current fleet:** obtain Main's next accepted complete observation and
   rederive reservations, finalization states, periodic controls and memory
   target. The old 19:10 observation predates epoch248's 19:17 completion.
   Qualification/build phases need their own bookings. No memory release is
   inferred from the newly stricter native211 adapter.

The generic standalone guard does not itself authenticate the held launcher.
The launcher brackets first-fire acceptance with exact mapped-gate, sole-PID,
no-child and no-descendant checks, and the held process independently validates
the release proof. Its first sample's empty worker list is accepted in that
context. Preserve this distinction when recording qualification evidence.

## Main's next sequence

1. Review and qualify the protective-stop implementation and complete shared
   consumer integration above. Under a separately admitted bounded build, run locked
   offline crate tests and Clippy, guard feature-on/off tests, and actual fleet,
   status and wrapper adapter tests. Reconcile failures, publish all required
   source, and bind exact artifact provenance and remote containment.
2. Seal the launcher and guard to their fixed paths from `README.md`. Qualify
   equivalent sandbox read/write/fsync access, missing/expired/wrong token
   refusal and same-PID exec. Follow the actual stop/capture/retirement sequence
   in `protective-stop.md` after the separately booked input capability. Use
   actual durable captures in all consumer acceptance tests. Preserve the existing native211 terminal proof.
3. Book the 8.7GB input hash phase independently, outside the startup lease:

   ```text
   LAUNCHER inputs SELF_SHA NEW_INPUT_EVIDENCE_DIRECTORY SEALED_CAPABILITY_DIRECTORY
   ```

4. Build a fresh exact current-fleet review with the full eight source roles,
   actual prestart evidence, 16 allowed CPUs, and unchanged hard obligations.
   The metadata launcher needs the parent mounts described above. The commands
   below require new execution directories on every invocation:

   ```text
   LAUNCHER admit REVIEW REVIEW_SHA SELF_SHA NEW_ADMISSION_EXECUTION_DIRECTORY
   LAUNCHER launch REVIEW REVIEW_SHA SELF_SHA NEW_LAUNCH_EXECUTION_DIRECTORY
   ```

   `launch` performs a new admission; it does not reuse the previous command's
   lease. Its original 60-second lease includes sealing, manager operations,
   first timer fire, repeated complete admission and token publication. The
   operator deadline is at most 50 seconds. Hashing in final historical-handoff
   validation also needs measured runtime; static estimates are insufficient.
5. Accept the actual handoff through the fleet and single existing cadence,
   retire the old native211 telemetry claim through its qualified terminal
   transition, and publish/read back the definite full211 ETA. Count a replay
   lane only after real transaction progress. Natural completion, current-plugin
   playback of authenticated R2 readback, sidecar and local retirement remain
   separately gated.

The gate clears inherited environment and restores a fixed PATH, HOME, runtime
thread settings and invocation ID. Qualify the actual canonical-block fetch
path with that environment and read-only home; do not assume an interactive
gcloud refresh or shell PATH proves service credential availability.
