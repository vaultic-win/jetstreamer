This standalone Rust wrapper runs independent full and current-plugin scans of
the exact private epoch145 canonical prefix. It does not write a checksum,
import an archive, promote a runtime, publish, retire files, or access R2.

The full scan uses the independently acquired slot62639999 incoming anchor,
slot63071999 terminal blockhash, and the source-derived provenance digest from
the qualified exporter's completion. The plugin scans `145:145` through the
existing qualified `horizon_pipeline`. Both stages hash the immutable prefix
before and after their child command. Neither stage opens the archive body or
starts its child until its actual invocation has fresh opaque memory/DATA
admission and a genuine timer-driven guard token. The native guard and internal
watchdog preserve source identity, kernel limits, resource floors and original
producer closure throughout the operation.

The two dependency graphs are intentional. `main.rs` uses the small operational
graph; `admission_bridge.rs` links the existing opaque parent-memory and DATA
constructors. Use the exact compiler inputs and transitive dependency hashes in
the qualification, rather than an arbitrary Cargo build or similarly named rlib.
The retained bridge graph has byte-identical libraries at different paths after
cleanup. The qualified exporter's deployed bridge is unchanged.

Both graphs passed production and test Clippy and actual builds. All22 core
tests and all3 bridge tests passed, with no ignored or filtered tests. These
results cover source scope, canonical width, provenance, original completion,
authority rejection, admission clocks, guard-token identity/age, metadata custody
and native command parsing. They do not prove native scan capability or qualify
either archive scan. Actual capability and guard checks remain required.

Before preparing a runtime plan:

1. Require the genuine exporter completion, successful original PID1 event,
   reaped actor and empty cgroup/descriptors. Stop and drain only that completed
   exporter's own guard/timer; preserve the original epoch199 controller/timer.
2. Preserve the source and71-slot tail. Close the exporter's admission,
   pre-read-guard and completion metadata as immutable evidence after its last
   writer/guard has drained. Preserve exact bytes and original paths. The
   original admission binding inside the completion uses its `/var/lib` path;
   expose its home-backed state at that same path with an exact read-only bind
   in the verifier and guard sandboxes. Do not substitute a different binding
   or fabricate a shortened native manifest.
3. Seal a root-owned original completion receipt with schema
   `horizon-epoch145-production-export-original-completion-v1`, the exact
   completion/admission bindings, original unit/IID, success/zero exit, original
   PID1 rows, and the actual outer/cgroup/descriptor/guard/timer drain evidence.
4. Obtain fresh candidate-specific opaque accounting. Each serial scan reserves
   its own64GiB actor,256MiB guard,6GiB external pool and at least1,612,808,192B
   of uncovered memory. Retain the whole canonical-prefix DATA allowance,
   original source obligations and all newer phase obligations. The compiled
   DATA floor is a minimum, not permission to omit a later allocation.
5. Normally seal both executables, their qualification and the exact stage plan.
   Prove the home-backed private state projection and read-only archive access
   in the final sandbox. Run metadata-only capability, then a separately bound
   native actor/guard attempt. Preserve failed originals; never restart them or
   manufacture a token. Capture original completion/drain for each successful
   scan before handing both receipts to a separately qualified publisher.

The production build does not enable a synthetic fixture entrypoint. Its fixed
source and producer pins intentionally select the real1328 export generation.
A replacement export generation requires a new reviewed qualification.
