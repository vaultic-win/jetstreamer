# Prepared prefix completion to private V3 assembly

This route is source preparation. No actual-prefix completion, new prefix
reread, handoff execution, archive scan, Bank run, admission, service launch or
R2 mutation has been performed. There is no operational plan populated with
future hashes. Keep the healthy native 20 prefix unchanged.

## Existing independent reader: use its exact native 20 profile

The current `jetstreamer-qualification-verify` source already supports
`qualification-223-v1620-prefix-*`, full worker a651b7a6, native 20 revision
77bdb45d and the 431,523-slot known-root span. No new reader algorithm or
permissive generic fallback is needed. Build/test/seal this current executable;
do not assume an older sealed native 25 tail reader includes that profile.

After the actual prefix naturally completes with original terminal manager
success, root preserves its original receipt, manifest and journal. Under a
separately bounded read-only verification owner running as ubuntu, the exact
reader arguments are:

```text
SEALED_QUALIFICATION_VERIFIER
  /home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/output/epoch-223.jet
  --private-root=/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1
  --expected-epoch=223
  --expected-output-start-slot=96336000
  --expected-bootstrap-slot=96335538
  --expected-terminal-slot=96767522
  --expected-runtime-profile=solana-v1.6.20
  --expected-worker-sha256=a651b7a6ee3c0d4f8359e1ea6cfcb96becf259d440ee744beb173b264de6af20
  --receipt=/home/ubuntu/.jetstreamer-private/qualification-223-v1620-prefix-full-root-v1/receipts/epoch-223.native20-prefix.validation.json
```

This is an argument specification, not a launched command. The actual sealed
reader digest, safe execution envelope and unoccupied no-clobber receipt path
must be bound at that time. The reader must finish its full archive/manifest
reread, both canonical-root checks and exact native 20 identity checks. Preserve
and root-seal copies of its actual receipt, producer completion and manifest,
plus original terminal/PID1 journal evidence. No receipt or digest is predicted.

## Existing metadata handoff gate

Run the already qualified/sealed f44af401 tool-only gate only after those actual
inputs exist. Its binary digest is
137b5a3a767604ea4c9f7405dd0af7af0eb860f30e5ece52ce49017825d35c22.
Follow `epoch223-cross-runtime-handoff-plan.md`; keep its immutable request and
actual output. It binds the exact corrected native 25 input d79e374e, requires
full consensus tuple equality and plans validator-local cursor normalization.
Its output grants no assembly or publication authority.

The gate implementation now lives in a shared source module used by both the
CLI and assembler. Its existing schema, predicates and metadata output stay
the same. The old sealed f44 gate remains the required gate authority; a new
binary produced during the shared-module refactor is not silently substituted.

## Missing executable link: prepared private V3 assembler

`jetstreamer-epoch223-private-assemble` supplies the actual file-to-file merge
entrypoint. It cannot replay or restore a Bank and has no R2 or sidecar-writing
code. Its strict root-owned immutable plan schema is
`jetstreamer-private223-v3-assembly-plan-v1`, containing `handoff_request`,
`handoff_receipt`, `admission` (each `{path, sha256}`) and fixed `output_root`:

`/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1`

CLI arguments are `PLAN PLAN_SHA256 SELF_SHA256 [--check-only]`. The check-only
path rehashes its self/plan and the real metadata evidence, recomputes the shared
gate, requires the old qualified gate's actual matching receipt, and constructs
validated V3 provenance. It does not read admission, query host/services, open
epoch archives or create output. Even this check awaits actual future inputs.

Actual execution additionally requires both original source services inactive
after exact zero-restart success, a fresh root-owned 0700 empty output root on
the source filesystem, exact persistent owner identity and a separate fresh
resource admission. The assembler requires unit
`horizon-assemble-223-native20-native25-v1.service`, root, Type=exec,
Restart=no, zero restarts, 24h RuntimeMax, 64 GiB MemoryMax, 48 GiB MemoryHigh,
swap 0, CPU 400%, Tasks 512, UMask 0077, PrivateNetwork=yes,
ProtectHome=read-only, ProtectSystem=strict, NoNewPrivileges=yes and exactly
the fixed output root writable. Root's unit must retain only the traversal
capabilities needed to traverse private inputs and perform the complete
read-only process-reference census: exactly cap_dac_override and cap_sys_ptrace
in both bounding and ambient sets. Never relax the private inputs. The earlier
sealed 20e tool remains unchanged; this new source requires separate qualification
and sealing before any operational use.

The shared `jetstreamer-horizon-observe::source_idle223` component now supplies
the source-idle check directly to the assembler and can also be called by its
resource-admission adapter. It adds no independent gate service or poll loop.
For each exact prefix/tail unit, successful complete loaded-unit and pending-job
censuses bracket a full archive-reference scan and exact cgroup emptiness checks.
A loaded unit must retain its original invocation (or a legitimately empty
terminal invocation field), success/0, zero restarts, no PID/job and inactive/dead
state. An unloaded unit needs two positive complete-manager absence observations,
no queued job, an absent/unpopulated exact cgroup and no command/map/link/descriptor
reference to its archive. Failed/partial queries, contradictory presence, changed
manager identity, populated descendants and permission failures refuse the check.
Historical success still comes from the actual hash-bound handoff evidence;
current absence never substitutes for that history. Do not relaunch old producers
or synthesize current fields after systemd collection.

The assembler pins both opened private sources, requiring uid 1000, mode 0600,
one link and no checksum sidecar. It invokes the existing `merge_runtime_segments`
with their independent manifest digests/terminal hashes and exact native 20/
native 25 V3 provenance. V4 remains same-runtime-only. The shared merger hashes
and decodes the complete sources, checks PoH and all metadata/update phases,
rejects write gaps/duplicates/missing events, and performs the checked normalized
mapping. No raw cursor equality, padding, truncation or event dropping occurs.

Output is no-clobber mode 0600 `epoch-223-private-v3.jet`, bounded to 160 GiB and
24h. Every write preserves the independently admitted filesystem floor, which
must be at least 2 TB plus any older protected claims; cgroup memory/CPU/task
bounds protect the host. It fsyncs the output/directory, rechecks both original
source identities and owners, hashes the completed output through a pinned
handle and writes a private no-clobber `assembly.json`. `intent.json` is durable
before output creation. Failure preserves all inputs and partial output; there
is no automatic retry, cleanup, resume or replacement authority.

## Prepared independent admission; qualification still required

The existing epoch 144 assembly admission/fleet adapters are closed to 144 and
cannot be borrowed. Source now includes an independent two-stage actual 223
adapter producing `jetstreamer-private223-v3-assembly-admission-v1`. It remains
unqualified and unsealed until the actual prefix completes and its real
independent reread/terminal/equality evidence is available. Its contract binds the actual assembler, handoff
request/receipt, prefix/tail digests, output filesystem/device,160 GiB maximum
output,64/48 GiB memory limits,24h time limit, complete accepted fleet ledger,
fresh invocation-bound observer and all preserved older guards/century claims.
It records protected disk/memory reserves and a sample no older than 15 minutes.
The assembler rehashes those bound ledger/observer files and refuses missing,
stale, mismatching or insufficient capacity evidence. It does not manufacture
that independent admission. Do not hand-write a positive admission JSON or
treat the metadata gate's equality fact as capacity authority. Qualify this
adapter only against the real completed prefix and fleet present then.

## Separate final checks

Private merger success is not an independently verified complete archive or
publication approval. Its completion leaves independent final full verification,
current plugin verification, runtime promotion, canonical sidecars, publication,
retirement, repair closure and R2 authority false. Prepare the final private V3
full/plugin/fleet adapters separately; do not route this source through a
single-runtime V2 verifier or the 203 same-runtime V4 publisher. Only after all
normal full/plugin/boundary/publication checks may the normal authenticated
uploader commit a matching sidecar. Keep 223 open until the verified ready pair.


The first stage is `jetstreamer-r2 admit-assembly223-capacity SPEC
--spec-sha256 HEX --self-sha256 HEX`. Its closed spec schema is
`jetstreamer-private223-assembly-capacity-spec-v1`, with `resource_basis`
(the existing exact observer/fleet/protected_guards map) and a no-clobber
`/var/lib/jetstreamer/horizon-223-assembly-capacity-NAME/capacity.json` output.
It reuses the neutral `maintenance_capacity` complete-owner core. Foundation's
wrapper preserves its old successful receipt shape and disk-only behavior.
Assembly adds the sealed 160 GiB output plus 32 MiB metadata reservation, at least 2 TB protected floor, a 64 GiB
candidate memory cap, complete typed remaining owner memory, and 10% host memory
reserve. Sampled and fresh available memory must fit both before and after.
It requires every protected timer active and the exact latest completed guard
fire in both brackets. Unknown owners, active 223 sources, mismatching observer
bindings, terminal histories or caps refuse admission. This stage authenticates
capacity only and explicitly denies source completion and assembly launch.

The second stage is `jetstreamer-epoch223-assembly-admit PLAN PLAN_SHA256
SELF_SHA256`. Its closed request schema is
`jetstreamer-private223-assembly-admission-request-v1`, with bound
`handoff_request`, `handoff_receipt`, `capacity`, separately supplied
`capacity_tool_sha256` and `assembler_sha256`, and no-clobber output
`/var/lib/jetstreamer/horizon-223-assembly-admission-NAME/admission.json`.
The tool reruns the shared real metadata handoff preparation, requires the
actual old qualified gate's exact receipt, validates the independent capacity
and its freshness, rehashes the original ledger/observer and performs the
shared exact loaded/unloaded source-idle checks. It writes mode 0400, fsyncs the
receipt and parent, records the actual output device, and grants only the
fixed private assembly. No sample, future output hash, completion receipt,
checkpoint or admission may be invented to exercise this route operationally.

Before operational use, qualify and seal both stages plus the rebuilt
assembler; add the exact assembly fleet/capture and protective guard adapters,
then prepare the private V3 independent full/current-plugin/import route.
These last adapters remain a real deployment blocker; a source test or an
admission file alone is not authority to bypass them.

## Exact qualification and seal checklist

1. Keep the original native 20 producer and native 25 tail untouched. After actual
   native 20 PID1 success, preserve its original completion, segment manifest,
   terminal journal and independent prefix reread. Invoke the previously
   qualified gate in `horizon-223-handoff-plan-tool-f44af401-v2`; require the
   shared metadata recomputation to reproduce its real result. A loaded-to-unloaded
   manager transition needs the shared complete absence adapter, not a recreated
   service or an invented successful `systemctl show` row.
2. Validate the new observer core fixtures, node assembler integration and
   admission fixtures, R2 maintenance-capacity/closed-scope fixtures, and strict
   production Clippy. Build the actual release binaries once in a coordinated
   shared Cargo window. No test invokes source-idle `observe` or real host
   admission by default.
3. Hash the actual rebuilt assembler, admission writer and R2 binary. The Rust
   deployment sealer must seal those exact bytes, source revision/tree and unit
   templates without altering the two older packages. No future binary digest
   may be substituted in a spec before this step. The minimal sandbox proof
   must demonstrate private traversal and complete `/proc` scanning with only
   `cap_dac_override cap_sys_ptrace` while the sources remain read-only.
4. Prepare the exact assembly namespace in fleet/observer/guard code and seal
   it before launch. Fresh capacity uses the accepted normal sample at that
   time, plus complete owner and active-timer/latest-fire brackets. Then the
   node admission authenticates the real handoff/source-idle and produces the
   private mode 0400 admission. A successful admission grants only the fixed
   bounded private assembly, never any next-stage gate.
5. After the actual assembler terminal, bind its actual invocation, output
   identity, full hash, provenance and completion with successful PID1 history.
   Recompute the independent V3 expectation from the original two manifests and
   handoff, rather than trusting a hash copied from the assembled header. The
   strict existing `verify_archive --full --anchor SLOT HASH
   --expected-terminal SLOT HASH --expected-provenance-sha256 HEX --threads 8`
   supports this independent provenance binding. For epoch 223 the adjacent
   anchor slot is **96335999** and terminal slot is **96767999**. The original
   native 20 bootstrap checkpoint **96335538 is not the adjacent anchor**;
   preserve separate sealed finalized boundary metadata for the actual hashes.
6. The private V3 runner must stage one unchanged canonical-name
   `epoch-223.jet` outside `HORIZON_DIR`, bind independent full and current-plugin
   scans to those same bytes, preserve before/after identities and fsynced logs,
   and leave runtime promotion/import/sidecar/R2 gates false. Its exact service,
   complete-owner admission, fleet/capture and import adapter are prepared in
   the continuation source and still require current qualification and sealing; neither the ordinary V2 qualification reader
   nor the fixed 203 V4 publisher supplies this route.
7. Only the separately qualified import/publication path may produce a local
   canonical pair. The usual full/plugin/boundary and authenticated remote
   upload/readback/sidecar gates remain mandatory. Status cleanup follows the
   canonical remote sidecar commit, with no anonymous-origin dependency.

The assembly capacity reservation includes 32 MiB for bounded admission/capacity
and assembly metadata, and the assembler withholds a further 1 MiB above its
admitted floor throughout archive writes until its final receipt is durable.
It rechecks that final metadata did not cross the protected floor.


The next source candidate also adds `source_idle223::observe_assembly(actual_iid)`
for the final V3 consumer. It keeps the original Prefix/Tail API and fixed
namespace unchanged, accepts only the fixed assembly unit/archive and a real
nonzero lowercase 32-hex invocation, and reuses the complete loaded/unloaded
manager/cgroup/process-reference brackets. It grants no historical success;
the consumer must first authenticate actual completion and PID1 evidence.
This API and the coordinated `ceil(total_memory/10)` reserve/validator change
are source preparation until their own tests/build/seal. The already qualified
529fc90f candidate remains unchanged. Do not deploy a helper-only rounding
upgrade with the older strict node capacity validator.

## Current independent V3 final-route source

The continuation adds `jetstreamer-epoch223-boundary-metadata`,
`jetstreamer-epoch223-private-verify` and `jetstreamer-epoch223-publish`.
These are offline candidates, not deployed services or proof that the archive
has passed any actual scan. The preserved 529fc90f assembler and older qualified
handoff/prefix reader remain separate authorities.

The metadata collector requests finalized exact-slot `getBlock` responses from
`https://api.mainnet-beta.solana.com` for anchor 96335999, first slot 96336000
and terminal 96767999. It preserves bounded raw requests/responses, rejects null
or skipped boundaries, validates the adjacent parent/hash/height relationship,
and never uses bootstrap 96335538 as the adjacent archive anchor. Missing exact
boundary data remains a blocker; no Bank rerun is needed merely to format it.

The independent verifier authenticates genuine assembly completion and PID1
success, recomputes the complete source-derived V3 expectation, and takes fresh
complete-owner capacity for one bounded copy plus logs. Its exact unit is
`horizon-verify-223-native20-native25-private-v3-v1.service`, with a root-private
`/var/lib/jetstreamer/horizon-223-private-v3-scan-NAME` directory, a 160 GiB
archive bound, 256 MiB metadata/log allowance, 64/48 GiB memory limits, no swap
and a 24-hour bound. It runs full verifier 067ca312 and current plugin 167954ad
against the same immutable canonical-name private copy. Independent source
provenance, actual canonical edges, unchanged source/copy identities and bounded
fsynced logs remain mandatory. The resulting receipt grants no import, sidecar,
registry, retirement or R2 authority.

The separate V3 publisher requires an explicit immutable local-publication
plan, actual captured verifier invocation/PID and original application/PID1
success journal, the exact verifier binary digest, actual full/plugin arguments
and log digests, and a fresh scoped verification-idle census. It independently
rederives the handoff and canonical metadata again, checks complete V3 coverage,
retains the original assembled source and measures the exact private copy before
publication. It uses the existing absence-only recoverable batch transaction,
same-mount/write-scope checks, held root-only receipt descriptors and permanent
UID/GID 1000 privilege drop. Its durable private publication receipt precedes
both uploader `.ok` gates; their third digest is the actual private verifier.
It cannot perform R2 mutations or promote the runtime registry.

This publisher intentionally refuses a preexisting batch. Generic batch startup
recovery must not run before authenticating the pending batch's exact context;
the shared library now provides an expected-context recovery API that checks
manifest fingerprint, exact epoch census and exact original publication context
under the destination writer lock before changing any namespace. Foreign and
unarmed pending batches remain untouched. Its separate publisher retry/receipt
adapter still needs implementation and qualification before idempotent deployment.

Verification capture/guard/fleet/peer and normal pipeline-status bindings are now
prepared as source. The verifier capture authenticates the actual sealed runner,
its intent, original PID, invocation, sandbox and monotonic start, plus its accepted
complete-owner capacity predecessor. Its natural zero-worker protective guard
uses the already qualified Foundation guard 044ccba7 without granting worker-root
allocation credit. The outer accounting wrappers preserve every older owner and
refuse overlapping epoch 223 phases. Normal pipeline status uses dashboard phase
`verification` and the exact accepted diagnostic owner. The existing generic
pipeline inactive lifecycle can identify that same owner; this grants no cleanup
from mere absence or successful content verification. The observer preserves the
same sample's archive inode and byte length, tolerating only monotonic growth by
the fixed assembler and retaining the immutable assembled-source size throughout
the final scans. A separate routine polling loop is never introduced.

These adapters still need final offline tests, sealing, exact sandbox capability
proofs and actual fresh fleet admission. The currently fixed five-owner routine
cycle rejects replacing the original prefix with a new assembly/scanner; prepare
its explicit phase handoff and updated status model at that time, before launch.
Assembly capture now records the actual
producer PID and authoritative monotonic invocation start so normal 30-minute
status publication can use genuine elapsed time. Neither stage adds a polling
loop. Status phase remains `verification`, with an inclusive definite estimate
through authenticated R2 sidecar commit; the metadata stays until that commit
or independently proved inactive ownership.
