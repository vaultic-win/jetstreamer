# Slot 92447542 cache lifecycle candidate

`jetstreamer-snapshot92447542-cache` handles only the compressed snapshot with
generation `1629744948337785` in `mainnet-beta-ledger-us-ny5`. It never selects
another file, launches replay, or writes cloud objects. This is a source
candidate; no deployed lifecycle qualification or cache eviction is established
by adding the binary.

The foreground operations are `check`, `evict CHECK_SHA256`, and
`restore CHECK_SHA256`. All require an independently hash-bound private plan,
a Root-owned sealed executable, and the exact helper's lifecycle qualification.
The check preserves the original acquisition receipt, verifies generation
metadata and all three payload digests, and binds the original inode. Eviction
uses a no-clobber move into Root-private quarantine and verifies that moved
inode before unlinking. Restore requires its own fresh capacity admission and
publishes a new inode and receipt without replacing an existing destination.

Qualification must precede operational use:

- Review the complete deployed consumer, interpreter, launcher and input
  readsets. Authenticate nonlaunchable dispositions and effective drop-ins;
  merely finding no literal filename is insufficient.
- Prove the actual service identity, capabilities, SDK identity/configuration,
  resource limits and complete process/reference inspection. Preserve the
  original acquisition's clean terminal evidence.
- Exercise the actual quarantine rename in the final sandbox. Two writable
  bind mounts can produce `EXDEV` despite matching device numbers. Never widen
  the whole filesystem to make this test pass.
- Exercise recovery after every durable transition, failed-transfer shutdown,
  floor/timeout/size failure, destination/receipt collisions, and an isolated
  restore round trip through the same engine. Qualification receipts must bind
  genuine results, not replace missing tests with asserted flags.
- Bind the normal production artifact's actual sources, features and compiler
  flags and seal it. Source tests do not qualify an executable deployment.

The ordinary test scope is the entire `snapshot92447542_cache::` module,
including `retained_metadata_fixture`. Filtering only `::tests` omits the
retained metadata and real SDK-process-group controls. The retained 796-byte
metadata fixture contains `bucket`; a separate derivative checks normalization
without that field. The process-group control uses a disposable shell and
descendant, without calling gcloud or accessing credentials.

Local source qualification may use a bound standalone projection of the crate
with pinned dependency versions. Preserve its complete transitive modules and
report its actual Cargo features; this does not establish the normal workspace
artifact or operational qualification. No canonical archive, sidecar, receipt,
or R2 object is eligible for deletion through this candidate.

## Explicit native SDK metadata control

The test-only Cargo feature `snapshot92447542-native-sdk-tests` adds exactly
`snapshot92447542_cache::native_sdk::actual_uid1000_sdk_metadata_profile`.
Compile the native test harness with this feature, then run that exact test
with `--exact --test-threads=1` under its separately admitted Root systemd
service. Ordinary builds and the existing twelve module tests use features
`[]`; do not enable the native feature in normal test selection or production.
This control calls the same private `metadata_core` and `sdk_command` used by
production. It does not construct a production `Plan`. Its successful lookup
is only `gcloud storage objects describe` for the fixed versioned URI and
account/project already pinned in the production command. No snapshot body,
download, cache eviction, restore, R2 call or replay is part of this control.

Supply the admission via the two independent environment values
`JETSTREAMER_SNAPSHOT92447542_NATIVE_ADMISSION` and
`JETSTREAMER_SNAPSHOT92447542_NATIVE_ADMISSION_SHA256`. Every `Bound` below is
`{"path": "/absolute/canonical/path", "sha256": "lowercase-64-hex"}`.
Admissions, profiles, source evidence and lineage must be regular Root-owned
files without write bits. Preserve each earlier failed native attempt.

The strict admission JSON fields are:

- `schema`: `jetstreamer-snapshot92447542-native-sdk-admission-v1`.
- `route`: `native-sdk-metadata-only`.
- `recorded_unix_seconds`, `expires_unix_seconds`: actual admission integers;
  validity must be positive, at most 180 seconds, and still current at entry
  and completion. Generate fresh clocks; this source supplies no receipt.
- `test_binary`: `Bound` to the actual native harness executable; the test
  checks `/proc/self/exe` against this exact file and hash.
- `normal_helper_lineage`: `Bound` to the lineage described below.
- `gcloud`: `Bound` to the actual canonical Homebrew `gcloud`, validated by
  the production SDK command engine with its existing digest/custody rules.
- `profile`: `Bound` to the actual invocation's profile described below.
- `sources`: four `Bound` values for `snapshot92447542_cache.rs`,
  `snapshot92447542_native_sdk.rs`, this `README.md`, and the observe crate's
  `Cargo.toml`. Hashes must match bytes embedded when compiling the native
  harness. Retain the complete normal artifact's transitive source proof too.
- `output`: a new `native-sdk-result.json` directly inside an existing
  canonical Root-private mode-0700 result directory. Publication is no-clobber.

The strict normal lineage JSON fields are `schema` =
`jetstreamer-snapshot92447542-normal-helper-lineage-v1`, `helper` (`Bound` to
Root-owned immutable normal helper), `artifact_proof` (`Bound`), `sources`
(the same four source bindings), `cargo_features` = `[]`, `lto` = `fat`, and
`codegen_units` = `1`. Derive the artifact proof from genuine normal build
records, never from this test's success. Its required fields are `schema` =
`jetstreamer-snapshot92447542-normal-artifact-proof-v1`, `helper_sha256`,
`cargo_features` = `[]`, `lto` = `fat`, `codegen_units` = `1`, and
`source_hashes` (a JSON object mapping those four exact basenames to SHA-256).
The proof may retain additional compiler/build evidence. The normal helper
must be rebuilt from the new sources before using this control; lineage to an
earlier source revision is rejected even if its ordinary tests passed.

The strict native profile JSON fields are `schema` =
`jetstreamer-snapshot92447542-native-sdk-profile-v1`, `unit`, `invocation_id`,
`control_group`, and `expected_properties` (a string-to-string JSON object).
Bind the service's actual 32-character lowercase systemd InvocationID and
`/system.slice/UNIT.service` cgroup; do not invent these before activation.
Use a guarded admission handoff before the harness begins useful work. The
harness must become the service's actual `MainPID` (an exec handoff preserves
PID); a launcher retained as MainPID is rejected. `INVOCATION_ID`, actual
`/proc/self/cgroup`, MainPID/starttime and systemd properties are checked at
entry and completion. Only Root identity is accepted.

`expected_properties` must contain the complete effective values for `Id`,
`ActiveState`, `SubState`, `InvocationID`, `ControlGroup`, `NRestarts`,
`MemoryMax`, `MemorySwapMax`, `CPUQuotaPerSecUSec`, `NoNewPrivileges`,
`ProtectSystem`, `ProtectHome`, `KillMode`, `ExecStart`, `MainPID`, `User`,
`Group`, `TasksMax`, `RuntimeMaxUSec`, `ReadWritePaths`,
`CapabilityBoundingSet`, and `AmbientCapabilities`. Additional genuine
properties are allowed and are also compared exactly. Required values are
active/running, zero restarts, 536870912-byte memory, zero swap, CPU quota
`2s` (200%), tasks `128` or `512`, NoNewPrivileges=yes, ProtectSystem=strict,
ProtectHome=read-only, KillMode=control-group, and finite runtime at most
180 seconds (systemd's seconds/minutes rendering is accepted). Use a service
type for which RuntimeMaxSec is effective, not Type=oneshot. ReadWritePaths
must contain exactly `/home/ubuntu/.config/gcloud` and the private output
directory, with no parent-directory grant. Config writes allow actual token
refresh under ProtectHome. Keep admission/source/lineage bindings read-only.

Parent effective, permitted and bounding capability masks must contain exactly
`CAP_DAC_OVERRIDE CAP_KILL CAP_SETGID CAP_SETUID CAP_SYS_PTRACE` (`0x800e2`).
Use the same minimal set in the effective service configuration; bounding
alone is insufficient. The control also reads actual cgroup-v2 memory, swap,
task and CPU limits. NoNewPrivs must be 1 in actual parent/child `/proc`
status. The production pre-exec hook clears supplementary groups and drops
the SDK's real/effective/saved/fs UID and GID to 1000. The spawn witness reads
these actual identities, empty Groups, zero effective/permitted/ambient
capabilities, PGID=PID and stable kernel starttime, plus its actual cgroup.
A second witness rechecks identity before the unreaped leader is shut down;
its starttime/PGID must match the first. Zombie cgroup membership is not used
as a live-membership assertion.

Successful fixed metadata must validate the exact generation
`1629744948337785`, size `8894131881`, CRC32C `2aRcEQ==` and MD5
`cjxmnTAGSMNCZcYD91XjbQ==` through the production parser. The owned SDK group
is killed and its leader reaped before pipe collection finishes. Native
postconditions require waitpid ECHILD and group-probe ESRCH. A separate real
SDK spawn deliberately rejects its witness to prove the same owned-group
cleanup occurs before that witness error is returned. Tokens, SDK stderr and
credential files are never emitted; only fixed object metadata and private
kernel/build evidence enter the Root-private result.

A native result establishes this metadata/SDK profile control only. The
original acquisition's guard/disposition acceptance, complete consumer
readsets, final deployment seal, actual-sandbox rename, every recovery and
failed-transfer/floor/timeout/size/collision control, isolated same-engine
restore round trip, independently accepted lifecycle qualification and fresh
operational admissions remain required. No qualification flag or original
cache provenance rule is weakened by this test.

## Read-only staged-consumer discovery

`jetstreamer-snapshot92447542-census` captures the actual system/user unit
inputs, lexical aliases and raw parent-path scanner matches without exclusions.
It also records exact process-path and original-inode references without reading
the snapshot body. Every captured input and alias is rechecked; changed directory
enrollment rejects the capture. Source bytes are saved by SHA-256 under a private
`unit-inputs` directory for independent launcher/environment/template/plan review.
An empty literal scanner result does not establish a complete semantic readset.

Run only as the actual MainPID of a separately admitted Root `Type=exec` service
with 512 MiB memory, zero swap, CPU200%, Tasks128, RuntimeMaxSec180,
NoNewPrivileges, ProtectSystem=strict and ProtectHome=read-only. The sole explicit
writable path must be the Root0700 result directory. The binary accepts two
arguments: a Root-immutable admission JSON path and its independent SHA-256.
Admission fields are `schema` =
`jetstreamer-snapshot92447542-consumer-census-admission-v1`, `self_binary` (`Bound`
to the canonical Root-immutable binary), `issued_unix_seconds`,
`expires_unix_seconds` (positive validity at most180 seconds), `unit`, actual
`invocation_id`, actual `expected_exec_start`, and `output` (new `census.json`
inside that result directory). Gate useful work until the actual service identity
and admission are bound. Metadata capture requires DAC_OVERRIDE and SYS_PTRACE;
it never starts/stops another service, changes a guard, contacts cloud storage,
or authorizes cache check, eviction, restore or replay.

The finite roots include installed system/user units, local/vendor systemd
roots, runtime transient/control/attached units and generator roots. Actual
manager load paths must still be reconciled with that enrollment. Referenced
external scripts, environment files and sealed plans remain independent source
review inputs; the census explicitly records `interpretation_complete: false`.

## Exact condition-blocked consumer contract

The consumer review uses schema
`jetstreamer-snapshot92447542-finite-consumer-readset-review-v2` and an exact
compiled registry of18 reviewed units: the original acquisition, eight other-slot
downloaders, five importers and four namespace probes. A prefix match is not an
admission. Each canonical fragment, program path/hash and effective ExecStart argv
must equal its registered envelope. Importers retain the frozen image/main pins;
probes bind their script and actual canonical `/bin/sh` interpreter separately.

A canonical regular `fragment` remains a `Bound`. A manager-installed symlink is
bound separately by `installed_fragment`: `path`, exact absolute `raw_target`,
full `Identity`, and ordered `parents` (`path`, `DirectoryIdentity`) through `/`.
Every parent must remain canonical, Root-owned and protected from group/other
writes. The link and target are independently rechecked. Direct regular fragments
have no alias binding. Every effective drop-in, exact negative-condition guard
and existing immutable marker is still bound; condition resets and unknown
staged parent references still reject. Runtime guards under `/run` apply only
while present and require fresh qualification after reboot.

Each consumer additionally supplies `program`, optional probe `interpreter`,
`native_commands` and `declared_environment` bindings. The command evidence
contains `unit` and all seven actual D-Bus `raw_typed_properties`, with type
`a(sasbttttuii)`: one ExecStart tuple and empty other hooks. Omitted CLI arrays are
not synthesized. Declared environment evidence contains `unit` and
`property_digests` for Environment, EnvironmentFiles, PassEnvironment,
UnsetEnvironment, ExecSearchPath, WorkingDirectory, RootDirectory and RootImage;
each value records the actual D-Bus `type` and SHA-256 of its raw `--json=short`
response. These are current declared properties, not a historical interpreter
execution witness. The loaded typed Unit.Conditions must include the exact
non-trigger, negated marker condition.

Each per-unit source readset uses schema
`jetstreamer-snapshot92447542-source-readset-v2`, binds `unit`,
`fragment_sha256`, ordered `source_evidence`, `effective_argv`,
`expanded_inputs_reviewed: true`, and nonempty
`potential_program_readset_evidence` (immutable `Bound` source reviews).
`scope` is exactly
`potential-program-inputs-separate-from-condition-blocked-admitted-reads`.
`currently_admitted_compressed_cache_reads` is `[]` only under the authenticated
condition-blocked scope; `guard_sha256` and `guard_marker_sha256` bind that scope.
`historical_loader_execution_qualified` remains false. This represents potential
application/loader inputs explicitly and never claims a dormant program has no
possible I/O.

The independent foreground command
`BIN review-consumers ADMISSION ADMISSION_SHA SELF_SHA` runs the same private
consumer proof as production without constructing a production Plan. Its strict
Root-immutable admission uses schema
`jetstreamer-snapshot92447542-consumer-review-admission-v1`, positive validity
at most180 seconds (`issued_unix_seconds`, `expires_unix_seconds`), `self_binary`
and `consumer_review` bindings, actual `unit`/`invocation_id`/
`expected_exec_start`, and a new `consumer-review.json` output. Use the census
service's admitted512MiB/Swap0/CPU200%/Tasks128/Runtime180/strict/NNP profile and
only its private output directory writable. The actual MainPID must exec the
normal sealed helper. This command reads metadata and source/code evidence;
it does not read the snapshot body, contact cloud storage, mutate old units,
or qualify lifecycle, eviction, restoration or replay. Existing production
check/evict/restore admission and lifecycle gates remain required.

## Shared engine and recovery candidate

The normal helper's private `lifecycle_engine` now owns the complete check,
eviction, restoration, guard and durable recovery flows. Production wrappers
retain the fixed-generation Plan, history, consumer, metadata, digest, SDK and
restore-admission gates. The production factory cannot choose fixture data.
The engine holds one lifecycle lock for each operation.

`BIN ORIGINAL_PLAN --plan-sha256 ORIGINAL_PLAN_SHA --self-sha256 HELPER_SHA
restore-recover CHECK_SHA RECOVERY_ADMISSION RECOVERY_SHA` reconciles an old
attempt under a separate, fresh Root-immutable recovery capability. Keep the
original Plan byte-identical. Recovery authenticates its actual prior owner,
original PID1 terminal evidence, exact intent and optional stage inode, and the
current admitted MainPID/IID. It cannot download or launch replay. An intent-only
interruption or registered abandoned stage can be reconciled; nonempty
unregistered or substituted stages remain preserved. A matching published
payload can reconcile its receipt and clean a remaining registered stage only
under that fresh recovery authority. Stage cleanup accepts the exact documented
UID1000-to-Root custody freeze across an interruption, while rejecting changed
inodes, modes and reverse ownership transitions.

The opt-in feature `snapshot92447542-native-lifecycle-tests` also enables the
existing SDK native feature. It is excluded from ordinary tests and normal
production builds. Seven Root-only `lifecycle_engine::full_engine_fixtures`
tests run the full transactions with bounded fixture data, real owned UID1000
child transports, durable interruption models and transfer/collision faults.
They require a separate actual native admission and preserve their fixture roots
on success or failure. Their journals use a distinct fixture schema, omit cloud
generation claims and cannot count as real service-crash, measured-host-floor,
SDK-profile or full-generation qualification.

The separately selected native test is
`snapshot92447542_cache::native_engine::actual_fixed_generation_full_engine_roundtrip`.
It acquires the genuine fixed generation into an isolated cache, verifies all
payload digests, and calls shared check -> evict -> restore with the actual SDK.
It never reads or retires the original cache. A passing result establishes only
that isolated full-generation control. Final operational mount geometry and the
complete independently reviewed crash/recovery/failure matrix remain required.

Both native routes use `JETSTREAMER_SNAPSHOT92447542_ENGINE_ADMISSION` and its
independent `_SHA256` variable. The strict admission schema is
`jetstreamer-snapshot92447542-native-engine-admission-v1`. Fields are `route`
(`bounded-full-engine-fixture-models` or
`fixed-generation-isolated-full-engine-roundtrip`), `issued_unix_seconds`,
`expires_unix_seconds` (positive start window at most300 seconds), `test_binary`,
`engine_lineage`, `profile`, `fixture_root`, `fixture_identity`,
`maximum_fixture_bytes`, `output`, `protected_floor_bytes`, `fleet`,
`protected_owners`, `gcloud`, and `maximum_run_seconds`. Bounds use the existing
canonical Root-immutable `Bound` format; protected owners use actual `unit`,
`invocation_id`, `exec_start`. The fleet's sample must precede issuance by less
than1800 seconds; every live fleet owner and its current growth floor remain
protected. The isolated fixture root is an exact fresh UID/GID1000 mode0700
child named `qualification-snapshot92447542-native-engine-*` below the private
root. Output is a new Root-private `native-engine-result.json`. Fixture models
have a16MiB allocation bound; the real roundtrip reserves `2*SIZE+2*SLACK`.

The strict engine lineage schema
`jetstreamer-snapshot92447542-normal-engine-lineage-v1` binds `helper`,
`normal_build`, `harness_compile`, `full_source_manifest` and `source_evidence`.
Those five evidence members bind cache.rs, lifecycle_engine.rs, native_engine.rs,
the observe Cargo.toml and this README. Actual normal artifacts must have
features[]/profile.test=false/fatLTO/codegen1; the genuine compile-only harness
receipt must bind both native features, profile.test=true and the same complete
source manifest. No source or fixture flag substitutes for those receipts.

The actual Root Type=exec native profile uses512MiB, Swap0, CPU200%, CPUs56-63,
Tasks128, finite separately booked runtime at most7200 seconds, strict system,
read-only home, NNP and KillMode=control-group. Full flow needs CHOWN as well as
DAC_OVERRIDE/KILL/SETGID/SETUID/SYS_PTRACE: exact parent mask `0x800e3`. Only the
private fixture root, private result directory and original gcloud config are
explicitly writable. Quarantine the original cache and state with exact
`InaccessiblePaths`. SDK children still drop to UID/GID1000, empty groups and
zero effective/permitted/ambient capabilities. A fresh short admission books
entry; it does not extend the finite runtime or permit a restarted invocation.

These are source candidates until their real admitted completion receipts exist.
No lifecycle qualification or additional retirement is established by this code.

The normal helper also exposes `probe-mounts ADMISSION ADMISSION_SHA SELF_SHA`.
This separately admitted finite route tests only IID-named disposable sentinels
between the exact operational cache and state directories. It requires an actual
Root MainPID/IID, features[] normal build/source lineage, 512MiB/Swap0/CPU200%/
CPUs56–63/Tasks128/180s service, strict system and read-only home, and kernel
capabilities `0x800e3`. Its only explicit writable paths are the common private
parent, the original SDK configuration, and a private result directory under
`/var/lib/jetstreamer`. Every other immediate private-parent child must be enrolled
by identity and mounted read-only, including all descendant mounts; symlink or new
unbound siblings reject. This scope is independent of the read-only census route.

Admission schema `jetstreamer-snapshot92447542-operational-mount-admission-v1`
binds a <=180-second start window, `self_binary`, `normal_build`,
`full_source_manifest`, `profile`, `parent_identity`, `cache_identity`,
`state_identity`, `protected_siblings` (absolute path to directory-style
identity), `original_snapshot`, and `output`. The profile uses schema
`jetstreamer-snapshot92447542-operational-mount-profile-v1` and binds `unit`,
`invocation_id`, and the complete `expected_properties` map checked by the route.
All documents and the normal executable must be independently Root-sealed.
The source manifest binding must be the original binding used in the normal
build completion; an identical copy at another path does not replace it.

The probe authenticates descriptor mount IDs and mount options, the complete
sibling enrollment, and original snapshot/receipt identities before and after.
It takes the shared retirement lock (creating only that Root-owned bookkeeping
file if absent), fsyncs an intent before sentinel creation, requires real EEXIST
for a preserved destination collision, performs forward and reverse no-replace
rename with fsync and inode/content checks, and removes only its exact owned
sentinels. On failure, exact sentinel state and intent are retained for reviewed
disposition. Its result grants no check, eviction, restore, replay, or cloud
mutation authority and credits zero campaign bytes reclaimed. Source tests and
compilation do not qualify actual operational mount geometry; the route must
execute under its independently admitted final service geometry.

Actual service-exit controls live in the feature-gated native engine's
`process_crash` child module. The three selected tests are
`actual_prepare_warm_generation_session`, `actual_process_exit_or_native_case`,
and `admitted_native_transport_worker`; the last is only an owned UID1000 child,
not a standalone unbound test. These controls have no normal CLI route. Their
source and compilation alone confer no native lifecycle qualification.

Root invocations require separate
`JETSTREAMER_SNAPSHOT92447542_CRASH_ADMISSION` and
`JETSTREAMER_SNAPSHOT92447542_CRASH_ADMISSION_SHA256` environment bindings.
The strict `native-crash-invocation-v1` document uses an independently sealed
persistent Session plus a fresh existing EngineAdmission as `execution` with
route `persistent-native-session-invocation`. The full schema names retain the
`jetstreamer-snapshot92447542-` prefix. In addition to `action`, explicitly supply
all optional bindings as objects or null and the required `hold_seconds` (zero
without a hold), `actual_restore_runtime_seconds`, `attempt`, and
`measured_initial_test_floor_rejection` fields. See the Rust definitions for the
complete denied-unknown-field shapes.

The persistent Session hash owns the durable operation; the fresh admission
never replaces it. Real post-fsync phase witnesses precede process exit197.
Recovery independently authenticates both the immediately preceding process
and the original restore creator, their actual PID1 terminal/current closed
properties, and the fresh current native owner. New downloads choose a new
attempt suffix; recovery retains the original attempt. The warm seed is the
full verified 8.894GB fixed-generation output retained from the genuine SDK
roundtrip, with real production digest validation. Its local copy is labeled
as a verified warm generation, while the SDK-live death case must use real GCS.
Measured stricter test floors and faulty transport outputs remain distinct from
campaign-floor breaches and matching-generation success. All original cache
and state paths must be inaccessible to these isolated controls. Preserve the
original consumer guards and retire only exact closed native-test aliases
before fresh production consumer review. Completed isolated payload retirement
requires its own exact-scope proof; it never credits original campaign bytes.

The mount probe reads its complete profile with a separate2MiB bound; the shared
retention reader keeps its64KiB contract. Its mount scope follows mount-ID parent
ancestry below the actual common-parent descriptor. Older tmpfs mounts covered
by that parent bind remain recorded as covered lower mounts. Every visible
protected sibling also requires an O_PATH/no-follow descriptor whose mount ID
matches its exact read-only mask and whose inode/custody matches admission.
No file body is read through these sibling descriptors. Cyclic ancestry,
unbound masks, reachable writable submounts and all cache/state submounts reject.
