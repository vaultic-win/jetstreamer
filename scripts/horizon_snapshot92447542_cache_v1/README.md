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
