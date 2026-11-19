# Isolated native prestart controls for full epoch265

This tool qualifies the three-command PID1 gate used by horizon265-launch and horizon251-launch5 with a metadata marker as the useful-work payload. It never invokes a node, historical worker, native265 harness, snapshot initialization, production token path, archive operation or R2 client. A source packet is not native qualification: Main must build, publish, seal, execute and review actual evidence before setting `prestart_gate_tests_accepted`.

The existing full265 and251 launchers require exactly `sleep60`, `test -f TOKEN_ROOT/${INVOCATION_ID}/guard-admission.json`, then `test ! -L` on that path. Their loaded-unit policy also rejects EnvironmentFiles/PassEnvironment, differs from the complete sealed Environment set, and stripping INVOCATION_ID. Native265's internal token protocol is different and its already successful cold initialization must never be rerun for these controls. Source unit tests alone do not establish the native PID1 behavior.

## Inputs and publication

Build the new standalone crate with its lockfile and test/Clippy it under Main's existing guarded build allocation. No change to the already qualified horizon265-launch artifact is required. Retain actual compiler command, dependency closure, source manifest and exact helper SHA. Commit and publish all new files to account-updates and verify containment before runtime controls.

The `run PLAN PLAN_SHA SELF_SHA` plan is root-owned immutable JSON:

```
{
  "schema": "horizon265-native-prestart-controls-v1",
  "production_template": {"path": "EXACT_SEALED_FULL265_SERVICE", "sha256": "ACTUAL_SHA256"},
  "production_retention": {"path": "EXACT_SEALED_FULL265_RETENTION", "sha256": "ACTUAL_SHA256"},
  "source_publication": {"path": "EXACT_SEALED_SOURCE_PROOF", "sha256": "ACTUAL_SHA256"},
  "sleep": {"path": "/usr/bin/sleep", "sha256": "ACTUAL_SHA256"},
  "test": {"path": "/usr/bin/test", "sha256": "ACTUAL_SHA256"},
  "maximum_wall_seconds": 360,
  "maximum_metadata_bytes": 16777216
}
```

The source proof schema is `horizon265-native-prestart-source-publication-v1`, with Main_accepted=true, remote_ref=refs/heads/account-updates, source_commit, remote_head, fetched_unix_seconds (<=1800s), helper_sha256, source_manifest_reviewed=true, source_files array of repository_path/sha256, and build_provenance binding. Required source manifest paths are this crate's main.rs/Cargo.toml/Cargo.lock. The helper checks fetched ref, ancestry and every committed blob digest. Build provenance schema `horizon265-native-prestart-build-provenance-v1` binds the same source_commit/source_files, artifact_sha256, unresolved_dependencies=[], and actual_build_command_verified=true. Those review flags require actual retained compiler evidence.

## Exact native control execution

1. Before opening any full265 launch/admission clock, reserve one root metadata controller (MemoryMax128MiB, swap0, TasksMax64, CPUQuota100%, RuntimeMaxSec360) and at most one64MiB marker service. Reserve16MiB metadata. The controller's command is the exact sealed helper `run` command above. These controls do not count as replay lanes.
2. Run the built helper `emit-source NEW_SOURCE_DIRECTORY` to generate three exact units without installing them. Seal the helper and all three files with the normal Rust deployment sealer into `/var/lib/jetstreamer/horizon265-prestart-control-package-v3`. Never hand-assemble a runtime package. The helper path is fixed at that package's `horizon-prestart-controls`.
3. Seal the immutable plan/publication/provenance under a fresh separate root-owned package. Do not pre-create `/var/lib/jetstreamer/horizon265-prestart-control-state-v2`: the controller owns its no-clobber creation. All three control unit names must be absent before execution.
4. Invoke the controller as root through the reviewed metadata service. Required writes are only `/run/systemd/system` for the three fixed links and `/var/lib/jetstreamer/horizon265-prestart-control-state-v2`. It needs the normal root systemctl bus, read-only published checkout for Git, read-only `/proc`, `/sys/fs/cgroup`, and journal access. Minimal capabilities are DAC_OVERRIDE and CHOWN for private state/proofs and the ubuntu marker directory. No production working tree or token directory is writable. Controller PrivateNetwork=yes is compatible with local systemd/Git operations; Git performs no fetch. Main owns any source fetch before launch.
5. The controller verifies actual `/usr/bin/sleep` and `/usr/bin/test` hashes, production gate/retention source, exact control templates and effective native properties. It installs only `horizon265-prestart-control-v2.service`, `horizon265-prestart-override-v2.service`, and `horizon265-prestart-control-retention-v2.target` via no-clobber links; daemon-reloads; and starts only the retention target first.
6. Actual retention before/after must be byte-equivalent manager maps with producer inactive, MainPID0, no IID. Target must contain only the approved nonactivating After dependency and no Wants/Requires/BindsTo/Upholds. The override service is loaded with `Environment=INVOCATION_ID=111…111`, then rejected by the same native environment policy before it can be started. This is an explicit *preactivation policy* rejection, not a claim that PID1 itself rejects arbitrary environment directives.
7. Four sequential invocations of the same harmless marker service exercise the60s gate. Missing token fails at `test -f`; matching token is installed only after observing the new actual PID1 IID and start-pre ControlPID, and produces one IID/PID-bound marker; the next invocation gets no token and rejects the retained old token; the symlink case gets a leaf symlink to that old token, passes `-f`, and fails at `! -L`. Every failed control must have no marker, unchanged ExecMainPID from its waiting snapshot (PID1 may retain prior command history), and the precise failing ExecStartPre command/status. Every terminal invocation has zero restarts, no jobs/control processes, empty/absent cgroup, and retained actual PID1 journal. Positive marker PID must equal native ExecMainPID.
8. A final receipt is written only if all controls pass, all native IIDs are distinct, exactly one useful marker exists and the two system gate executables/self image still hash identically. Native resources and links remain retained for reviewed cleanup. On any failure it stops advancing and leaves all evidence and the bounded harmless control intact; there is no automatic retry or cleanup.

Expected elapsed time is approximately240s plus setup. Individual unit TimeoutStartSec90 and marker RuntimeMaxSec10 preserve the60s gate and keep the controls bounded. The controller's360s deadline must not be confused with the full265 launcher's50s actual-first-guard operator window.

## Evidence and acceptance

The state directory contains retention.json; environment-rejection.json; missing/matching/stale/symlink waiting+terminal JSON and PID1 JSONL; isolated control tokens; the single useful marker; qualification.json. Root metadata files are0600; marker leaf is ubuntu0700 with0600 marker; token paths are root-owned and non-writable to ubuntu. The matching control token says metadata_only and production_authority=false and is in a disjoint namespace.

Main must bind the entire directory census/digests, exact tool/package/source/build/native systemd version, and plan into an immutable accepted qualification_evidence package. The result schema is `horizon265-native-prestart-control-qualification-v1`. It sets actual_candidate_startup_qualified=false, actual_first_guard_required_before_useful_work=true and native265_initialization_repeated=false. It does not replace the full265 observer/fleet/status/terminal-delivery acceptance or actual current-fleet admission. Main may combine these actual controls with those already qualified consumer proofs into the existing `horizon265-prestart-qualification-v1` review. Keep the launcher artifact hash bound to the already published actual horizon265-launch executable; this tool's digest is separate.

Tests in this packet are authored but not run by the source agent. Rustfmt parsed/formatted the source. Native controls remain unexecuted until Main explicitly performs the operational step under the campaign's existing authorization.

Native attempt v1 stopped before state creation: this host uses root-owned `/usr/bin/{sleep,test}` symlinks to 116 hard links of its 11.8 MB packaged coreutils binary. V2 pins those exact two resolutions, root custody and unchanged full-file digests before and after controls. The ordinary immutable evidence reader is unchanged. The original failed invocation and v1 package are retained.

Native attempt v2 preserved the installed but unstarted original controls and failed while reading PID1: each ExecStartPre array element is emitted on its own line. V3 preserves their complete ordered array while rejecting duplicate scalar properties, and uses fresh control/state names.
