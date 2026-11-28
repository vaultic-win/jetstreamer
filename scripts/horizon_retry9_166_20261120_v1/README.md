# Epoch 166 retry9 preparation and guard

The preparer accepts `epoch=166`, `attempt=local3retry9`, zero native replay/bootstrap peers and an empty owner list. The producer starts at the original bootstrap. The predecessor and candidate share the original 309,237,645,312-byte physical cap. The preparer rechecks the inherited full-lane physical ledger and rejects proposed growth over its remaining headroom. An offload forecast grants zero local credit.

The HOME-backed package root is `/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry9-recovery-20261120-v1`. Build the `guard` Cargo package under its default features and the `prepare` Cargo package with `--features preparation`, using their respective locked manifests. The hard-coded normal deployment paths below are relative to this package root.

| Artifact | Path |
| --- | --- |
| Native guard | `guard-v1/guard` |
| Preparer | `prepare-v1/prepare` |
| Preparation receipt | `preparation/epoch166/local3retry9/prepared.json` |
| Guard state emitted by the preparer | `preparation/epoch166/local3retry9/guard-state` |

Set the new plan field `retry9_precreated_roots` to the bound absolute path and digest in `prepare/retry9.rs`. This is the actual November 20 three-root receipt. Its capture time must precede the genuine new guard witness. Keep the closed producer, guard service and timer for each of the five exact stopped generations listed there in the plan. The historical retry2/4/5/6 lineage, retired artifacts, original native DATA gates and 167 retained allowance remain in the inherited preparation. The new artifact proof schema is `horizon-epoch166-retry9-original-slot-guard-artifact-proof-v1`.

The shared `audit_budget.rs` checks the current HOME audit v9 service, image, config, invocation, memory and CPU and calculates the exact remaining audit DATA demand during a download or playback. The before/after sample binds the same epoch and archive inode. Advancing downloads receive at most the lower confirmed resident allocation and first reported byte count. Rollover or regression requires a fresh sample. Preparation records the independent audit capacity check as `resource_checks.audit_home_DATA` and its validated concurrent replay fit as `resource_checks.audit_fit`. A launcher can include this same module, call `observe()`, `requirements()` and `data_requirements(&prepared["resource_checks"]["audit_fit"], available)` immediately before launch, and keep the original fleet obligations and guard floor.

Source dependencies include the checked-in retry8 preparer and guard modules specified through Rust path attributes, their fixture files, and both package lockfiles. Build and test evidence, native witness qualification, physical capacity after any actual retirement, Git publication, deployment seals and the launcher's live rechecks are required separately.
