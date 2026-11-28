# Standard166 restart and scratch retirement: source-only handoff

No operations, builds/tests, live observations, resource sampling, deletion or qualification were performed. Existing retained plans/receipts and Git source objects were read. Root owns all admissions, terminal capture and relaunch.

## Result

The standard166 invocation restarts replay from its manifest-bound predecessor snapshot. Its retained `cohort-state.json` has no slot/entry/transaction/writer cursor. Reusing a cohort run directory is not continuation from the stopped replay position. No inspected existing retirement profile accepts this exact standard-lane layout and standalone guard evidence; a narrowly scoped standard166 adapter is needed.

## Exact immutable lineage and retained evidence

- Original command: `/home/sol/.jetstreamer-private/epoch166-independent-singleton-20261109-v1/ACTUAL166_ORIGINAL_PRODUCER_ARGV.json`. It runs `horizon-qualify-166-standard-20261109-v1.service`, original invocation `06c7b420f92d42a6b0743ba578bcd8b6`, with `JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true`, snapshot verification enabled, directory loading disabled, and no cohort-resume environment variable or snapshot override.
- Exact package: `/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/`. Its normal seal is `deployment-seal-receipt.json`; original seal inputs are `/home/sol/.jetstreamer-private/epoch166-independent-singleton-20261109-v1/PACKAGE_SEAL_PLAN.json`.
- `jetstreamer-node` SHA-256: `a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65`; v1.5.6 worker SHA-256: `cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819`. Both were copied unchanged from `/usr/local/lib/jetstreamer/deploy-epochs159-173-publication-boundary-20261012-v1/`.
- Source lineage receipt: `/var/lib/jetstreamer-epochs159-173-boundary-capability-20261012-v1/capability-receipt-v1.json`, `.source.commit = e6f48efe2749d35d6875fdd3cbd7f6f4379adf75`. Read source at that commit, not today's mutable checkout. This review does not independently reproduce the images or promote that receipt into an exact build/source-image proof.
- Sealed singleton manifest: `preflight-166-v4.json` in the exact package; file SHA-256 `c632ae8d95748f563d8c47db587afa9139b165298004c3fa6820332c4d89b6b4`; semantic fingerprint `sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b`.
- Bootstrap: `gs://mainnet-beta-ledger-us-ny5/71711708/snapshot-71711708-73JLv83cyRgHUNxtajhwXimfDSH4GUmu6R8LHKPbxu76.tar.zst#1634787359098769`, length 1,968,014,870, MD5 `Q7nDEwnnM5lZd1QZw4X7Rg==`, CRC32C `q+wuJQ==`. Historical generation probe: `/home/sol/.jetstreamer-private/epoch166-independent-singleton-20261109-v1/ROOT_FRESH166_LANE_CONFIG_AND_GENERATION_PROBE.json`. This is prior evidence, not a fresh credential/remote check.
- Required final root: slot72143703, accounts hash `CJEQdfn6zGqx4da6wL7CqgDhNAEij9tCPz7CrY9ZWH1a`, snapshot generation1634787403577062. Preserve all canonical-root/publication gates.

Run directory:

`/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/private/destination-dd3947fd4ee7fdd82612b5977aea040658746bdd51eab3e2bc25858329734ef8/work/root-cohort-166-166/run-4188448-1794243111198290622`

Its `cohort-state.json` is exactly schema/start_epoch/end_epoch/manifest_fingerprint/status, with status `running-private`. Preserve `archives/epoch-166.jet`, `inputs/`, state and diagnostic evidence; the proposed deletion scope is only contents of `scratch/`.

Actual standalone stop evidence is under `/home/sol/.jetstreamer-private/epoch166-independent-singleton-20261109-v1/duplicate722-correction-current-guard-handoff-20261110-v1/receipts/`:

- `stop-intent.json`, SHA `a5a8a7491f185d6c77531ab970c0c76aec54de0c96f1b4a1c0a80905125dd147`, schema `jetstreamer-horizon-standalone-stop-intent-v1`.
- `stop-completion.json`, SHA `feb72802f57e992c398c2ad500db8ee6f5489ce46e9b58165da9d08967924b24`, schema `jetstreamer-horizon-standalone-stop-completion-v1`.
- Their plan SHA is `71cbb6783e2cfffb6e4601644ebbdb59a6bed4520c25ac3e59a1c7fa17b41f57`, naming `/usr/local/lib/jetstreamer/horizon-standard166-duplicate722-correction-guard-plan-20261110-v1/guard-plan.json`.

Root's retained stop journal is `/var/lib/jetstreamer/seven-standard-reserve-stop-20261110-v1/epoch-166-original-stop-journal.json`; the event rows and exact bindings are in adjacent `ORIGINAL_SEVEN_RESERVE_STOPS_AND_REPAIR_MODEL.json`. Those records also account for a collected/not-found original unit; future code must not require the vanished transient fragment or mistake unit absence alone for original terminal proof.

## Why scratch is not an admitted continuation cursor

At commit `e6f48efe...`, `jetstreamer-node/src/main.rs:14774` defines only the five fields above; `14860` resumes directory ownership and manifest binding; `17959` selects its scratch; `18227` explicitly clears dirty mutable accounts state; `18268` reloads the original manifest bootstrap; `13801` preserves old private output before replay rather than appending at a serialized writer cursor. The original argv requests a new run, so an ordinary re-execution creates a different run directory. Setting `JETSTREAMER_ROOT_COHORT_RESUME_RUN` can reuse retained input/run scaffolding, while replay still restarts from the bootstrap.

The exact v1.5.6 worker source (`historical-runtime/v1_5_6/worker/src/runtime.rs:81`) initializes from `InitialState::SnapshotArchive`. Its worker **does implement** `ExportSnapshot` (`worker/src/main.rs:125`); that capability is not evidence that this stopped invocation exported a complete mid-replay continuation set or durable output cursor. Preserve any discovered export/continuation evidence and stop retirement if it changes this dependency classification.

## Smallest safe profile and next executable gates

`jetstreamer-r2/src/reserve_scratch.rs` is incompatible: it requires the seven-component `epochN-singleton-*/lane-a/private/...` layout, a same-package independent-singleton preparation/build bundle, and `reserve_stop::Evidence`. `reserve_stop.rs:120` requires distinct controller/producer units and adaptive-stop schemas. Standard166 has six path components after the private root and one standalone unit. Epoch185 contents-only and stopped203 profiles also bind other exact cases; do not loosen them globally or fabricate matching receipts.

Prepare a separate exact standard166 contents-only adapter using the descriptor-relative ledger/removal primitive in `jetstreamer-horizon-observe/src/stopped203_tree.rs`, with atomic no-clobber receipts as in `stopped203_retire.rs:120`. Keep the scratch directory inode and every parent/run/inputs/archive byte. Bind the exact unit/invocation, original standalone guard plan and both stop receipts, original argv/package/seal/manifest/source review, retained artifact closure and fresh complete fleet. Authenticate the solo-owner terminal chain and exclude active/staged/indirect readers; allow only the exact reviewed lifecycle definitions. Reject nested mounts, symlinks, external hardlinks, new/changed entries and replacement roots. Internal hardlink shape must be established by a bounded check before deciding whether the existing nlink==1 primitive suffices.

Next sequence: source adapter and immutable plan → isolated positive/negative/interrupted/repeated lifecycle qualification → normal Rust seal and source-image binding → Root-funded exact native check producing a reviewable ledger → separately admitted execution with fresh gates → durable completion and actual reclamation evidence → separate accounting release and fresh replay admission. Capture source/retained evidence outside the deletion tree first. No existing source packet or historical stop receipt alone authorizes that execution or a restart.
