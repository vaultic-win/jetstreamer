# Epoch 170 retry7 with the independently admitted epoch 166

This route uses the existing, precreated standard epoch170 retry7 directory. It accepts the actual independent epoch166 invocation and, if already admitted, epoch167 retry8. It authenticates both receipts and the live timer and PID for each. A partial epoch167 admission or a different producer makes it fail closed. The terminal retry7 epoch167 evidence and its 512 GiB reservation are retained in either case.

The common allocation scan still measures the four historical standard roots. The additional independent166 root is charged at its full 309,237,645,312-byte cap with zero realized credit. The formulas include the live v10 audit handoff, its current exact archive and working allocation, the concurrent auxiliary phase peak and the holding obligation. The preparer measures the resident memory of all current peers. The launcher repeats the live capacity check immediately before starting and after the first guard sample. These checks require fresh runtime evidence.

## Build and seal order

1. Publish the source on `account-updates` and use the already booked build slot. Qualify `join170` and the `prepare` package (feature `preparation`). The preparer needs no future artifact hashes. Check the byte sizes and SHA-256s in `prepare/SOURCE_CLOSURE.json` against the published files. Run native tests, production Clippy and the release build. Seal at `epoch170-retry7-recovery-20261120-v1/one-peer-prepare-v2` with the source files and the actual artifact proof.
2. The proof's schema is `horizon-170-joined-preparer-build-proof-v1`. Record epoch 170, attempt `local3retry7`, `production.sha256`, `equivalent_build_source_commit`, `source_contained_in_origin_account_updates`, actual `tests_passed` and `tests_failed`, `production_clippy_passed`, and `features: ["preparation"]`. In manifest order, record each `source_members` entry with absolute `path`, `sha256`, `bytes` and `sealed_name` equal to `source-NNN-BASENAME` (zero-based, three decimal digits). Seal the executable as `prepare` (0555), the proof as `artifact-proof.json` and sources as 0444. The previously qualified retry7 guard remains required.
3. Qualify and seal `launch` using the actual `HORIZON170_JOIN_PREPARE_SHA`, `HORIZON170_JOIN_PREPARE_PROOF_SHA`, `HORIZON170_JOIN_SOURCE_COMMIT` and `HORIZON170_JOIN_NATIVE_TEST_COUNT` (the exact number passing in step 1). Its sealed location ends in `one-peer-launch-v2/launch`. Qualify and seal `stage` using the same preparer/proof digests and the resulting `HORIZON170_JOIN_LAUNCH_SHA`.

## Root operation sequence

Use the latest coordinated fleet. The 04:15 UTC single-producer fleet is valid only until 04:45 and only for that topology. A new epoch167 admission needs a coordinated fleet containing both producers. `join170 stage-config` prints JSON to stdout. Persist each configuration in a new root-controlled HOME-backed file and bind the actual SHA-256 on each stage invocation. The helper reads receipts and never starts a worker.

| Operation | Configuration inputs after `join170 stage-config FLEET FLEET_SHA` | Stage arguments after `CONFIG --plan-sha256 CONFIG_SHA --self-sha256 STAGE_SHA` |
| --- | --- | --- |
| First guard witness | `witness GENERATION_A` | `witness` |
| Physical measurement | `measure GENERATION_A` | `measure TAG_A` |
| Fresh guard witness | `witness GENERATION_B` | `witness` |
| Prepare | `prepare GENERATION_B MEASUREMENT MEASUREMENT_SHA` | `prepare TAG_B` |
| Bind completed preparation | `launch-plan GENERATION_B` | `launch-plan` |

Use unique witness generations and unique four-digit stage tags. Execute the exact `native_preparer_argv` emitted after measure and prepare. Use the actual native measurement output for the prepare config. The prepare stage requires the same fleet and observer as the measurement, a measured fleet at most 180 seconds old and a second qualified witness at most 120 seconds old. The launcher enforces the prepared genesis, final admission and genuine first guard. A plan or successful source qualification alone does not represent a running epoch.
