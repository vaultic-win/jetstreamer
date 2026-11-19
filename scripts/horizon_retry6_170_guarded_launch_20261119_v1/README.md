# Epoch 170 retry 6 admission with home-backed R2 audit v8

This source successor admits epoch 170 only alongside the actual home-backed
audit v8: PID `2227285`, invocation `99c7ddc48af140efb131b784a6b064d2`, exact
runtime/config/seal and migration `START_EVENT.json`. The audit keeps 24 GiB
memory, four CPUs and 512 tasks. Its paths must actually reside on the
`/home/sol` filesystem. Source preparation is not build qualification, admission
or launch authority.

`src/audit_budget.rs` is shared by this launcher, the retry8 preparer and
`stage170retry8`. Include that file in all three source/build closures. The
preparer's normal seal must include it as `source-audit_budget.rs`; the launcher
requires the preparer's copy to equal its own compiled source. Staging verifies
its compiled main, Cargo manifest/lock and shared module against clean committed
files contained in `origin/account-updates` before any staging operation.

The observer must emit the envelope returned by
`audit_budget::fleet_obligation()` under `continuing_audit_obligation`.
`DATA_reservation_bytes` must be absent. The former zero-DATA/root-only envelope
is rejected. No observer is changed by this source package.

Admission requires stable `playing_entire_epoch` progress, a complete resident
archive of the exact reported length and unchanged owner. Metadata-only
allocation scans calculate remaining archive growth plus the unused part of
the 16 GiB working cap and a 2 GiB Cargo growth allowance. The
385,290,386,716-byte archive acceptance ceiling is not reserved for every small
epoch. Concurrent changes cause a failed check that must be retried against a
new stable sample; admission never pauses or restarts the audit.

The required free DATA is:

```text
audit_growth = remaining_exact_archive + remaining_working_cap + 2 GiB
continuity = 6,796,908,511,026 + complete_concurrent_remaining_growth
             + fresh_subtree_overlap + unrelated_growth_margin
             + additional_growth_not_covered_by_existing_promise
required = max(historical_required_raw_available, continuity) + audit_growth
```

Both historical fit and audit continuity must hold. This preserves stopped166's
309,237,645,312-byte obligation, epoch170's 288 GiB whole-lane cap, current peer
identity requirements, DATA fulfillment and normal guard gates. Audit memory
and CPU are added once to historical resource requirements; any actual running
holding transfer is additionally charged by the launcher. The exact DATA and
memory checks run again immediately before launch, and the admission binds
`FINAL_PRELAUNCH_HOME_CAPACITY.json` by path and digest.

## Qualification and deployment order

1. Publish the complete required source closure to `account-updates`, fetch and
   verify remote containment. Keep the source files used for each build exact.
   Builds, tests and runtime transitions remain the parent controller's work.
2. Build/test/lint the preparer manifest
   `scripts/horizon_retry6_170_20261118_v1/prepare-live166retry8-v1/Cargo.toml`
   with `--locked --features preparation --bin prepare` in an admitted build
   allocation. Run the full existing qualification suite plus the shared
   module's tests; use the actual passing count in the proof. Preserve production
   rustc/features/dependency provenance and all applicable strict checks.
3. Create the normally sealed preparer successor at
   `/var/lib/jetstreamer/horizon_runtime_data/epoch170-home-audit-v8-20261119-v1/prepare-v3`.
   Include `prepare`, `artifact-proof.json`, every preparer source member and
   `source-audit_budget.rs`. The proof retains schema
   `horizon-live166retry8-preparer-build-proof-v1`, source containment, production
   SHA, exact source members, features `["preparation"]`, zero failed tests and
   production Clippy success. Do not manufacture qualification results.
4. Build/test/lint this launcher using four mandatory compile inputs:
   `HORIZON_170_PREPARER_V3_SHA256`,
   `HORIZON_170_PREPARER_V3_PROOF_SHA256`,
   `HORIZON_170_PREPARER_V3_SOURCE_COMMIT`, and
   `HORIZON_170_PREPARER_V3_TESTS_PASSED`. The full launcher suite includes a
   provenance test that reads the exact sealed preparer and retained guard, so
   use the intended privileged reader after step 3. Seal the qualified launcher
   at the same successor root under `launch-v5/launch`.
5. Build/test/lint `--bin stage170retry8` from
   `scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml` with the
   preparer SHA/proof inputs above plus
   `HORIZON_170_RETRY8_LAUNCH_V5_SHA256`. Seal it as a new immutable deployment
   with the shared source closure. Other stage package binaries have independent
   build pins; do not substitute their qualification for this binary's.
6. Qualify the observer successor with the new fleet obligation. Use the fresh
   genuine fleet/status/observer, current peer166/167 admissions/protections and
   exact bindings to run the existing witness, measure and preparation flow.
   The native preparer performs the home audit capacity check too.
7. Generate the launch plan, run the sealed launcher with `--check-only`, then
   `--launch`, each with exact plan/self SHA arguments. Require the actual
   producer and first PID1 timer-driven guard evidence. Preserve existing
   rollback, source publication and closed-owner gates throughout.

No hashes, test results or new launch evidence are supplied as defaults.
