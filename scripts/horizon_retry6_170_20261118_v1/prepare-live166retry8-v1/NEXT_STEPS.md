# Epoch170 next executable prerequisite

This candidate derives from `prepare-live166retry7-v1`.
`PREDECESSOR_SOURCE.json` records the original source hashes. On Nov19, its
bounded release test build and production build succeeded. The exact test image
`prepare-40bd154e8d0f598f` passed all305 tests as root with no failures or ignored
tests in `horizon-retry6-170-live166retry8-tests-20261119-v1.service`, invocation
`a375730441e543f5a277646c7f8e6d9d`. Production build invocation
`5133847292e34ec79a3e37cddac34c16` also completed successfully. Both used2CPU,
2GiB memory, no swap, and the existing target. No replay admission is claimed.

Strict Clippy found two identical floor branches in the initial candidate. Their
conditions are now combined without changing the selected floor. Final v2
qualification passed: Clippy invocation `c03f99c86a464dbd85cf1f3daad07ecb`, all
305 tests in invocation `6d2399398cdb4808a8fb70be7e07c563`, and production build
invocation `d42f6283217c45f1877bb4a7a83780d3`. The v2 test-build invocation is
`c8f1c8d8da8447f7a6a9975a1fd95d52`. The corresponding unit names use the same
`horizon-retry6-170-live166retry8-` prefix and `-20261119-v2.service` suffix.
Use these v2 executions for final artifact provenance; retain the initial
successful checks and failed Clippy invocation as history.

The preparer now binds actual166 retry8 admission/protection and PID/start ticks,
requires future167 **retry7** admission/protection, and accepts both current peer
preparation generations through the complete resident/preparation adapters. The
actual166 guard floor is the full6829053656882, rather than the former6584106303282.
Retired167retry6 is rejected for the170 current-peer route. Existing parser tests
remain; new tests cover actual166 receipts and cross-epoch route rejection.

The completed test-build command was:

```
cargo test --manifest-path scripts/horizon_retry6_170_20261118_v1/prepare-live166retry8-v1/Cargo.toml --features preparation --bin prepare --release --offline --jobs 2 --target-dir scripts/horizon_retry8_166_20261119_v1/guard/target --no-run
```

The copied Cargo.lock package name is corrected; all qualification commands used
`--locked`. Dependencies and features are unchanged. The next steps are source
publication, exact artifact provenance and normal runtime sealing, followed by
the genuine167 prerequisite below. Keep builds sequential in the recorded
2CPU,2GiB,swap0,jobs2 envelope and existing target.

New immutable preparer destination:
`/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-prepare-20261119-v1/prepare`.
The selected170 guard route, whole-root288GiB cap, and guard floor are unchanged,
so the existing170 guard image/proof path is deliberately retained. Prove its
source/dependency/feature equivalence before reuse; capture a fresh own-image
witness and normal contract seal at:
`/usr/local/lib/jetstreamer/horizon-epoch170-retry6-live166retry8-data-contract-20261119-v1/contract.json`.
Do not create another replacement root or alter live DATA witness ancestors.

Operational prerequisite remains genuine protected167retry7 execution. No future
IID/PID, admission or guard receipt has been invented; the runtime reads bound
actual receipts, and rejects absent, mismatched or stopped predecessor evidence.
Use the booking from that actual167 preparation (attempt local3retry7, preserved
512GiB cap, completeDATA6794761027378). Keep166's extra288GiB promise and170's
288GiB whole-root cap. No resource credit or promise release is added here.

The final170 launcher must separately revalidate and add audit24GiB/4CPU/DATA0
and, while still active,169holding2GiB/2CPU. This candidate does not end either
allocation or claim these extra allocations already fit. Parent must qualify the
holding completion/retirement before counting any reclaimed storage, capture
fresh simultaneous fleet capacity, and preserve parked-data restore obligations.

Publish all required source to origin/account-updates, verify exact containment,
seal and prove production provenance, then complete fresh measurement/preparation
and the launcher's actual native positive/preflight gates. Source qualification
alone does not authorize admission or resolve a lane shortfall.
