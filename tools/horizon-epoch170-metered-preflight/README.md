# Full metered epoch 170 preflight source

The Rust preflight uses the verified full-root input receipt and the independent diagnostic readback receipt. It preserves the retry-13 failure and guard-drain references. The candidate uses node `a09b8e5a` and the corrected metered worker `b0219574` through a distinct read-only worker alias. The bootstrap, canonical root, and retained index projections are carried over from the admitted singleton manifest; the output and log use a new private generation.

`guard-route.patch` adds an exclusive native guard route for `horizon-qualify-170-full-metered-20261124-v1.service`. It preserves the retry-13 route and binds the new route to the legacy 384 GiB lane root, the original minimum floor, the VMA ceiling, a distinct receipt directory, and the new root inode through the native witness. The root receipt must use schema `horizon-epoch170-metered-successor-root-v1` and bind the exact `root`, `device`, `inode`, and `retained_retry13_terminal_sha256`.

`inputs` derives the proposed worker and native process arguments, guard route, and observer position from immutable input receipts and a complete fleet receipt. The output field `producer_argv_after_protection` is the eventual post-permit producer specification. The actual service requires an invocation-bound held entry and release after the genuine first native guard and post-guard fit.

`cadence` checks the installed observer registration and package member, live service invocation and PID/start ticks, exact program arguments, and exclusive lock inode. `preflight` requires the candidate guard's build, seal, native rooted witness, static plan, and actual negative control against retry 13. It also requires a candidate observer enrollment and a fresh native prestart capacity quote bound to the exact candidate, current fleet, guard qualification, source profile, and observer enrollment. The executable rechecks the live cadence actor, peer invocation IDs, and the expected coordinated timer. All reports carry zero resource credit and no launch authority.

```text
horizon-epoch170-metered-preflight inputs OFFLINE DIAGNOSTIC FLEET FLEET_SHA
horizon-epoch170-metered-preflight cadence ACTIVE ACTIVE_SHA
horizon-epoch170-metered-preflight enroll OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA ACTIVE ACTIVE_SHA
horizon-epoch170-metered-preflight quote OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA ENROLLMENT_SHA PROVIDER_KIND PROVIDER_SEAL_SHA
horizon-epoch170-metered-preflight preflight OFFLINE DIAGNOSTIC FLEET FLEET_SHA GUARD_SHA OBSERVER_SHA PRICE PRICE_SHA
horizon-epoch170-metered-preflight hold PAYLOAD_SHA
```

The held producer reads the sealed source profile at `/run/horizon-epoch170-full-metered/payload.json`. It checks the native service identity, resource limits, and read-only input projections before waiting. The operator must bind the live guard and its post-guard capacity quote before publishing the invocation ID at `/run/horizon-epoch170-full-metered/barrier/allow`. Both inputs are read-only to the held producer.

After native preflight, seal the exact reviewed profile as `payload-<fleet-sha256>/payload.json` under the epoch 170 runtime directory. Run `python3 -IB held-argv.py REVIEW REVIEW_SHA PAYLOAD_SEAL_SHA` as root to print the held service's argument array. It checks the payload against the native review and retains the pinned held executable and read-only permit directory. The command only prepares the argument array.

Use `python3 -IB guard-argv.py start-intent REVIEW REVIEW_SHA` to prepare `START_INTENT.json` before starting the held service. Once PID 1 reports the held producer, `guard-argv.py plan` supplies `ACTUAL_GUARD_PLAN.json` for its invocation. Seal each record before using the next command. `guard-argv.py arm-argv` validates the plan with the sealed guard and prints the protective timer's command. After the timer has completed a successful guard sample, use `guard-argv.py first-guard SAMPLE` for `FIRST_GUARD.json`. The post-guard capacity provider rechecks those records before any permit is written.

Once the native post-guard provider returns a positive quote, seal it as `POST_GUARD_CAPACITY.json`. Use `guard-argv.py release-record` for `AUTHORIZED_GATED_PAYLOAD.json`. After sealing that record, `guard-argv.py permit` rechecks the hold and writes the exact invocation ID to stdout. Publish those bytes atomically as a root-owned `0444` file at the host barrier's `allow` path. The released process keeps its PID and invocation ID.

After the node replaces the held process, use `guard-argv.py admission` for `ACTUAL_ADMISSION_AND_PROTECTION.json`. Then pass the first successful guard sample that includes the historical worker to `guard-argv.py worker SAMPLE` and seal the result as `FIRST_PROTECTED_WORKER.json`. The existing fleet observer reads these paths, adopts the worker, and records its first measured replay progress.

The first pending native qualification is the new invocation route and `GUARD_QUALIFIED.json`. Publish the source changes on `account-updates`, stage the distinct HOME-backed root and its receipt, and build, seal, and qualify the route-specific guard using its installed image and native witness. The next preflight inputs are the enrolled candidate observer and the exact native fit quote. Use a fresh fleet receipt for this transition. The candidate provider and held release transaction still need integration with the current controller before a worker start.

The `full170-v9` quote selects `tools-homefloor-170-full-metered-v3` and authenticates V9's clean terminal, the separate startup submission and recovery receipts, and the exact V12 writer. Use `full170-v9-v13` with `tools-homefloor-170-full-metered-v5` after the registered V13 writer takes the incumbent lock and timer. These two routes cover the retained stopped epoch 168 retry4 roster.

For a coordinated fleet with a protected epoch 168 retry5 worker, use `full170-v9-v13-retry5` with the separately sealed `tools-homefloor-170-full-metered-v6` provider. Enroll against the same V13 ACTIVE receipt and use the V6 provider for the post-guard quote. Its price retains the stopped retry4 obligation and charges retry5 growth in both epoch 170 projections, including the projection after epoch 170 uses its whole-tree allowance. For the release, use the guard helper from the operator deployment qualified with that provider. It rechecks retry5's producer, guard timer and sample before issuing the permit.

After the exact V10 epoch 145 verifier drains and its semantic completion is authenticated, use `full170-v10-v13-retry5` with `tools-homefloor-170-full-metered-v7` for the protected retry5 fleet. Use that same sealed provider again at post-guard pricing. The V10 provider keeps the V13 receiver and retry5 protections.

The offline build passed Clippy with warnings denied and three focused tests. The guard suite compiled for `incident-recovery,epoch170-full-metered`. Running under its native root custody passed 101 tests with one ignored namespace test. That test requires the new precreated candidate root. The first unprivileged test run hit four existing root-custody tests, which passed under the root run. The `inputs` and `cadence` commands succeeded on actual retained evidence. The production preflight rejected the missing new guard qualification before considering later inputs.
