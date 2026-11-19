# Home-backed audit observer successor

Source only: `src/bin/observe_cycle_retry8_homeaudit.rs` is a separate successor
of `observe_cycle_retry8.rs`. The existing observer, timers, workers and audit
remain unchanged until Root qualifies and deploys this source.

The successor includes the exact shared
`horizon_retry6_170_guarded_launch_20261119_v1/src/audit_budget.rs` module. It uses
that module's `observe()`, `fleet_obligation()`, `validate_fleet_obligation()` and
`compiled_source_sha256()` interfaces. Bind both source files in the artifact
proof. The actual audit identity is v8 PID 2227285, invocation
`99c7ddc48af140efb131b784a6b064d2`; another invocation needs a reviewed successor.

## Accounting

The old zero-DATA/root-only audit envelope is replaced with the shared home
obligation and a durable `HOME_AUDIT_OBSERVATION.json`. One cadence-bound
observation captures native identity, frozen inventory, progress, exact owned
scratch inode/allocation, state and reader metadata allocation, and the last
written summary/child records. No archive body is read. Downloading, reader
qualification/waits and resident playback are supported. An epoch/phase or
scratch ownership transition during capture fails without inventing a budget.

Remaining audit growth is:

```text
exact current archive length - min(current resident allocated bytes, archive length)
+ 16 GiB - observed exclusive state/reader working allocation
+ 2 GiB admitted Cargo growth allowance
```

The full Cargo allowance is retained because no exclusive cache baseline grants
credit for consumed bytes. Resident scratch/work are already reflected in actual
free space. The 385290386716-byte acceptance ceiling is never booked as a future
archive reservation. A snapshot during a download records the earlier resident
allocation; later growth is not used to reduce the bound.

`complete_DATA_bytes` retains the existing **6794761027378-byte replay contract**,
which the stage/preparer still require. Additive audit growth is explicitly
reported as `complete_DATA_with_remaining_audit_growth_bytes` and under
`continuing_audit_obligation.current_storage`. `complete_DATA_authority` documents
that separation. This is not a reduction of the replay promises. The one known
20:03 migration supplement's conservative archive-plus-full-work-and-cache total
can be separated only when its exact replay baseline, old166 obligation and sum
match; any unknown extra obligation causes refusal.

All existing memory totals, old166's 309237645312-byte DATA obligation, live
166/167 identities, epoch/status bindings, holding obligations, historical proof
and non-replay transition bindings remain. Audit memory is not added again.
Admission remains separate: the shared admission code must reobserve the current
audit and concurrent replay growth; this observer cannot authorize a launch.

## Cadence and output placement

The accepted replay sample still must enforce the 1800-second minimum and bind
all 19 authenticated statuses. The audit has the same minimum. The sole next
timer is scheduled no earlier than either the replay sample's next permitted
time or 1800 seconds after this audit observation began. This prevents varying
reconciliation latency from scheduling an early audit poll. Timer naming and
the existing single-successor behavior are preserved.

New cycle output, next observer sample and sealed config use the existing
root-owned, home-backed `/var/lib/jetstreamer/horizon_runtime_data` alias. The
original observation executable and all historical receipt paths are retained.
Root must validate that the final sandbox can read the audit state/readers and
write these new output paths without changing healthy workers or mount identities.

## Qualification and deployment handoff

No build, test execution, commit, seal, reservation or service mutation has been
performed for this source handoff. Rust 1.98 rustfmt parsing/formatting and a
whitespace check are the available local validation. New tests exercise exact
growth versus resident bytes, ceiling/cap rejection, preserving both peer/status
records and old166, and rejecting an unexplained predecessor allocation.

Root should use its admitted HOME target and fixed Rust 1.98 toolchain to run:

```text
cargo test --locked --manifest-path scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml --bin observe_cycle_retry8_homeaudit --target-dir ADMITTED_HOME_TARGET
cargo clippy --locked --manifest-path scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml --bin observe_cycle_retry8_homeaudit --all-targets --target-dir ADMITTED_HOME_TARGET -- -D warnings
cargo build --release --locked --manifest-path scripts/horizon_retry6_167_live166_stage_20261118_v1/Cargo.toml --bin observe_cycle_retry8_homeaudit --target-dir ADMITTED_HOME_TARGET
```

Preserve explicit toolchain environment, required resource guards and the exact
shared module source. Validate the successor against the genuine accepted
sample/status/fleet and an equivalent final sandbox. Publish the required source
to `account-updates`, seal the new HOME runtime with the approved Rust sealer,
and switch only the cycle helper at the next accepted cadence. Do not start the
binary merely as a read-only probe: like its predecessor, its normal invocation
creates the next sealed observer config and arms the next timer. Do not create
a second observer timer. Keep v8 playback running throughout.
