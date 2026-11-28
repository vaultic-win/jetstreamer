# V32 sole cadence handoff

V32 preserves the accepted V31 lineage starting with the 03:18 fleet. It follows the latest accepted descendant and inherits its exact native timer, clock configuration and writer lock. The reader binds the original V31 ACTIVE and seal, the retained epoch 167 and 170 evidence, the original epoch 146 reader, and the exact joint 168 enrollment.

## Read-only preparation

Run `derive.py V31_PACKAGE MERGED_167_GATE STAGING` against the installed V31 package and the gate source from commit `578c962b`. The staged seal plan uses `tools-cold168-retry5-failed166-v32-entry146`. It stages the 167 scope reader and an independent receiver that verifies the actual admitted gate against its deployment and preparation receipts. Install through the existing sealer after merging the V32 source.

Run the sealed V32 `status_cycle.py --check-entry`. Then run `status_cycle.py --check-v32-handoff FLEET SHA` against the latest accepted fleet. This prints the READY contents after checking that the original observer timer is the only waiting timer or confirming its completed native sample. Save the exact READY under `FAILED166_CADENCE_V32_READY.json` in the existing cadence state root.

The controller activates V32 in the existing cadence service with the original consumer lock. V32 verifies that the V31 process incarnation has exited, acquires the same lock through normal entry, and records `FAILED166_CADENCE_V32_ACTIVE.json`. Keep the native observer timer and immutable observer config through the transition. If a cutover races a newer accepted fleet, rerun the handoff check against that fleet.

## Private 167

The receiver reads `START_INTENT.json` from the existing bounded 167 state directory. It binds the admitted package, native PID and start ticks, 42 GiB producer with 40 GiB high and 1 GiB guard, and the exact `bounded_cap_bytes` and `armed_floor`. The release and permit must bind the same admitted actor. Only a matching live guard can advance the bounded worker into the private diagnostic schedule.

The private row is `current_bounded167_checkpoint`. Its hold, bootstrap, worker and terminal phases preserve the historical `cold167_execution_failure` and 512 GiB booked tree. The cadence keeps the original epoch 167 canonical status route. The native observer carries a separate private assignment for the bounded worker. A native exit closes that assignment with zero resource credit.

The original joint 168 enrollment remains authoritative until its exact native terminal receipt verifies and its cgroup drains. A normal successful sample retains its original diagnostic result through the transition. If the timer's sample fails and the genuine terminal is already proven, the inherited recovery cadence removes only that diagnostic entry when it creates the next allowed observation.

## Probe

Run `probe.py SEAL_PLAN PRIVATE_DIRECTORY` with the same installed evidence and a fresh isolated directory. The probe materializes a private sealed copy, runs normal entry checks, exercises the predecessor handoff and crossed receipts, projects all private 167 phases, tests a joint 168 terminal fixture, and checks the actual accepted clock. The probe has zero production clock changes.
