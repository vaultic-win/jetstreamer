# Guarded full epoch 172 on half a CPU

The controller runs the canonical epoch 172 node with the sealed v1.5.6 worker. The producer and protective timer are separate systemd units capped at 50% and 25% CPU. Native replay and guard memory limits remain 68 GiB and 1 GiB. The complete fit retains the existing audit slice, other replay owners, auxiliary bookings, focused epoch 169 growth and its live floor. The historical 172 memory-point record covers this producer and guard. HOME accounting covers the entire 288 GiB epoch 172 tree. The new unit has a fourteen-day runtime ceiling because the historical prefix rate projects slightly beyond seven days at 50% CPU.

The pinned normal node executes through a read-only file bind under `/run/horizon-full172-half-core`. The guard identifies executables underneath the epoch tree as historical workers. The node's original argv, verification settings, bootstrap, indexes, terminal checkpoint and epoch output paths remain bound to the qualified full-epoch payload.

Build `gate.rs` with the release Rust toolchain, compile the existing epoch 169 `admit169` executable as `reservations`, and include the current epoch 136 `public_audit.py` witness in the controller seal. The helper's read-only `--measure-replay-reservations FLEET SHA` command reuses the original identity-bound disk scanner and auxiliary accounting. The seal also includes `profile.py`, `capacity.py`, `session.py`, and `build-proof.json`. The latter binds the tested source commit, Git input blobs and both ELF hashes. The controller verifies the origin branch at runtime.

Use the root-owned sealed package at `/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-half-core-20261120-v1/controller`. Run the session as root. Substitute the current full fleet file, its SHA-256 and the SHA-256 of the controller deployment seal. The same interlock serializes observed capacity, genuine timer proof and release.

```sh
/usr/bin/python3 -I -B "$package/session.py" preflight "$fleet" "$fleet_sha" "$seal_sha"
/usr/bin/python3 -I -B "$package/session.py" launch "$fleet" "$fleet_sha" "$seal_sha"
```

The preflight authenticates the remote inventory and rehashes the input files. Launch repeats those checks. Under the first and post-guard fits, the native gate holds its original PID until the root-owned invocation token appears. The first timer receipt must prove the exact raw free-space and whole-root limits before payload release. The persisted admission and subsequent R2 status initially describe bootstrap. A repeated launch recovers the same recorded admission and preserves failed setup evidence.

The sole scheduled fleet/status writer owns publication. Include `ACTUAL_ADMISSION_AND_PROTECTION.json`, producer PID, invocation and phase in its bootstrap transition. Once the historical worker is active, run the following and add the returned row to its next regular coordinated observer. The worker must be the sealed executable inside the correct scratch, with a fresh protective sample. Publish the replay phase and ETA after observed slot and transaction counters advance. The confirmation command reads the resulting authenticated status and observer evidence.

```sh
/usr/bin/python3 -I -B "$package/session.py" observe "$admission" "$admission_sha" "$seal_sha"
/usr/bin/python3 -I -B "$package/session.py" confirm-adoption "$admission" "$admission_sha" "$seal_sha" \
  --fleet "$updated_fleet" --fleet-sha "$updated_fleet_sha"
```

For the first rate measurement, compare the actual first and last advancing stdout counters over a normal observation interval, including elapsed time, slot and transaction deltas, producer CPU time, and guard recency. A checked bootstrap or guard receipt alone cannot establish a replay rate.
