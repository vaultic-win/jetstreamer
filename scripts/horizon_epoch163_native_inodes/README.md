# Epoch 163 native restore scratch

The epoch 163 snapshot at slot 70,415,741 contains 394,226 distinct tar members. The restore uses ten inodes including the tmpfs root and its scaffolding before it creates archive members. This profile mounts a 40 GiB tmpfs with exactly 524,288 inodes. The native actor and the issuer inspect the actual namespace before restore. The native48 lifecycle verifier also checks the mounted inode count while the actor runs. The backing DATA filesystem retains its separate minimum of 131,072 free inodes.

## Source preparation

Build a new generation in a private working directory. The normal 128 GiB actor source lives in `jetstreamer-node/src/bin/epoch163-native-input/source/native.rs`. The original issuer and plan templates are retained in the branch as source records of their historical qualifications. Apply the appropriate successor patch in a working copy.

* For native128, copy `direct163/` from `scripts/horizon_first_lane_native_before_v1/helper-overlay/jetstreamer-r2/src/fleet/` and `native-preparation/` from the same historical package into the working directory.
* For native48, take `native.rs` from the sealed `horizon-epoch163-native48-input-source-20261112-v1` actor source. For the issuer, use `direct163/` from the native48 independent helper overlay after applying its successor `PRIOR_NATIVE48_OVERLAY_LIFECYCLE.patch` and incorporating the lifecycle overlay. The independent overlay is `epoch163-native48-independent-source-20261107-v1` and the lifecycle overlay is `epoch163-native48-lifecycle-source-20261107-v2` under the host's private root. Keep the rest of the build's actor and integrated helper graphs with their existing provenance.

With the working directory arranged as above, set `package` to this package's absolute directory and `profile` to `native48` or `native128`. In the working copy, run

```sh
sha256sum --check --strict "$package/$profile.sha256" &&
    patch --batch --fuzz=0 -p1 -i "$package/$profile.patch"
```

For native128, copy `restore_mount.py` into the successor's `native-preparation/`, alongside the patched preparer and preflight. For native48, emit its actor's `TemporaryFileSystem` assignment using

```sh
python3 "$package/restore_mount.py" "$scratch_directory"
```

Pass that output as one systemd property. Keep the existing state-only `ReadWritePaths`, read-only sources and scratch temp aliases. Qualify the actor first, then bind its actual sealed image and qualification SHA-256 in the issuer and preparer. The native48 issuer and the native128 successor templates require those qualification digests. Commit the integrated, digest-bound sources used by the selected build before admission. Preserve the original memory, swap, CPU, disk, lifecycle and admission guards for that profile.

## Qualification evidence

At 11:57:55 UTC on 2026-11-23, an isolated kernel test populated both tmpfs profiles with the actual snapshot member names, original order and logical file lengths. At the old limit of 131,072, Linux returned `ENOSPC` for member 131,063, `accounts/70192500.1146344438`. The production failure names this member but did not record its errno. The corrected mount accommodated all 394,226 members with 130,052 inodes left.

The test used sparse stand-ins. Per-task tracepoints counted 394,226 shmem inode slots and 394,226 dentries, representing 387,918,384 bytes in those two slab caches. Allow for data pages, other kernel allocations, allocator overhead and Bank memory when pricing a real restore. The original tar contains 8,353,534,771 logical bytes. Raising `nr_inodes` leaves the data-byte cap and cgroup hard limits in force.

The home-backed proof packet is `~/.jetstreamer-private/epoch163-inode-repair-20261123/proof/`. SHA-256 of `KERNEL.json` is `6ee74a7b691c1edf66bb8e274608c366c5e5dc2937c99680a54eb73548f493ad`. SHA-256 of `METADATA.json` is `d2a2d80747f8cfa0435febaf25acf1c14dd588ac039d1e9e6bac9ff917629b17`. Actual snapshot extraction, Bank hash verification and first-output production each require their own qualified run.

## Native48 source and compiler reservation

On the campaign host, stage the complete corrected actor and audit its retained compiler dependencies with `python3 stage_native48.py actor OUTPUT`. It reconstructs all seven files from tracked sources, checks the 55 original extern hashes and verifies the native linker directories. Seal `OUTPUT/actor-source-plan.json` using the normal deployment sealer. Then `python3 stage_native48.py operator OUTPUT/actor-source-plan.json OPERATOR_OUTPUT` reproduces the 15 original guarded commands with their corrected source paths and payload digests. Ten produce artifacts, and the other five run the original 82 ordinary and kernel controls. The historical phase supervisor still requires the four-producer fleet it was built against. Its current-fleet admission needs a separately qualified successor.

Run `python3 build_price.py NATIVE_FIT CHECKED_PROJECTION` as the evidence reader to price those commands. The quote reopens authenticated source and fleet receipts and preserves the hourly epoch 169 source transfers, workspace and independent guard. An exclusive loan after epoch 159's actual drainage can fund the two-CPU compiler and one-CPU DATA guard from focused 169's three producer CPUs, with the single-CPU supervisor occupying the serial build allocation. The bootstrap uses two overlapping two-CPU cgroups inside the same joint envelope. Reserve 10 GiB of work and growth plus 512 MiB for source, seals and receipts on HOME. Hold the donor and compiler interlocks through drainage. The actor units match the `horizon-qualify` prefix of 145's independent replay census. Verify explicit compatibility or actual nonoverlap before admission.

The 48 GiB restore requires its separate 786,326,978,560-byte available-memory floor and eight CPUs. Only the completed restore, observed Bank hash and finalizer qualify its capability for first-output work.

For the five compiler-operator bootstrap commands, the released general build slot can cover one 256 MiB supervisor and one 512 MiB child. The dedicated `horizonaudit-epoch163bootstrap.slice` must enforce a single CPU across both processes. Each child retains its original 200% unit quota, zero swap, 40-second lifetime, 12 MiB output limit, private network and 32 MiB compiler tmpfs. The two generic compiler locks exclude another bootstrap. All five jobs use compiler names. The 128 MiB HOME image and 16 MiB outside allowance cover persistent evidence and the operator deployment. These jobs use no focused epoch 169 loan.

`stage_native48.py operator --current-fleet ACTOR_PLAN OUTPUT` prepares the supervisor with its current admission checks. Run `dispatch_bootstrap.py prepare COMMIT` as the campaign evidence owner to seal the four source files and the bootstrap tools. A fresh complete 145 native price must identify the live verifier, all five producers, the public workers and the historical 159 terminal. `bootstrap_fit.py` checks it against the current general slot and the original five compiler commands. The controller can then issue `dispatch_bootstrap.py dispatch COMMIT QUOTE SHA LIVE_145_IID`. The quote contains `native`, `bootstrap` and the five `original_commands` hashes. Only the expected ROOT-approved one-shot dispatch creates the image and bounded slice. Preserve its grant and outputs on failure.

The 15 later consumer phases require their own explicit compiler loan, native fit and physical guard. Their existing unit names enter the 145 producer census. The current supervisor requires a drained 145 verifier before it can acquire the actual focused and compiler locks for those phases. Completed bootstrap checks qualify the supervisor only. A native restore still needs its original 48 GiB and eight-CPU booking, available-memory floor, returned Bank hash and finalizer.

After the bootstrap supervisor exits, run `python3 -IB finish_bootstrap.py` as the evidence owner. It matches the five ordered child invocation IDs and their actual PID1 success events to the supervisor's clock, checks the original commands and artifacts, confirms every cgroup drained and seals the qualified operator. The fixed work image retains its receipts until the controller reconciles local custody.
