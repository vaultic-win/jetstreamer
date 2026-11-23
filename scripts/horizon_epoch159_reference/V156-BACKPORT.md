# Bounded epoch 159 v1.5.6 reference

At slot 68,687,834, 162 successful finalized voters signed the Bank produced by the archived v1.5.6 worker. The v1.5.19 reference diverged on this first child. At 68,688,000, all 461 successful signed votes referenced hashes present in the earlier v1.5.6 SlotHashes and absent from the v1.5.19 SlotHashes. At 68,688,001, thirteen successful votes signed the first Bank of epoch 159. Both references missed that Bank and rejected the original vote at transaction 78. The signed first-child evidence and the 1,049-row boundary join are identified in `v156-backport.json`.

The isolated candidate carries the official upstream vote initialization and stake-cache gate from `241fb938` into the October 4 v1.5.6 worker tree `6bdd58ce`, at Jetstreamer commit `7b001172`. Its old SDK registry receives only the gate declaration and entry. Cargo uses the original 294-package lock, 15 Solana Git packages at `01e4d0a1`, the same two vendored runtime crates and all 275 registry archive checksums. The five files have explicit preimage and result digests. The historical worker, BPF loader and all original Bank construction, PoH, hash and slot-vote checks keep their original source. A test-only integration target is added to the private workspace after building the release executable.

## Source preflight and native build

From this directory, run the following source checks on Anza.

```sh
/usr/bin/python3 -IB backport_source.py check
/usr/bin/python3 -IB test_trace.py
/usr/bin/python3 -IB test_service.py
/usr/bin/python3 -IB test_feature156.py
```

The October 4 build used `cargo +1.49.0 build --release --manifest-path worker/Cargo.toml`, default features and the host target. It took 2m03s with its original target cache and produced the 9,361,680-byte `cf5fa883…819` worker. Its ELF build ID is `8f58e83c64d3c68a5f27da2412e1a920773ea240`. Cargo 1.49 resolves the Solana bare cache as `solana-58d818797bb1766e`. Source preparation checks it against the archived checkout at the locked Git tree before materializing the private patched checkout. Both the old and current host have GCC 13.3.0 and binutils package 2.42-4ubuntu2.10. glibc changed from 2.39-0ubuntu8.9 to 2.39-0ubuntu8.12 on November 13. The original startup objects and linker scripts match today's bytes. The dynamic loader, libm and libc changed. The archived original worker used those same updated shared libraries in the November 23 positive pre-boundary trace.

The compile entry point runs as sol (UID 1001) inside the owner's existing resource-priced compiler, with `PrivateNetwork=yes`, `ProtectSystem=strict`, `NoNewPrivileges=yes`, an empty capability set and an absolute writable directory on charged HOME scratch. Its output argument names a fresh child of that writable directory. It uses a read-only host, an isolated writable Cargo home, locked offline metadata, one build job, and an empty target. Cargo must resolve the five edited inputs from the expected three packages. Its native Cargo messages must identify a fresh compilation of all three packages and the worker. The test exercises the registered inactive feature and vote initialization for valid and oversized accounts on both sides of activation.

```sh
./compile-v156.sh "$charged_home_scratch/v156" \
  /home/sol/.cargo /home/sol/.rustup/toolchains/1.49.0-x86_64-unknown-linux-gnu
```

An observed November 20 v1.5.6 build with warm debug inputs took 6m56s for release using one CPU, 2 GiB RAM and no swap. The retained release target allocated 1,039,966,208 bytes, and the separate debug target allocated 1,211,613,184 bytes. This candidate starts with an empty release target and runs a release-only integration test. A planning allowance of one CPU, 4 GiB RAM, 4 GiB charged HOME scratch, zero swap and a 45-minute wall-time limit covers the larger rebuild of the changed SDK and vote dependencies. This is a proposed allocation. The controller prices it against the current fleet independently of the bounded diagnostic. Record actual peak memory, HOME, CPU duration, compiler, linker inputs, test result and the new ELF before admission.

## Native diagnostic

Seal the resulting ELF in the HOME-backed runtime package. The diagnostic sandbox mounts that package read-only at `/opt/epoch159`, where the worker is available at `feature156.WORKER`. The owner seals and reviews the native build output, test results, input hashes and executable. Place a `v156-build.json` in the flat runtime package alongside the original ordinary reference modules, `feature156.py` and `v156-backport.json`. Its fields are `native_build_succeeded: true`, `native_build_evidence_sha256` (the owner's full native build receipt), `source_manifest_sha256` (the shipped v156-backport.json), `patch_sha256`, and `worker` with its absolute sandbox path, file length and SHA-256. The unprivileged process hashes the actual mounted worker and checks the original protocol-v5 Rust, genesis, runtime and target handshake.

```sh
sudo -n /usr/bin/python3 -IB package-v1/service.py --feature156 check-mounted-inputs
sudo -n /usr/bin/python3 -IB package-v1/service.py --feature156 recipe
sudo -n /usr/bin/python3 -IB package-v1/service.py --feature156 dispatch "$admission_sha256"
```

The separate service checks the actual prior invocation and scratch retirement, the prior donor-unit set, the same global donor lock and the live epoch 145 verifier before borrowing. The physical package, entire snapshot, independently pinned index and seven original CAR windows, capacity, lease set, unique intent, UID, mounts, resource caps and retention procedure all use the existing reference controls. The replay reservation is two CPUs, 48 GiB RAM, zero swap, a fully allocated 24 GiB HOME ext4 with 524,288 inodes, and 32 MiB other HOME.

After restoring the original snapshot, the worker must produce the first signed child, matching its ordered canonical transaction signatures, success flags and fees. The first-child write stream also records a native digest. A mismatch stops this attempt and leaves the evidence for comparison. The final epoch 158 checkpoint must match all nine original native fields. At both first epoch 159 slots, collect native Bank hashes, complete SlotHashes and ordinal transaction results. At epoch activation observe the actual original feature write, including account hash, owner, rent epoch and bytes. Transaction 78 must succeed. All 157 blocks, 69,491 original entries and 97,502 transactions must be covered. This diagnostic has no archive publication step.


## Qualify the standard producer

The November 23 23:01 UTC reference passed all four signed Bank checkpoints, all 157 blocks and the formerly failing vote at slot 68,688,001. `production_probe.py` verifies the retained successful invocation and exact worker bytes, then prints the snapshot, checkpoints, worker binding and expected terminal results. This is a read-only check:

```sh
sudo -n /usr/bin/python3 -IB production_probe.py
```

Use the sealed, current `account-updates` production node in a new private proof lane. The standard historical registry selects v1.5.6 for the entire warmup and output interval. The backport implements protocol v5 and advertises the same runtime, toolchain, target and mainnet genesis. Set its executable for this invocation through the existing worker environment variable, and record the actual executable SHA-256 in the qualification evidence. Keep other lanes' executable bindings independent. The archive wire format, PoH checks and publication gates use the existing production implementation.

After the ordinary capacity and sandbox admission, seal the reference's `checkpoint_filenames` as the one-filename-per-line checkpoint file, and bind the exact snapshot and current node in the same deployment. Use the ordinary Old Faithful input path with the qualified indexes. The smallest replay that can exercise the failure through both the production input and archive writer starts at slot 68,687,834 and ends at slot 68,688,001:

```sh
JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=yes \
JETSTREAMER_HISTORICAL_WORKER_V1_5_6="$sealed_worker" \
  "$sealed_node" 159 "$private_destination" --verify \
  --snapshot-archive="$bound_snapshot" --epoch-hashes="$bound_checkpoints" \
  --replay-scratch="$private_scratch" --qualification-end-slot=68688001 \
  --horizon-output="$private_destination/epoch-159-prefix.jet"
```

Require the standard producer to reach and verify all four post-bootstrap accounts checkpoints. Compare its terminal native checkpoint to the signed reference and check the emitted segment's bootstrap and terminal evidence, sealed worker digest, exact coverage of slots 68,688,000–68,688,001, anchored PoH and current-reader decode. Join transaction 78 in the second block by full signature and require success and the 5,000-lamport fee. A source mismatch should identify the first failing block and compare its CID-qualified entries against the existing bounded reference before introducing a source adapter.

The retained epoch-159 root at 69,119,821 precedes epoch end. A full candidate still needs all 432,000 output slots and a canonical end-of-epoch or successor checkpoint that covers the tail. The existing production route supports an explicit verification tail, subject to its qualified terminal evidence and one-owner constraints. Qualify that full route and independently verify the complete archive before considering publication.
