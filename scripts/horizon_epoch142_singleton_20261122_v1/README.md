# Epoch 142 independent replay

The ordinary v1.4.25 node starts from the root at slot 61,328,765 and processes 15,234 warmup slots before the first output at 61,344,000. It checks the canonical accounts hash at slot 61,775,538 and writes through slot 61,775,999. The epoch has 432,000 output slots.

[route.json](route.json) contains the normal argument array, environment, original service inputs and three read-only file binds. The retained GCS snapshot is 4,297,291,805 bytes and lives inside a HOME-backed image. The source seal binds generation 1634786682225857, the loop-device inode, the backing image inode, SHA-256, MD5 and CRC32C. Pin both inodes before admitting a worker. Mount the ledger and private work beneath a common writable parent and bind the snapshot, genesis and [manifest](preflight-142-v4.json) at the paths in the route.

The November 22 native qualification verified the complete input and selected the full singleton, the v1.4.25 worker and the checkpoint. A 2 MiB file-size ceiling stopped the private worker copy before execution. The qualified source receipt is `/var/lib/jetstreamer/horizon_runtime_data/epoch142-full-local-20261122-v1/NORMAL_ENTRY_QUALIFIED.json`, SHA-256 `0a179033e37086d57ab0172c84d605b29b76ddd5050711c19bcebecf2e5e7c32`.

The prospective worker uses the existing full-replay envelope of 68 GiB and nine cores, a separate 1 GiB and one-core guard, and a 288 GiB writable tree. The checked runtime handoff records the unfunded amounts and the required guard and status registration for the real invocation. Its path is `/var/lib/jetstreamer/horizon_runtime_data/epoch142-full-local-20261122-v1/FULL_REPLAY_HANDOFF.json`, SHA-256 `a2eec5cfc92192dde08470d8c65c0f0125761196cdc6536931e66cd367f35342`.

## Continuous replay through epoch 143

When both archives are missing, the same v1.4.25 node can carry bank state from epoch 142 into 143. The pair uses the same snapshot at slot 61,328,765 and checks the canonical roots at slots 61,775,538 and 62,207,522. Its output covers slots 61,344,000 through 62,207,999. Both archives stay staged until the final root and both archives pass validation. [Paired preflight manifest](preflight-142-143-v4.json)

Select `142-143` in the normal `--verify --root-checkpoint-cohort` invocation and bind the paired manifest with fingerprint `sha256:413ba642b7c5d130e145edcd8c8ead1afd3b4d3ea521472a3067fc6ab2cf5e37`. Use a dedicated ledger and private run directory. Before launch, check that both epochs are still available for assignment and price the full two-epoch working set, including both staged archives. The singleton and the pair are alternative bookings for epoch 142.
