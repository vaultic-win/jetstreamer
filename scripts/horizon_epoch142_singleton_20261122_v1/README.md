# Epoch 142 independent replay

The ordinary v1.4.25 node starts from the root at slot 61,328,765 and processes 15,234 warmup slots before the first output at 61,344,000. It checks the canonical accounts hash at slot 61,775,538 and writes through slot 61,775,999. The epoch has 432,000 output slots.

[route.json](route.json) contains the normal argument array, environment, original service inputs and three read-only file binds. The retained GCS snapshot is 4,297,291,805 bytes and lives inside a HOME-backed image. The source seal binds generation 1634786682225857, the loop-device inode, the backing image inode, SHA-256, MD5 and CRC32C. Pin both inodes before admitting a worker. Mount the ledger and private work beneath a common writable parent and bind the snapshot, genesis and [manifest](preflight-142-v4.json) at the paths in the route.

The November 22 native qualification verified the complete input and selected the full singleton, the v1.4.25 worker and the checkpoint. A 2 MiB file-size ceiling stopped the private worker copy before execution. The qualified source receipt is `/var/lib/jetstreamer/horizon_runtime_data/epoch142-full-local-20261122-v1/NORMAL_ENTRY_QUALIFIED.json`, SHA-256 `0a179033e37086d57ab0172c84d605b29b76ddd5050711c19bcebecf2e5e7c32`.

The prospective worker uses the existing full-replay envelope of 68 GiB and nine cores, a separate 1 GiB and one-core guard, and a 288 GiB writable tree. The checked runtime handoff records the unfunded amounts and the required guard and status registration for the real invocation. Its path is `/var/lib/jetstreamer/horizon_runtime_data/epoch142-full-local-20261122-v1/FULL_REPLAY_HANDOFF.json`, SHA-256 `a2eec5cfc92192dde08470d8c65c0f0125761196cdc6536931e66cd367f35342`.
