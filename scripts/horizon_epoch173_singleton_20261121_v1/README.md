# Epoch 173 singleton inputs

The standard epoch 173 node reads the sealed GCS bootstrap at slot 74,735,808 through a read-only file bind. The ledger receives mainnet genesis through another read-only file bind. Give the ledger and private state a single writable parent mount so the node can atomically rename files between them during publication. Keep the input files read-only under the producer’s sol:horizon identity. The argument array, environment, paths and hashes are in [route.json](route.json).

In the bounded startup qualification, the ordinary node accepted the entire 2,341,977,058-byte bootstrap at generation 1634787554356719. It bound the final account root at slot 75,167,662 and selected solana-v1.5.6 for slots 74,735,809 through 75,167,999, including the final 337 slots. The fixture’s 2 MiB file ceiling stopped the private worker copy before execution. Both inputs kept their original inodes.

Production replay requires a funded actor, a current full-fleet fit, the normal worker and guard startup sequence, and status registration. The existing archive verification and publication procedures apply after full replay.
