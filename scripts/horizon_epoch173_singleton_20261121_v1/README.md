# Epoch 173 singleton inputs

The standard epoch 173 node reads the sealed GCS bootstrap at slot 74,735,808 through a read-only file bind. The ledger receives mainnet genesis through another read-only file bind. Give the ledger and private state a single writable parent mount so the node can atomically rename files between them during publication. Keep the input files read-only under the producer’s sol:horizon identity. The argument array, environment, paths and hashes are in [route.json](route.json).

In the bounded startup qualification, the ordinary node accepted the entire 2,341,977,058-byte bootstrap at generation 1634787554356719. It bound the final account root at slot 75,167,662 and selected solana-v1.5.6 for slots 74,735,809 through 75,167,999, including the final 337 slots. The fixture’s 2 MiB file ceiling stopped the private worker copy before execution. Both inputs kept their original inodes.

The deployed standalone guard accepted the 288 GiB whole-tree cap and 3,500,000 worker VMA limit for this service. At admission, bind the new actor invocation and freshly computed free-space floor. Keep the payload behind the startup gate until the real timer-driven guard succeeds, the post-guard complete fit passes, and the controller registers the new owner and status. The existing archive verification and publication procedures apply after full replay.
