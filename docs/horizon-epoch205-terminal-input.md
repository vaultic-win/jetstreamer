# Epoch 205 terminal snapshot input

`jetstreamer-epoch205-terminal-snapshot-prepare` acquires only the compressed,
generation-pinned snapshot at slot **88,991,050**. It does not restore a snapshot,
execute entries, qualify a prefix or suffix, create a sidecar, publish an archive,
or change any runtime route. Epoch 205 ends at 88,991,999: the remaining **949
slots** still require separately qualified native restart, suffix and assembly
semantics plus the normal independent full/current-plugin/R2 gates.

The fixed source is the `mainnet-beta-ledger-us-ny5` object
`88991050/snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst`,
generation `1634790073611030`, length `8,407,269,066`, CRC32C `9/mUyw==`,
and MD5 `fBpHLn3nugSP8+TvNmpB1Q==`. These values agree with the retained
epoch-205 root-checkpoint manifest and an authenticated exact-generation GCS
metadata read. The local SHA-256 must be computed after transfer, not invented
from the snapshot filename or accounts hash.

The downloader reuses the reviewed compressed-input engine. The 223 legacy
profile remains unextended; the 227 and 205 profiles explicitly opt into the
same fixed protected-fleet contract. That contract binds the current exact
203/223/225 invocations, complete observer/fleet census and thirteen ready
epochs. Both protected downloads use the existing immutable
`horizon-bootstrap227-transfer-lease-v1/transfer.lock` to prevent concurrent
spending of their shared capacity reservation. Its historical name does not
make the new input an epoch-227 bootstrap.

For this operating point the minimum protected free space is
`(960 + 1536 + 640) GiB + 248,289,182,611 bytes`, or
`3,615,543,542,675 bytes`. Admission additionally requires the entire compressed
object and 64 MiB slack above that reservation. This does not adopt the proposed
smaller epoch-223 growth claim or relax any existing guard or hard ceiling.
The plan may raise, but cannot lower, the protected reservation. A changed
fleet, century census, invocation or operating point requires a fresh review.

Before transfer, seal the binary and exact plan with the Rust deployment sealer,
bind the GCloud launcher digest and a fresh coordinated v2 observer plus its
matching fleet receipt, and run the exact sandboxed `--check-only` invocation.
The profile accepts its plan, plan SHA-256 and executable SHA-256 positionally.
No object or account/project override is accepted. It uses the operator's
interactive GCloud configuration with the fixed account and requester-pays
billing project; refreshing that configuration never mutates a live replay's
isolated credentials.

Execution needs a distinct persistent non-restarting service, fresh output and
receipt paths, the same protected lease, and the engine's free-space/runtime/
process-group controls. It validates the complete GCS identity before and after
transfer, independently recomputes CRC32C, MD5 and SHA-256, revalidates local file
identity, and writes a no-clobber private receipt. The resulting input remains
compressed and private. Retain it until an applicable reviewed cache-retirement
profile establishes that it is no longer needed.
