# Epoch 157 private terminal reference

The two unmodified Solana workers replay the original Old Faithful entries in
order. Both restore the locally retained, generation-qualified 68,249,460
snapshot. The publisher still requires an independently trusted terminal
LegacyAccountsHash. This diagnostic has no authority to change a checkpoint
list, make an archive, start a producer, or publish to R2.

Install Python 3.12 and cbor2 5.7.1 in the campaign environment. The x86-64
CPython 3.12 manylinux wheel used on Anza has SHA-256
`9fc81da8c0e09beb42923e455e477b36ff14a03b9ca18a8a2e9b462de9a953e8`.
The script uses the system curl with HTTP/2, findmnt and the loop device sysfs backing-file record.
Run `python3 reference.py probe` for the two boundary blocks, three recovered CAR blocks and the native worker
handshakes. Run `python3 -m unittest test_reference` from this directory to
exercise the response and account-write boundaries.

The reference replay takes two arguments after `replay`. The first is the
private mountpoint of a fully allocated 96 GiB ext4 loop image on HOME. The
second is an empty mode-0700 receipt directory on HOME. The reference runs as
the unprivileged campaign user under a paid two-core, 80 GiB cgroup with zero
swap. The backing file must be read-only to that user. Mount the read-only
input snapshot, genesis, scripts, Python packages and both worker executables
in the existing protected launcher. Keep the attempt's receipt directory and
scratch mount writable. Allocate the image only after the complete fleet price
and the exclusive holder permit it. The hard image cap also contains a failed
or interrupted attempt. An interrupted run retains its receipts and evidence. Disable discard while formatting and mounting the image to preserve its preallocated blocks. Direct the service stdout and stderr to bounded HOME logs.
Use a fresh attempt after inspection.

The command inside that allocation is

```sh
python3 reference.py replay /absolute/attempt/scratch /home/sol/.jetstreamer-private/absolute-attempt-receipts
```

The driver pins the index slices, checks lengths and HTTP ranges, verifies every
selected CAR section CID, and requires contiguous physical CAR coverage.
The original indices omit 68,254,833, 68,255,841, and 68,261,681. The private
correction supplies the original byte spans, full SHA-256, parent slot and PoH
endpoint for exactly those three finalized blocks. All three were recovered
from the gap between neighboring CAR ranges and matched independently against
finalized getBlock responses. The neighboring slots 68,254,832, 68,255,840 and
68,261,680 are skipped. The driver follows each block's original entry and transaction
links, and checks every produced parent. Each native worker verifies the PoH,
executes the original transactions, and computes its own full frozen Bank
checkpoint and legacy accounts hash. The protocol reader checks the signature
and write-version sequence and binds the successful-transaction count. Account
writes from freezing the prior Bank are included at the start of the next
produced slot. It discards streamed write data after checking the frame.

Both passes must match all seven original consensus fields at the bootstrap
and at 68,255,828. Version 1.5.8 stops at its admitted last slot, 68,255,999.
Version 1.5.6 crosses into 158, compares the independently signed bank hashes
at 68,255,999 and 68,256,004, and must match the authenticated downstream
LegacyAccountsHash at 68,262,721. The two terminal consensus tuples must match.
Both workers share a bootstrap and related source code. The independent
downstream snapshot commitment and distinct vote signatures corroborate the
trajectory; neither publishes a terminal LegacyAccountsHash. The ordinary
producer gate remains in force until its separate provenance requirement is met.

At the end of each pass the worker exits and releases its scratch before the
next worker starts. `v1.5.8.json` and `v1.5.6.json` record the actual checkpoints.
`comparison.json` is written only after both passes and the downstream
comparison succeed. The two workers' AccountsDb cursors are validator-local.
