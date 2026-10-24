# Epoch 141 frozen ledger recovery

`jetstreamer-epoch141-ledger-reverify --plan PATH --plan-sha256 HEX
--self-sha256 HEX [--check-only]` verifies the existing frozen compressed
generation without downloading it again or modifying its bytes, owner or mode.

This is deliberately scoped to the exact failed source-download invocation on
dev-samjohnson and its retained inode, not a general adoption or retry tool.
Seal the executable and strict `jetstreamer-epoch141-ledger-reverify-plan-v1`
plan before use. The plan binds the original download plan, initial guard,
authenticated generation metadata and transfer admission, exact source
device/inode, no-clobber root-private output, protected free-space threshold
(at least the original threshold) and bounded runtime.

The original owner must remain loaded, failed, zero-restart and process-free
with its original invocation. An original success or stop receipt prevents
this recovery. The input must be canonical, root-owned 0444, singly linked,
exactly generation-sized, inside its frozen root-owned 0700 directory.
`--check-only` checks those local gates without an SDK call, hash scan or receipt.

Normal execution requires a persistent systemd invocation and performs exact
generation metadata lookups before and after a complete bounded CRC32C, MD5
and SHA-256 reread. It fails closed on source/path identity changes, original
owner changes, resource limits, credential errors or preexisting outputs.
It writes a distinct durable reverification receipt; it never fabricates the
missing original download receipt or claims the original failed unit succeeded.

Use a root oneshot with the source read-only, only the new receipt directory
and `/home/sol/.config/gcloud` writable, and the existing auxiliary one-core,
4/8-GiB memory envelope. Retain DAC traversal, setuid/setgid and own-child-kill
capabilities needed by the reviewed metadata helper. Do not run until the
operator refreshes the bound default gcloud configuration. Keep the auxiliary
growth reservation until the new compressed receipt and clean terminal
verification invocation are independently checked.

Compressed integrity is not ledger completeness or hidden-PoH recovery.
Complete native tar/LSM/WAL collection and every target boundary chain,
followed by canonical checkpoint, plugin and publication gates, remain separate.
