# Epoch 250 input custody

This one-shot Rust binary checks the generation-pinned GCS restore receipts,
manifest, two local snapshots, historical node and worker, and same-cluster
genesis. It writes a root-owned, no-clobber input acceptance receipt. Replay
still requires separate cache, native capability, admission, guard, and launch
gates. The binary cannot mutate R2 or start replay.

`check-251 OUTPUT_JSON` checks the reused, root-owned sealed epoch 251 bootstrap
against the original epoch 250 final-root download receipt: both name the same
generation, snapshot slot, size, CRC32C, MD5 and SHA-256. It hashes the actual
sealed bootstrap, genesis, deployed node and worker, binds the exact-source
native input test, and validates the singleton manifest and canonical checkpoint.
No final-checkpoint snapshot copy is required. The acceptance is input custody,
not replay admission or publication authority; the output parent must already
be root-private, and existing receipts cannot be overwritten.

`check-251-published-node OUTPUT_JSON` preserves those input and worker checks
but selects the sealed `eabd0b6a` node. It also binds the clean source manifest,
actual production build proof and deployment seal, requiring the exact node
digest, successful build and empty feature set. It emits a distinct v2 custody
schema and explicitly leaves exact epoch 251 node replay qualification and fresh
source-publication admission checks outstanding. The old modes retain their
original node and receipt schema; no live worker is changed.

The published-node mode passed four tests, strict Clippy, a fresh captured
release build from `d6d56aae2d2762994704587081baaf4e941ec596`, and a native
sandboxed input check on 2026-11-18. The helper is sealed at
`/var/lib/jetstreamer/horizon251-captured-node-auth-20261118-v1`; its executable
SHA-256 is `9168907cea6ead4a592f0b57b5184244f09dcfc8cc6026ef9396509911bab4b6`.
Acceptance:
`/home/ubuntu/.codex/diagnostics/horizon251-captured-node-input-20261118-v1/acceptance.json`,
SHA-256 `02227422d85616cb060bce6a001dab5ee104c0ff39a0f7d554b67466344b83f7`.
This rehashed the exact bootstrap and selected binaries. Node replay
qualification, candidate launcher migration and fresh admission remain open.
