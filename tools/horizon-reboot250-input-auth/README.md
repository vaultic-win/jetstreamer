# Epoch 250 input custody

This one-shot Rust binary checks the generation-pinned GCS restore receipts,
manifest, two local snapshots, historical node and worker, and same-cluster
genesis. It writes a root-owned, no-clobber input acceptance receipt. Replay
still requires separate cache, native capability, admission, guard, and launch
gates. The binary cannot mutate R2 or start replay.
