# Epoch 223 v2 warmup scratch retirement

This standalone crate handles disposable epoch 223 warmup scratch. Commit
`f896d8b2` preserves the exact source for the first v2 retirement. The
native 20 profile also binds the failed run's capture and stop receipts to the
successful repeat of the same target. It retains the original proofs and
deletes only the failed run's scratch.

Run the source checks with `cargo test --locked --manifest-path
tools/horizon-warmup223-v2-retirement/Cargo.toml`. Operational use requires the
exact sealed plan and executable SHA-256. The finished v2 retirement receipt
is in `~/.jetstreamer-private/warmup223-v2-retirement-v1/completion.json` on
Foundation.
