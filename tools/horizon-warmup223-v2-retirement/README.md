# Epoch 223 v2 warmup scratch retirement

This standalone crate retains the exact source used to retire the failed epoch
223 v2 warmup scratch. The deployed executable and completion receipt still
bind the original plan and executable digests. The standalone copy preserves
the source of that sealed executable, including its legacy profile checks.

Run the source checks with `cargo test --locked --manifest-path
tools/horizon-warmup223-v2-retirement/Cargo.toml`. Operational use requires the
exact sealed plan and executable SHA-256. The finished v2 retirement receipt
is in `~/.jetstreamer-private/warmup223-v2-retirement-v1/completion.json` on
Foundation.
