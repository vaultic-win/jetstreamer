# Bounded playback report tests

This package compiles the production plugin report module directly, without the
Solana runtime dependency graph. Run `cargo test --offline --locked` and
`cargo clippy --offline --locked --all-targets -- -D warnings` here.

The tests cover persisted slot boundaries, counts and invocation, incomplete
coverage, malformed ranges, relative paths, existing files and symlinks. They
do not qualify the full pipeline, archive decoder, remote readback, reader source
equivalence, or uploader sidecar gate. Those checks remain separate requirements.
