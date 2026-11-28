# Current reader publication gate tests

This bounded package compiles the production current-reader gate and progressive
coordinator directly. It covers full-range report validation (including valid
leader-skipped notifications), source/object/invocation mismatches, exact reader
qualification, immutable evidence, missing playback, and actual Git fetch/diff
against an isolated local repository. The Git fixture uses the invoking
repository's configured author identity. The coordinator tests cover forwarding
the required plan and refusing a missing plan while retaining retirement checks.

Run `cargo test --offline --locked` and
`cargo clippy --offline --locked --all-targets -- -D warnings` here.
These tests do not claim a production R2 transfer or actual full archive playback.
The uploader's full crate, deployed artifacts and native transport/playback
integration still require qualification before selecting a new publication path.
