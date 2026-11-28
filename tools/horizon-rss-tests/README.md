# RSS census tests

This package directly compiles the production observer's RSS module. Run
`cargo test --offline --locked` and
`cargo clippy --offline --locked --all-targets -- -D warnings`.

Tests use temporary proc/cgroup fixtures. Positive Linux exit evidence may
restart the entire bounded host census; it never authorizes zero RSS or a
partial sum. Missing fields without exit/reuse evidence remain failures.
These tests do not qualify a deployed observer, change the 30-minute cadence,
authorize a lane or replace an accepted resource observation.
