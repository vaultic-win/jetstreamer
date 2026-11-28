# Recoverable pressure checkpoint evidence handoff

`tools/pressure_checkpoint_handoff.rs` implements the controller phase from an
already clean producer exit to an immutable resume-evidence package. It does not
stop a producer, release memory reservations, admit or launch a replacement,
publish an archive, or access R2.

The root-only command accepts `PLAN --plan-sha256 HEX --self-sha256 HEX`.
The plan schema is `horizon-pressure-checkpoint-handoff-plan-v1`, with a hash-bound
`exit_plan`, a private `state_directory` and a new `destination`. State and output
must be direct children of `/var/lib/jetstreamer` with the respective
`horizon-pressure-handoff-state-` and `horizon-pressure-resume-evidence-` prefixes.

An exclusive state lock serializes retries. The pinned clean-exit helper checks
the retained producer invocation before sealing and again before completion.
The pinned Rust deployment sealer copies the paused report, exit proof and exit
plan into the new package. If the controller dies after sealing, its replacement
validates the existing package against the durable seal plan: exact receipt,
member names, hashes, modes and lengths, and the sealer's sorted SHA256SUMS,
including the seal receipt. It never overwrites a conflicting package or record.
Completion explicitly requires fresh admission and denies launch, resource
release and publication authority. Keep the producer's terminal invocation
retained until the transition and its intended proof consumption finish.

Qualification on 2026-11-19 used a fresh native HTTP CAR producer at slots
432000–432001, two transactions, and 64 ticks per slot. The producer exported a
checkpoint, reaped its source worker and exited successfully. The test controller
then deliberately exited 86 after the real deployment seal and before completion.
The production controller recovered the package, wrote completion and accepted
an identical retry. A fresh native worker consumed the resulting sealed report
and exit proof, executed the suffix, and assembled a V4 archive. An independent
full verifier checked both slots' PoH and the exact terminal blockhash.

The unit scope test and root integration tests passed, including immutable-record
retry, conflicting bytes, symlink/hardlink rejection, actual sealer compatibility,
changed member rejection and unexpected member rejection. Clippy test compilation
passed with `-D warnings`. Builds and native tests ran serially with 2 GB memory,
zero swap, CPU quota 400%, CPUs 48–55 and TasksMax 256.

Evidence is retained in
`/home/ubuntu/.codex/diagnostics/horizon-pressure-handoff-20261119-v1`.
The controller image SHA-256 is
`c39aaefa2a8d9bfe223678dcacdac498158aea4ebbf53b0f81872a5ec7d423e2`;
the sealed resume-evidence receipt SHA-256 is
`34db28391950978ba9d325ce027339e775f00a6242529ad93856143afd00c2a9`.
The two-slot archive SHA-256 is
`b3ca610f79f609e63691a9d9185e01ea0280ab2bce80455dc0ff84ee213cbadc`.

This establishes one recoverable controller phase on a native synthetic input.
Automatic fresh admission, guarded suffix launch, the actual production CLI,
full-epoch plugin playback and exact mainnet worker pressure qualification remain
required before using checkpoint rotation to oversubscribe production memory.
