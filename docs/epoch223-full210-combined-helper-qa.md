# Combined epoch 223 / full 210 helper QA proposal

This is a source-only proposal. No Cargo, target/cache access, runtime action or
R2 operation was performed. Exact command arrays and source pins are in
`epoch223-full210-combined-helper-qa-plan.json`.

## Source closure

The combined implementation checkpoint is `7412f095d56a9683c257ea29532225f98d8f97ce`
(tree `389c9f9d1febcb8e3caeb8e65fa675442a36d54a`). It is frozen bracket checkpoint
`87f98a80` plus exact full 210 commits `1d0ab837`, `74b0699a`, `63a5e385`.
Their sole added source change is `maintenance_capacity/singleton210_memory.rs`.
Reviewed terminal 227 commits e3d84732, c6992980 and 511fbc75 are now also
integrated, with only the separately requested two error-message spacing edits.
All eight shared eaa files remain byte-identical to eaa8f5ac. Later full-root
source is preserved separately. Reviewed epoch 204 commits 26e9eed8 and 9d0c9ac4 are now integrated.
Both cherry-picked cleanly. The fleet assembly-owner map adds the recovery owner
without removing capped owners or the separate demotion 223 adapter. Host-memory
accounting retains the typed assembly path followed by demotion 223 memory views.
No semantic conflict was found. This source is still unqualified.

Static comparison against reviewed closure 688aa576 found every reviewed path
package manifest unchanged. Workspace/R2 manifests, lock and Cargo config SHA-256
values match; vendor, lock and config Git objects match. This establishes an
unchanged proposed dependency/feature closure, not current cache readiness.
After owner-frozen repairs arrive, root must review their exact deltas, prepare a
new coherent successor, regenerate the complete tracked source census and plan
pins, and recheck manifests/config/build inputs before granting execution.
No guessed future ELF hash or old QA result qualifies this combined source.

## Exclusive lease and cumulative allowance

Root must explicitly transfer the actual shared target/cache lease first. Do
not touch target/cache or compete with an existing Cargo owner during preparation.
The reviewed target is `/home/ubuntu/workspace/jetstreamer/target`; Rust is 1.98.0.
The original target-baseline digest is 6e32307a85bf83ae8633955e6afede0e066bc160203755104c8ba19bcd465635.
All prior/current changed artifacts, failed attempts and evidence remain charged
against the same 4 GiB cumulative allowance. A fresh census cannot reset spend.
Current remaining allowance has not been measured here. If it is insufficient,
stop and let root review a new resource decision; no cleanup or new target is
implicitly authorized.

Use the reviewed pre-Cargo wrapper and actual manager/kernel sandbox checks:
14/16 GiB memory high/max, zero swap, CPU 200%, 512 tasks, no restart, control-group
kill and 1,800 seconds per sequential command. Each command needs its own actual
bounded invocation under the same exclusive lease, rather than an unbounded
multi-command shell. User/group ubuntu, private network/tmp, no new privileges,
strict system/read-only home and inaccessible campaign paths remain required.
Only leased target and a new root-approved evidence directory may be writable.
Unset DOCS_RS, unreviewed ClickHouse inputs and compiler overrides; preserve
reviewed Cargo config, environment and actual tool identities.

Before and after each command, retain actual artifact/source identity and
cumulative charge results. Stop on first test/lint failure, unexpected native or
dependency rebuild, network attempt, configuration drift or exhausted allowance.
Keep failed evidence and original source labels. No automatic retry or baseline
reset is proposed. QA monitoring is separate from replay/resource observation;
it does not authorize another routine campaign poll.

## Proposed sequential commands

All commands use `--release --frozen --locked --offline -j2 -p jetstreamer-r2`.

1. Strict Clippy: `--all-targets --all-features -- -D warnings`.
2. Focused all-feature test group `demotion223`.
3. Focused all-feature test group `canary227`.
4. Focused all-feature test group `canary227_terminal`.
5. Focused all-feature test group `inactive_status` (including canary cleanup).
6. Focused all-feature test group `assembly204_recovery`.
7. Focused all-feature test group `fleet_memory`.
8. Focused all-feature test group `prefix223_live_peer`.
9. Focused all-feature test group `singleton210_memory`.
10. Focused all-feature test group `maintenance_capacity`.
11. Complete all-feature package suite.
12. Complete default-feature package suite.

Tests use `-- --test-threads=1`; no ignored tests are forced to run. Record exact
matched test names/counts; a zero-match focused group is a failure of the plan.
The maintenance group intentionally exercises cross-consumer accounting beyond
the narrow singleton group. Full suites catch command dispatch/serde/status and
feature interactions. Existing fixture skips must remain reported as ignored;
synthetic or ignored results never establish an actual native commitment.

Required assertions include authentic terminal native 223 proof in both saved
census brackets; no release from cleared PID/clocks alone; retention of every
existing growth byte, guard and larger reserve; full additive accepted-control
charges; unknown-owner rejection; original failed epoch 223 evidence/clock;
actual epoch 223 task/status ownership; 30-minute routine refresh cadence and
only explicit user or genuine lifecycle exceptions. Mixed canary/223 paths must
retain the canary producer and exactly one guard charge.

Passing this proposal qualifies only the selected combined R2 helper source.
The native utility and parent need separate selected-feature QA/builds; existing
harness a280 still needs its actual cold-input execution. Production helper
build/capture/seal requires separate root authorization and fresh real artifact
pins. Source QA cannot release producer ownership, prove live fit, publish a
sidecar or upload an archive.

## Integrated cleared-terminal epoch 227 policy

The root-reviewed source series is based on eaa and keeps all eight original
shared eaa files unchanged. Fleet capture and inactive cleanup use the same
typed current-terminal validator. Raw zero PID/start/exit properties stay raw;
origin PID/start and exact original success require separately authenticated
launch/result/journal evidence, plus before/after idle census and journal-tail
checks. Empty properties cannot create success. Existing failed history, pending
trigger rejection and zero release credit remain intact. Cleanup still requires
exact publication identity, conditional ETag and durable intent/completion; this
is not archive/sidecar or resource-release authority. The retained-PID predicate
is unchanged. New tests cover exact successful original manager/producer
witnesses, missing/duplicate/foreign or newer history, and result-bound child
identity. The focused inactive-status suite checks unchanged cleanup scope;
actual systemd/R2 cleanup remains outside source QA.

The source checkpoint in the machine plan predates only the requested wording
changes and this proposal update. Root must pin the final document commit and
full tracked source census before execution. No production/native artifact pin
has been created, and epoch 204 source qualification remains required.

## Final combined execution preparation

Root must review the final clean source commit/tree and external package hashes,
then explicitly authorize staging at the existing passed source pathname
`assembly204-aac-qa-corrections-worktree` and transfer its shared target lease.
Preparation has not moved that pathname or read/written target/cache. The external
package supplies a full tracked source census, exact commands, unchanged reviewed
closure, original cumulative baseline and an adapted bounded wrapper proposal.
The prior eaa result is historical evidence, not this successor's qualification.
All prior evidence and retry allocations remain charged; the last historical
combined charge was 2,850,996,224 bytes, not a current free-budget measurement.

The focused recovery tests cover original-actor immutable lineage across routine
frames, 30-minute cadence with the exact explicit user-requested exception, and
real host RSS/guard accounting as non-replay overhead. Phase-origin inputs cannot
be replaced by arbitrary later data. Full suites must still pass after source
integration. The execution package is preparation only, not a launch instruction.
