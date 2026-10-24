# Foundation 213 typed empty hook arrays

This isolated successor descends from frozen db0b3d74. The original worktree,
production candidate and provenance successor remain unchanged.

The actual first sealed invocation failed before data access because systemctl
show omitted empty ExecStartPre. An omitted display field cannot establish an
empty property. The successor independently queries the five exact Service
properties ExecStartPre, ExecStartPost, ExecCondition, ExecStop and ExecStopPost
through busctl get-property on the exact tracked unit D-Bus path.

Every query must succeed and return exactly `a(sasbttttuii) 0`, optionally with
its single trailing newline. Missing replies, other signatures, nonzero counts,
extra tokens, malformed types and unavailable properties fail. The raw reply
string is preserved for each property. A show field may be omitted only after
that property's typed empty array has been proven; a present show field must
still be an empty string. No raw show keys are added, hidden or normalized. All
other required properties remain mandatory, including explicit success/zero
Result and ExecMainStatus for the currently running invocation.

Actual typed replies become part of the private running Facts alongside the raw
show properties, executable, process identity, sandbox, kernel limits, held
transition descriptor flock and immutable spec bindings. Every existing context
revalidation performs the actual queries again and requires exact fact equality.
The supplemental receipt provenance includes the original raw typed replies.
There is no absence-as-empty rule, generic property fallback, operational retry,
service alias change, PID exemption or new authority.

Offline fixtures preserve root's actual terminal manager-show bytes (SHA256
`d2ecea55e2dac0414df4286bbfc4e16ff22d4ac20f195b7ec2148436f4d3dc75`)
and typed empty reply bytes (each SHA256
`c2732de4326d4404f99f2b7381cafaefeae0d981ca769ab36d077e68529f7d2b`).
The failed invocation was dc6b1b8b8de44050a2b95c15c0b3602f, PID 803491.
The test first validates the actual omitted-display/typed-empty shape and also
rejects that failed terminal invocation as a running context. The live-shaped
matrix removes all five show fields and exercises every missing/malformed raw
reply, conflicting show value and other missing required property. Neither unit
Environment nor credentials are queried or copied.

The change does not alter the actual resumable transport, admission freshness,
protected peer guards/floors, anchored retirement or the service template. Source
qualification and candidate creation perform no operational service, process or
resource observation, archive/snapshot body access, R2 action or cleanup.


## Qualification

The focused self-accounting suite passed all 10 tests. The complete R2 release
suite passed 662 tests, with none failed and 48 intentionally ignored. Both
commands used the explicit shared target, CARGO_INCREMENTAL=0,
`--locked --offline --release -j2 -p jetstreamer-r2 --all-features`. The focused
filter was `holding::foundation213::restore_self::tests`. The log records this
worktree's observer library being rebuilt after timestamp-only invalidation.
The anchored transport/retirement sources, Cargo.lock and Cargo configuration
remain byte-identical to the frozen parent.

Strict all-target Clippy also passed with the same locked/offline release flags
and `--all-targets -- -D warnings`. The production candidate is built separately
from the clean frozen successor, with `--verbose` and literal dep-info plus actual
direct Rust/native input copies and hashes captured before lease release. This
is input provenance for the stated scope, not a complete hermetic/toolchain or
linker archive-member proof. Root independently seals and qualifies execution.
