# Foundation 213 tracked resumable restoration

This work descends from frozen 4a49ce4a. It does not modify that worktree, the
anchored retirement implementation, resumable byte/SHA transport or frozen
7d4266bc probe artifacts. Only `holding-foundation213-restore-resumable` may
construct the new opaque running context, under the exact tracked alias
`horizon-foundation-holding213-maintenance-v1.service`.

The dispatcher holds the existing transition descriptor flock first. Context
construction then authenticates the real root PID, nonzero systemd invocation,
actual kernel argv, sealed mapped executable/path/hash, immutable exact restore
spec/hash, fixed mapping, exact Prefix213 custody/admission bindings, process
start time, actual UID/GID/capabilities/NoNewPrivs, effective read-only/writable
mounts, manager sandbox and real cgroup memory/swap/tasks/CPU controls. The
kernel's descriptor-specific flock record must prove that this PID owns this
same root-owned, single-link lock inode. Revalidation never reacquires a lost
flock or accepts another process because its PID happens to match a JSON field.

Capacity retains the original five replay owners and every guard/growth/floor
check. Raw fleet, observer and before/after censuses are not edited. Only the
exact authenticated self row is distinguished from replay-competitor comparison;
every other unknown owner, replacement, vanished peer or changed command fails.
The opaque Rust type cannot be supplied through the JSON spec. Admission-only,
legacy restore, maintenance and retirement paths get no such exception.

## Entry freshness and bounded continuation

The admission's 900-second age and accepted observation's 1800-second age remain
strict at the real initial entry time. This is retained as an immutable timestamp
inside the actual running context, not supplied by a user flag and never renewed.
The first complete entry capacity check must still fit the already-admitted
protected floor before any byte restoration. A slow prefix hash/suffix/final
reread can then continue within that same actual bounded invocation without
failing solely because the original entry proof became older than 900 seconds.

Every later check still rehashes immutable bindings and the running executable,
proves the same actual PID/IID/start time, actual unchanged kernel/sandbox bounds,
held transition flock and the fixed maximum service lifetime. The current five
protective guards are selected from genuine latest completed PID 1 histories,
never receipt mtime or an older success after a failure. Selection is limited to
the five original protected producers, their original sealed plans/binaries and
receipt directories; timers must remain active and correctly targeted. Current
receipts must still be fresh within 1800 seconds, have the same producer identity
and protection envelope, and pass the existing complete growth/floor validators.
No guard is started and no replacement observer/resource sample is generated.

The exact current roster is 225, 205, 204, singleton 209 and root-prefix 223;
legacy native 207 cannot fill the singleton 209 slot. Each latest receipt must
preserve the admitted optional-field presence as well as values. Stop semantics
remain in the existing complete per-owner disk validators: the pinned legacy
225 guard and plan implement implicit stops without a `producer_stop_enabled`
field, while the modern guards retain their explicit true flag. Offline fixtures
retain all five actual immutable receipt/plan shapes from admission 363; they are
test evidence, never runtime authority or a fallback to stale receipts.

The accepted observation remains an explicitly retained allocation baseline for
this existing reservation, never a new capacity claim. Current owner/cap censuses,
current completed guard facts, actual output allocation checks and filesystem
free-space brackets remain enforced. The held floor can never decrease below the
entry admission; it can rise to protect a larger current reserve. Every later
metadata write checks that nondecreasing floor. No new peer admission, memory or
disk credit, replay, retirement or publication authority is created. Changed
owners, stale/tripped guards, insufficient actual reserve or the original bounded
service deadline still stop the operation and preserve private progress.

The complete restoration receipt retains its existing schema, actual complete
SHA proofs and authority-denial fields. An additional self-accounting provenance
object explains the original entry timestamp and held reserve; it is not a new
admission or a retirement authorization. Retirement still requires its own fresh
closure/capacity transaction and independently hashes the full real files.

## Concrete service requirements

Use `foundation213-resumable-self-accounting.service.in` under the exact alias
above. The reviewed concrete exec template sets:

- Type=exec, active/running; RuntimeMaxSec=4h (14,400,000,000 raw microseconds),
  TimeoutStartSec=90s and no restart or completion hooks.
- User=root, Group=root, KillMode=control-group, Delegate=no.
- MemoryMax=6G (6,442,450,944 bytes), MemoryHigh=5G (5,368,709,120 bytes),
  MemorySwapMax=0, TasksMax=256 and CPUQuota=100% (1,000,000 raw microseconds
  per second; normally cpu.max `100000 100000`).
- NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=read-only and the one
  common ReadWritePaths=/home/ubuntu/.jetstreamer-private bind.
- CapabilityBoundingSet and AmbientCapabilities contain only DAC_OVERRIDE,
  DAC_READ_SEARCH and SYS_PTRACE. Actual /proc capability bounding must match.
- No ExecStartPre/Post, ExecCondition, ExecStop/Post, OnSuccess/OnFailure or
  triggering units. In particular the old maintenance finalizer is not called.

Validation also supports a real oneshot activating/start invocation bounded by
TimeoutStartSec at most 4h, rather than its ineffective RuntimeMax. Exec requires
a real RuntimeMax at most 4h. Memory may be smaller but must be positive and no
larger than 6G; tasks at most 256, CPU quota positive and at most eight CPUs, swap
zero. MemoryHigh may be a positive bound no greater than MemoryMax or the genuine
manager/kernel infinity/max pair. Explicit or default root user/group labels are
accepted only with actual kernel UID/GID 0. The writable bind may instead name
only the exact holding state; public Horizon and sealed deployment paths must
actually remain read-only. These are checked values, not declarations that root
may skip. No service or body operation is performed during source qualification.


## Source qualification

The corrected source passes the complete R2 release suite with both native
features: 660 tests passed, none failed, 48 intentionally ignored. The final
shared-target test invocation was `CARGO_TARGET_DIR=/home/ubuntu/workspace/jetstreamer/target
CARGO_INCREMENTAL=0 cargo test --offline --release -j2 -p jetstreamer-r2
--all-features`; it did not include `--locked`. Its log records rebuilding this
worktree's observer library after an explicit timestamp invalidation without a
content change. An earlier separate private-target run also passed 660 tests;
that compiler cache remains preserved and is not the release artifact source.

Coverage includes actual descriptor flock loss, exact manager/kernel/mount and
capability bounds, immutable self/peer identities, entry age boundaries, fixed
four-hour lifetime, nondecreasing reserve, the exact five-owner guard selection,
and all five actual immutable guard receipt shapes including legacy 225. Source
qualification does not execute an operational restoration or confer deployment
authority. Root must independently seal and qualify the actual running unit.

Final strict all-target Clippy also passed using the explicit shared target,
`CARGO_INCREMENTAL=0 cargo clippy --locked --offline --release -j2 -p
jetstreamer-r2 --all-features --all-targets -- -D warnings`. Cargo.lock, workspace
configuration and the anchored resumable transport and retirement sources remain
byte-identical to the frozen base. Production artifacts are built separately from
the resulting clean commit with `--locked --offline --release -j2 --all-features`.
