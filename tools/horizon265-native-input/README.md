# Epoch265 selected-worker cold input harness

Source only. No native run, guard, admission or runtime qualification has occurred.
This standalone Rust binary links the shared `protocol-current` facade; it does
not rebuild or link the historical worker. Main owns dependency lock generation,
serial bounded tests/builds, publication, sealing, guard qualification and launch.

The closed request sequence is Hello, Initialize from the exact retained snapshot,
FreezeCheckpoint114479281, Shutdown. It pins worker `c3b2c334`, snapshot `04eb59e2`,
genesis `133f7eae` and input-packet `f7dbb6ee`. It checks protocol/backend/Solana
commit/mainnet genesis, snapshot identity and canonical accounts commitment
`Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW`. The snapshot's existing write cursor
is preserved across checkpoint; it is not incorrectly required to start at zero.
No entry replay, export, download, remote mutation or runtime promotion exists.

`gate.rs` adapts the native211 actual-invocation first-guard gate. Before worker
spawn, input hashing, ledger copy or snapshot work, it validates root-sealed plan,
original 60-second admission, current boot/executable/cgroup and immutable token
under `/var/lib/jetstreamer/horizon-native265-startup-tokens/<IID>/`. The token
binds a genuine no-trip first-guard sample and unique PID1 start/completion events.
The gate has no renewed deadline, fallback, retry or missing-evidence bypass.

Use a new empty ubuntu-owned0700 root:
`/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1`.
The harness creates ledger/scratch/tmp and copies only the20KB sealed genesis
after admission. Snapshot bytes are not recopied or rehashed: the exact packet
digest and full immutable device/inode/length/owner/mode/link/timestamps retain
the existing whole-file verification. The selected worker is rehashed.

The original input packet is root0400 beneath private diagnostics. Main must seal
a byte-identical0444 copy as
`/var/lib/jetstreamer/horizon265-native-input-evidence-20261119-v1/input-packet.json`
using the normal sealer. The harness expects that readable immutable copy with
the original exact SHA, not relaxed permissions on the original evidence.
Likewise expose sealed admission/guard/token evidence to the ubuntu service
through readable immutable packages and qualify reads under the final sandbox.

The harness has one2700-second monotonic deadline, nonblocking poll-bounded IPC,
64MiB protocol frame limit, 8MiB total stderr retention and acknowledged shutdown
with reap. Oversized/failed logging fails the run; logs are never silently
accepted as complete. Session cleanup kills/reaps on error. The systemd template
adds an independent2700-second service limit,128GB memory cap, zero swap,512 tasks,
eight-core quota, closed network and write access only to its private root.
Admission must book506191984640 bytes scratch plus the complete existing floor,
all concurrent hard reservations and controller/guard/log overhead. CPU selection
and every template binding must be fixed before qualification/admission.

## Required guard/controller work before any execution

Existing `native227::observe_at` requires exactly the harness MainPID. This
standalone IPC harness necessarily has a separate historical-worker child, so an
existing native211/251 guard **will reject it after spawn**. Qualify a closed265
profile for this exact root/unit/harness SHA and selected worker image: exactly
the harness during the first-guard wait; then the harness plus at most one exact
child, checking parentage/cgroup/mapped immutable image/VMA limits. Preserve
hard memory, filesystem floor, whole-root cap and no-extra-process checks. Never
disable the guard or use a permissive generic child allowlist to get past this.
No guard artifact is claimed qualified here. The first-guard token schema remains
`horizon-native265-first-guard-token-v1`; the startup schema is
`horizon-native265-startup-plan-v1` and admission schema is
`horizon-native265-current-fleet-admission-v1`. Their full field contracts and
negative fixtures are in `gate.rs`.

Adapt the native211 root controller only with its latest per-field original
booking provenance and auxiliary/control overhead handling from `1309311b`.
The epoch265 replay launcher also still needs those changes; its earlier copied
reservation reader is not sufficient. Main must publish all required source to
account-updates and verify actual artifact source/dependency containment before
admitting either native qualification or replay. Retain terminal evidence and
complete no-trip guard history through acknowledged child reap and kernel drain.

## Results and checks

`native-result.json` is a durable, no-clobber measurement from the real harness,
written only after successful checkpoint, shutdown/reap and unchanged inputs.
It deliberately does not claim PID1 natural completion or zero guard trips: those
are external observations Main must verify and seal. Combine this result with
actual command/journal, source provenance, clean PID1 completion and complete
no-trip guard history into the launcher's separate
`horizon265-exact-worker-cold-input-qualification-v1` receipt. Never substitute
the input packet, codec tests, a successful source build or this README.

Negative source tests cover wrong image/owner/boot/clock/token, absent/stale/failed
guard, PID1 ordering, gate-before-work, malformed checkpoint/handshake/initial
state and IPC timeout/log failure. Run locked/offline tests and strict Clippy in
Main's one qualified build envelope after locking dependencies; no test or build
has been executed by the source agent. The existing actual codec evidence is
independent of selected-worker initialization and is not rerun by this harness.
