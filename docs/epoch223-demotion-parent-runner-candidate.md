# Exact epoch 223 demotion parent and runner candidate

Source preparation only. No Cargo, parent/worker execution, native input,
replay, status publication or R2 action has qualified this adapter.
The historical worker source is unchanged at
551728fda72afd36ce6f8652ddb0020ec249e860.

## Immutable inputs already available

Parent sealed package:
`/var/lib/jetstreamer/horizon-native223-demotion-bracket-551728fd-v1`.
Its seal plan SHA-256 is
`acaaa520ab8561a24d330f61a33186b3804d94b78b343ca3f6034cb3b55f86b7`.

- Production `jetstreamer-historical-worker-v1-6-20`: 8,975,736 bytes,
  SHA-256 `0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0`.
- `bracket-release-test-harness`: 20,071,016 bytes,
  SHA-256 `a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b`.
- Source QA report SHA-256
  `3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f`.
- Build/harness report SHA-256
  `b1caaebf21e878e09e5d60735d074aafcd56b1eaf0204d6cfa5d19ee5192edb1`.

The report deliberately does not claim a contemporaneous ELF digest at the
earlier source-test run. Its exact retained Cargo harness path/fingerprint and
source depinfo are preserved, and its metadata stayed unchanged across the
later production build. The newly hash-bound harness still requires an actual
independent cold-input invocation. The production worker remains unexecuted.

## Parent changes and isolation

New node feature `epoch223-demotion-bracket` uses a separate typed adapter.
It does not edit `compatibility.rs` or its ordinary era registry. Internal
ordinary planning/test routes remain unchanged; the actual build's entrypoint
requires epoch 223 and explicit private comparison. Its launch validator
permits only cold bootstrap 96335538, warmup from 96335539, output from 96336000,
and end 96544588, in a fresh `qualification-223-demotion-bracket-*` root.
Cohorts, inherited recovery, full-root and tail spans are rejected.

The existing private comparison/preflight CLI spellings are reused:
`--epoch223-tail-comparison` means this exact bracket in this isolated build,
and adding `--epoch223-tail-preflight` traverses its no-worker barrier.
The preflight emits its own demotion-bracket schema and correct 208,589 output
slot count; it never claims the old 477-slot tail or known-root prefix.
The generic CLI's other cold/root expectations are not weakened.

The exact focused range gets a private descriptor with backend identity
`solana-v1.6.20-epoch223-called-program-demotion-candidate` and dedicated
`JETSTREAMER_HISTORICAL_WORKER_EPOCH223_DEMOTION` override. There is no usable
default executable path. Default builds still reject that handshake.
The parent verifies the copied executable's exact pinned digest before it can
spawn or initialize the worker, closing the pathname replacement window.

Snapshot initialization binds the exact 9,815,262,303-byte cold archive with
SHA-256 `301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665`.
Before the first entry, the actual worker freezes its bootstrap and the parent
compares the complete known tuple (Bank, accounts, last PoH blockhash,
capitalization, transaction count, tick height, write cursor, complete flag,
zero bootstrap writes). This is separate from the earlier harness proof.

The source scheduler, transaction result/fee checks, wire ordering and native
PoH verification remain the existing parent implementation. Additional native
checkpoints at 96544586 and 96544587 compare the actual Bank commitments to
`3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso` and
`5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7`. No hash is substituted.
The parent also compares exact original parent transaction 432 and failing
Vote wire bytes, their observed canonical success and actual native success.
The Vote must be slot 96544588, entry 4, transaction 0, after both Bank gates
and the successful parent wire. The terminal checkpoint refuses completion
without all four real observations. Unit-test supplied hash strings cannot
create this initialized native session.

The bootstrap AccountsHash remains mandatory. The diagnostic deliberately
does not fabricate terminal or intermediate accounts hashes from voted Bank
hashes. Its separate Bank/Vote obligations do not qualify the real root
96767522, a full archive or a native resume checkpoint.

## Closed runner successor

`jetstreamer-epoch223-demotion-bracket-resource` is a separate utility target.
It reuses the reviewed bounded runner's exact file binding, private directory,
process-group ownership, natural terminal handling and private segment
recording. A compile-bound manifest-validation hook defaults to the existing
root checker for every existing profile; only this new binary overrides it
with its own exact diagnostic scope and pinned semantic worker. No serialized
option can switch another profile to this validator.

The profile fixes slot 96544588, 36-hour maximum, two Rayon threads, original
cold snapshot and distinct unit/root/result schemas. Proposed inherited native
planning bounds remain 225 GB MemoryMax / 150 GB MemoryHigh, swap 0, 300 GB
scratch plus output margin, and the old protected floor. These are conservative
proposals, not a fresh fit result or authorization to retain an obsolete floor.
Root must review fresh complete-fleet/century admission before any invocation.

Runner production compilation separately binds:
`JETSTREAMER_EPOCH223_DEMOTION_PARENT_SHA256`,
`JETSTREAMER_EPOCH223_DEMOTION_NATIVE_PROOF_PATH/SHA256`, and
`JETSTREAMER_EPOCH223_DEMOTION_ADMISSION_PATH/SHA256`.
Absent configuration still compiles for the compatible-feature CI lane but
fails closed before any child launch. It is not a default credential or worker
fallback. The production worker SHA is pinned directly in source.

An actual bracket requires a separately sealed
`jetstreamer-epoch223-demotion-native-input-proof-v1` binding the exact sealed
harness, test name, original source QA, source commit, production worker,
snapshot/genesis, successful zero-restart manager result, full bootstrap tuple
and zero replay/bootstrap writes. This proof issuer/adaptation remains a
required next implementation/qualification gate. Existing old-native20 results
and test logs whose native case was ignored cannot satisfy it.

The separate admission schema binds the exact unit/parent/worker/snapshot/native
proof, 120-second fresh complete accepted fleet/observer context, no overlap,
requested and actual kernel memory limits, protected floor and independent
guard's PID/start ticks/cgroup/IID/ELF. The runner rechecks the real guard
process identity before spawn and on its 15-second safety cadence. This is not
a second fleet/replay resource observer. Its actual runner PID/IID are captured
in the genuine pre-spawn evidence. Guard issuance/capability and typed admission
capture remain unqualified; a hand-written optimistic JSON is not a substitute.

## Genuine repair task and status contract

Coordinate with the lifecycle source contract at
`epoch204-recovery-r2-adapter-source-v1`, frozen ec43bd3f, specifically
`fleet/assembly204_recovery/ownership.rs`, `transition.rs` and
`pipeline_status.rs`. That implementation is exactly 204 and must not accept
223. No files in that worktree were edited.

A separate typed 223 claim must bind original failed e70a launch/clock and
current repair plan, admission, actual actor launch, frame and ETA policy, all
by exact path and digest. The real owner can supervise actionable source/native
tasks, but a queued plan, sleeping process or old e70a IID is not live repair.
Actual task launch capture requires PID1's zero-restart unit/IID/PID, exact
ExecStart executable/argv, start ticks, complete start journal, real start time,
kernel/cgroup limits and applicable independent guard identity.

Issuance brackets a complete current census before and after, rejects competing
owners/replacements, binds accepted observer/fleet as context, and records the
honest metadata-event timestamp. It must not fabricate a new observer or rates,
backdate the phase, or reset elapsed execution to this repair. Use verification
during real cold-input/compatibility work, then replay only once execution is
actually observed. Status must have a definite integer sidecar-inclusive ETA
covering source/target wait, native input, the 209,050-slot bracket, full restart
and canonical root, prefix reread, native handoff, 477-slot suffix, assembly,
independent full/plugin/boundary checks, close, upload, readback and sidecar.
Bind all positive allowances and their evidence to the actual actor.

Publish immediately after genuine launch/claim capture, then refresh only with
the single 1,800-second campaign observation. User-requested status observations
remain allowed out of band; positive failure/handoff/completion events use their
supported immediate lifecycle. Retain failed diagnostics/history and unrelated
204/207/209/225 claims/gates. Implement and qualify this exact ownership/status
branch before ongoing native work is advertised. This source adapter does not
implement or deploy that issuer and cannot authorize its own status.

## Next source QA gate

No parent/runner Cargo command has run. Only pinned Rust 1.98 parsing/formatting
and diff checks ran; the modified historical worker tree remains byte-unchanged.
Existing code inside default-vs-private branches was mechanically indented.

Request a fresh main-target lease and reviewed 16 GiB memory/total-artifact,
two-job, sequential release/offline/locked, 30-minute-per-command source QA
envelope. Preserve an actual allocation baseline and verbose compiler records;
stop on native C/C++ rebuild or cap failure. Do not access a target owned by the
lifecycle/227 agents. First typecheck default and exact feature, run the five
pure adapter tests, the private runner manifest-scope test, selected existing default registry/IPC tests, scoped strict
Clippy and the compatible utils-feature checks. Run negative scope and missing
proof/parent-pin tests without starting workers. The CI matrix adds the node
feature explicitly, while compatible utils builds need no runtime proof env.

Only after review and real qualification may root build/seal the isolated parent,
perform no-worker capability, issue the real native proof/admission/guard and
admit a bracket. Passing the bracket still requires a fresh full-root restart
from 96335538 unless a native snapshot export/import is independently implemented
and qualified; the existing worker refuses export. Root 96767522, prefix reread,
suffix, assembly and every archive/sidecar gate remain open.
