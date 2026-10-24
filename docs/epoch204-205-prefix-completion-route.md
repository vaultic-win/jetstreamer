# Active capped prefixes 204 and 205: source completion handoff

Source preparation in an isolated worktree based on `38d5115c`. The horizon-r2
checkpoint-continuation rules apply. No new resource poll, archive scan, Bank
restore/replay, service operation, immutable-package change or R2 request was
performed. The latest campaign observation remains root's cycle 353 at 08:42
UTC. Preserve both healthy producers and their original scratch/output.

## Frozen authorities and coverage

| Epoch | Original invocation | Output start | Known-root prefix terminal | Canonical end | Missing tail |
| --- | --- | ---: | ---: | ---: | ---: |
| 204 | `448da7f2a3a34217afe7e115120b3cea` | 88128000 | 88559361 | 88559999 | 638 slots |
| 205 | `373359a11aef4993a1a949e19ff617c3` | 88560000 | 88991050 | 88991999 | 949 slots |

These are not inferred from live file sizes. Exact sealed launch receipts:

- `/var/lib/jetstreamer/horizon-prefix204-launch-fcbf3992-v1/launch.json`, SHA256
  `a1b38f09bb1314c9280ca924602bab1523d28755146919912f604c1ee9bbfdfb`.
- `/var/lib/jetstreamer/horizon-prefix205-launch-5c01bf93-v1/launch.json`, SHA256
  `febbbb44b1d2b16afc3511e171dbb1f1aab732890893be1ce2f72239bc01ca9e`.

They bind the exact units
`horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service` and
`horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service`, respectively.
Their resource plans hash to `cc5109ed54c4b5cdc7db99a7e839708753b677cee11b7ca867c30e7a198911ba`
and `7dd71710d60017224fd1f6fabd97f228642b687802da98a11f8927aea67b6485`.
Both bind parent node `025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d`
and capped worker `4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc`.
Their runner digests are `1cd9bfe3418616add2319802adc4caf66b86e3f6fdf6c903c4be2648b10c0baa`
and `fb41a1193c86749db27ef609f487a25de334a7e58b3440093288aecc75ae4801`.
Runtime is Solana v1.6.16, revision `86c26f843276581509c3434acc2efbf4202c44e0`.
The unchanged node generation is
`jetstreamer-node/0.7.0/old-faithful-to-horizon-v2@3de96e71010a8a2f5e629f666227b137483bff7b`;
the same sealed node's generation binding is retained in the qualified 203
continuation scope, not replaced by this worktree's current build revision.

The 204 sealed `epoch204-incomplete-span-blocker.json` in
`horizon-focused-204-complete-span-store8-ca2e38b-v1`, SHA256
`be015943dc8812566ad5417c25eba25f79ac0f3ea4834f9ce0d9cedba6adaeeb`,
independently records the canonical 432000-slot epoch and the historical plugin
rejection of its 638-slot deficit. A registry end of 88560000 never repaired
that deficit or granted publication. The 205 immutable preparation below
records canonical end 88991999 and 949 missing slots. Both also agree with the
canonical arithmetic `(epoch + 1) * 432000 - 1`. Prefix counts remain 431362
and 431051; do not rewrite either as a complete epoch.

## Reusable inputs and incompatible older routes

204's existing bootstrap is slot 88127580, accounts root
`4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf`, compressed SHA256
`d3114597ce25c3efaa4a96899ab3e9437c51cb9086d4166639f0ad2ae0613ee6`.
205's existing bootstrap at 88559361 is exactly the prospective 204 tail
snapshot: accounts root `83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA`,
8,225,957,010 compressed bytes, SHA256
`24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e`,
retained in `/var/lib/jetstreamer/horizon-focused-205-store8-3de96e7-v1`.
Its generation-bound GCS identity is preserved by `snapshot-bindings-205.json`
(SHA256 `06dc3b7beb14bbb943fa3c92e663548b94e897ee3b574734a2d629a07befa029`).

The prospective 205 tail snapshot at 88991050 has accounts root
`BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp`, 8,407,269,066 bytes and
SHA256 `1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f`.
The immutable package is `/var/lib/jetstreamer/horizon-terminal205-input-e94ae66-v1`.
The preparer's source binds GCS generation 1634790073611030; compressed input
custody alone is not native initialization proof.

`/var/lib/jetstreamer/horizon-native205-restore-prepared-d0780f0-v1/preparation.json`,
SHA256 `0d0e3f475bde6badd7475b29efe68f361d39251afa2d1e16714be41353dc7daf`,
is explicitly **not executed** and grants no suffix/assembly authority. Its
probe binds the older `3f5e8efe...` worker, the older
`qualification-205-prefix-store8-v1` pathname and a different generation
expectation. It cannot read or qualify the current capped producer by changing
its JSON or forwarding a new prefix path. Keep that package unchanged.

The preserved 204 complete-span epoch-hashes input has SHA256
`e8cd76bc5193fc19f3cb9acb3cac349d8e4acf055edd03b132efe4df3f011b3d`;
the active cropped prefix input has SHA256
`50475cb66daf0a5126a23fa7f84b7ed5f95718d5b866c258860b71d5b624feec`.
205's bound epoch-hashes file has SHA256
`09cd3c3a244aed0bea058453eaf68dedd6b5587934427ecfacc553dab1a5e65b`.
Future tail preparation must positively qualify actual tail metadata through
88559999/88991999, not assume a filename or prefix input contains it. This
review did not parse those potentially large inputs or scan either archive.

## Smallest missing source path implemented

The current independent qualification reader had an exact capped 203 path and
exact native 20/25 profiles for 223, but neither current capped 204/205 output
name was admitted. New `qualification_verify/prefix204205.rs` adds only those
two exact private roots, `output/epoch-N-prefix.jet`, original capped worker,
Solana revision/generation, bootstrap/output/terminal slots and the two known
snapshot accounts roots. A namespace guard also rejects the generic
`epoch-N-through-SLOT.jet` fallback when these roots are misspelled or their
scope is changed. Complete canonical filenames and sidecar creation remain
outside this reader.

The existing full `read_and_validate_segment_manifest` path still hashes and
deeply validates the entire original archive, typed manifest and account-update
semantics; before/after identities, private ownership and absent canonical
sidecar requirements are unchanged. Successful receipts explicitly deny native
restart, complete-epoch coverage, assembly, runtime promotion and publication.
The known accounts roots are independent; the reader does **not** claim an
independently known canonical terminal Bank hash. Every raw Bank/checkpoint
integer and write cursor remains in the original typed manifest and its
semantic digest, for the actual native full-tuple comparison later.

After natural producer success and actual manifest closure, the reader's
argument template is its original archive positional argument followed by:

```
--private-root=/home/ubuntu/.jetstreamer-private/shrink-root-prefix-resource-EPOCH-PROFILE-v1
--expected-epoch=EPOCH
--expected-output-start-slot=START
--expected-bootstrap-slot=BOOTSTRAP
--expected-terminal-slot=TERMINAL
--expected-runtime-profile=solana-v1.6.16
--expected-worker-sha256=4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc
--receipt=EXACT_PRIVATE_NO_CLOBBER_RECEIPT.validation.json
```

Use the exact table/scope above, not literal template labels. Build/seal the
actual reader only after the shared Cargo window and qualify its sandboxed
read path. Do not schedule an archive read while either healthy writer is
still active. Preserve original producer completion and successful PID1 raw
history, exact original IID/PID/command, original segment and actual reader
receipt as separate artifacts. A completed producer alone is not an independent
reread, and a reader success is not native suffix admission.

## Concrete remaining gates to the canonical sidecar

1. **Completion and reread dispatch:** add/reuse a closed terminal-history and
   source-idle adapter for these exact units and IIDs, including collected-unit
   history, zero restarts and complete process/cgroup/reference checks. Keep
   existing producers/guards unchanged. `bounded_resource_runner` already
   writes original natural-success/manifest evidence; consume it rather than
   rerunning a Bank merely to change its evidence format. No future terminal,
   manifest digest or reader receipt is predicted here.
2. **Native inputs/admission:** qualify exact new capped-worker profiles for
   each real prefix manifest, independent reread and retained terminal snapshot.
   Include genesis, full raw snapshot hash, original generation and prefix
   bootstrap/terminal tuples. Existing 205 preparation is useful input custody,
   not a compatible native comparator. Fresh capacity must protect every actual
   owner, effective internal/external floor, output growth and admission/guard
   metadata; the historical cycle 353 sample is not a future admission. Bind
   isolated zero-restart persistent owners and qualified reserve/VMA guards
   before any future native restore or suffix execution.
3. **Actual suffix barrier and execution:** in the worker that executes slots
   88559362..88559999 or 88991051..88991999, compare native slot, Bank hash,
   accounts hash/kind, last blockhash, capitalization, transaction count, tick
   height and complete-slot state with the real verified prefix terminal before
   any entry. Require zero bootstrap writes and exact unchanged capped worker.
   No previous restore-only probe substitutes for this actual barrier. Preserve
   validator-local initialized write cursors as raw integers; do not force them
   to equal the prefix cursor. Require exact block/entry/tick metadata and final
   canonical boundary hashes; no zero-filled slots or synthetic metadata.
4. **Private assembly/provenance:** prefer the already qualified 203 same-worker
   V4 restart algorithms, generalized only through new closed 204/205 profiles
   and fixtures. V4 requires exact same runtime identity **including worker
   executable hash**. Reusing the older `3f5e8efe...` worker is not equivalent.
   The 223 V3 route supplies useful shared metadata/checkpoint, normalization,
   merge, source-idle and admission patterns; its fixed native 20/native 25
   identities and cross-runtime authority do not admit either epoch here.
   Bind original source hashes, complete PoH/slot coverage, raw independent
   write intervals and checked normalization arithmetic. Preserve distinct
   source generations rather than projecting restart provenance into V1/V2.
5. **Independent final/current-plugin route:** independently derive expected V4
   provenance from original manifests and actual restart evidence. Full-scan
   the private canonical-name assembled bytes with initial adjacent anchors
   88127999/88559999 and final terminals 88559999/88991999 respectively, each
   bound to independently qualified actual hashes. Run the current plugin over
   those exact same bytes, binding final digest, archive identity, provenance
   expectation, tool versions and durable logs/receipts. Do not trust a digest
   copied only from the assembled header or reuse a prefix-only plugin receipt.
6. **Import/publication/delivery:** qualify exact per-epoch V4 import/publication
   adapters (the fixed 203 publisher cannot publish these epochs). Only after
   independent full and current-plugin gates may a canonical local pair become
   eligible. Receipt-gated Rust R2 delivery uploads and whole-object-verifies
   the .jet, revalidates its source, then commits the canonical .sha256 sidecar;
   authenticated ready-pair proof precedes status cleanup. Adjacent-boundary
   receipts separately gate local retirement, not the remote upload. Preserve
   active post-replay status ownership and include this complete route in ETA;
   a plan or temporary terminal event does not release capacity claims.

## Qualification state

Two dependency-free Rust profile regression tests pass with `-D warnings`,
covering both counts/tails, exact roots/paths, worker/runtime/revision/generation,
root identities and malformed/generic-name fallback rejection. The complete reader CLI integration suite now passes: 25 release tests,
including the real 204/205 argument-routing regression, deep artifact validation,
and all prior 203/223/225 profiles. Strict production Clippy passes with
`-D warnings`. Rustfmt and `git diff --check` pass. Cargo was used only after
agent 223 released its lease, with the shared target and two compiler jobs.
No reader was deployed or run against a real archive.

The next implementation is a new closed 204/205 continuation adapter using the
203 V4 algorithms, not a relaxation of that frozen 203 profile. First add a
metadata-only input-policy validator binding each original launch/IID, actual
natural completion/PID1 proof, original full typed manifest and actual independent
reader receipt to its retained terminal snapshot and exact capped worker. The
future suffix driver must perform the actual snapshot initialize/freeze/full-tuple
comparison before any replay entry, retain its own raw cursor, then execute only
the 638/949 slots and build independently validated V4 provenance. A separate
restore-only Bank run is not required merely to reformat evidence; existing
valid actual native evidence should be consumed when applicable, while the
actual suffix worker's own pre-entry comparison remains mandatory. Fresh native
admission/guard and complete verification/import/publication paths remain
independent gates. The already prepared 205 comparator remains incompatible
with these current producer identities and is not silently repurposed.

The source reader integration and future operational path remain unsealed;
there is no claim that these two prefixes are ready for publication.

## Closed native-input and V4 adapters

The isolated `epoch204205-native-completion` source adds the metadata-only
`jetstreamer-capped204205-native-input` CLI and the
`jetstreamer_node::capped_prefix204205` library. Existing 203 continuation,
older 205 restore-only preparation, workers, readers and producers are unchanged.

The CLI accepts a separately hash-bound root-owned immutable plan and its own
executable SHA-256. Its explicit `--check-only` mode validates only the static
plan, without reading primary evidence, inspecting a snapshot or writing output.
Normal preparation requires the exact original launch path and raw launch hash
above, original runner natural-success result, captured terminal properties,
preserved PID1 manager history, full typed prefix manifest and actual independent
reader receipt. Every small evidence input is individually hash bound and
immutable; no prefix archive body is opened. The reader must bind the complete
typed manifest's semantic digest, original archive path/hash/size, candidate
runtime and prefix coverage. A rewritten tuple cannot borrow an old archive SHA
or the incompatible older 205 reader/preparation.

Both loaded clean-terminal and genuinely collected-unit property shapes are
supported, with exact original PID/IID/command and original PID1 start/success
history as applicable. Manager stop, failure or replacement history fails closed.
The original runner must report natural child exit zero, no external signal,
the exact typed manifest and raw manifest digest, and no independently qualified
or publication authority. A normalized target-stop benchmark cannot satisfy it.

The tool rehashes the fixed worker and genesis, and inspects the exact cached
snapshot's canonical readonly root-owned file metadata and compressed size. It
does **not** reread the 8-GB snapshot body: the future actual native worker must
still hash and bind the complete snapshot immediately before initialization.
It writes only an owner-read-only, no-clobber, idempotent private
`native-input-policy.json` below
`/var/lib/jetstreamer/horizon-capped-native-input-EPOCH-UNIQUE/`. Plan/source
inputs may not overlap that output namespace. Prepared metadata explicitly
denies current source-idleness proof, fresh resource admission, native
initialization, suffix execution, assembly, sidecar, publication and R2 authority.

`InputPolicy::native_barrier` is the actual-worker adapter: call it with the
executing worker's initialize/freeze result before sending any entry. It checks
the exact capped worker, legacy accounts-hash kind, slot, Bank/accounts/last-block
hashes, capitalization, transaction count, tick height and complete-slot state.
Bootstrap writes must be zero, ticks per slot 64, and the actual raw cursor must
equal the worker's initialized cursor. It deliberately does not force the native
cursor to equal the prefix cursor. There is no deserializer that converts an
older restore-only JSON result into this barrier token.

`NativeBarrier::provenance` builds only the exact same-worker 204/205 V4 scopes,
with the real 638/949 slots, original prefix generation and independently
recorded suffix generation. It binds the exact snapshot handoff, full native
tuple and raw initialized cursor, preserves both raw write intervals, and uses
checked normalization arithmetic. It rejects foreign workers/runtimes, a
different bootstrap cursor, omitted slots and overflow. `assemble` supplies
the actual handles, authenticated source digests and observed terminal block
hashes to the existing `merge_checkpoint_restart_segments` algorithm, which
independently verifies source bytes, dense coverage, PoH, source metadata and
raw writes. The caller supplies an already admitted guarded sink and the actual
source metadata policy; a different metadata policy cannot pass the merger.
No source file is opened, appended, replaced or retired by this adapter.

The persistent suffix controller and its exact actual-worker pre-entry hook
remain a separate source integration gate. It must reauthenticate these inputs,
prove complete current process/cgroup/reference closure, admit and protect all
restore/suffix/assembly overlap, fully rehash the snapshot, and invoke the native
barrier before any replay entry. Known-root reader completion or prepared input
metadata does not authorize that run. Final boundary/full/current-plugin,
exact V4 import/publication and authenticated R2/sidecar gates remain unchanged.

Initial targeted qualification passed all nine library adapter cases, including
in-memory real-width V4 merges for both complete 432000-slot epochs, full native
tuple rejection, independent cursors above JavaScript's exact-integer range and
normalization overflow. The initial two CLI scope/argument tests passed. Final
CLI fixture lifecycle tests, the full library suite, strict Clippy and a review
binary build are pending the shared Cargo lease after agent 227. No live source
read, host poll, Bank run, service action or R2 mutation occurred.

## Persistent closed continuation source integration

The later source integration adds the exclusive node feature
`capped204205-checkpoint-continuation-diagnostic`, dispatched through the existing
`--checkpoint-continuation-plan=PATH` and
`--checkpoint-continuation-plan-sha256=SHA` options. Its only legal invocation
selects exactly epoch 204 or exactly epoch 205, one explicit `--verify` and the
plan's explicit private `ledger` destination. It cannot reach ordinary replay,
recovery, a public destination or checksum creation. Combining another diagnostic
or qualification feature fails at compile time. The frozen 203/213 continuations
and older 205 restore-only preparation are unchanged.

`capped_control204205::{Plan, Metadata, Bound}` defines the strict input contract.
The plan includes actual future prefix/capture/reader digests, a newly built node
digest, the independent guard digest and isolated producer/guard names. No
future manifest, terminal success or positive admission is manufactured. All
metadata is reauthenticated from the original launch, natural runner result,
terminal properties, PID1 history, typed manifest and independent full-reader
receipt. Root-private evidence must first be copied unchanged into a root-owned,
immutable package that UID 1000 can traverse/read. A copied original launch is
accepted only by its exact original raw hash; it retains its original identities.
Keep the original package and evidence untouched.

The separate `jetstreamer-capped204205-control` binary has three explicit modes:

```
control capture CAPTURE_PLAN --plan-sha256 SHA --self-sha256 SHA
control validate-plan CONTINUATION_PLAN --plan-sha256 SHA --self-sha256 SHA
control guard CONTINUATION_PLAN --plan-sha256 SHA --self-sha256 SHA --producer-iid ACTUAL_IID
```

All modes require root, a separately sealed immutable plan and their actual
executable hash. The capture mode consumes real already captured terminal/reader
evidence, then reuses the reviewed complete manager/job, descendant-cgroup and
process-reference closure algorithm for only the exact original 204/205 owners.
It scans the entire original root. Only after natural success and current
idleness does it freeze the original archive and manifest as root-owned readonly
files, without rewriting their content. It checks original identities again
after a second complete idle census, and emits a no-clobber `source-capture.json`
in `/var/lib/jetstreamer/horizon-capped-capture-EPOCH-UNIQUE/`. This source capture
does not read an archive body, claim native initialization, publish or retire.
The original archive descriptor remains open and its captured identity is checked
through the later executing producer's full reread and assembly.

`validate-plan` is the source admission precondition exposed to the separate R2
resource emitter. It returns a bounded (64-KiB maximum)
`jetstreamer-capped204205-admission-inputs-v1` object containing the complete
typed proposal, rederived metadata policy, actual frozen source and retained
snapshot identities, and a current whole-original-root lifecycle idle proof.
It checks only retained snapshot metadata and small executable/genesis hashes;
it reads no archive/snapshot body, takes no resource sample and writes nothing.
The emitter may call it once before and once after its real admission transaction.
It grants neither resource admission nor native/suffix/guard authority.

The producer requires a root-immutable fresh admission at the plan's
`admission_receipt` path, published **after the final plan is sealed**. The receipt
binds that actual plan hash, source-capture hash, all exact package identities,
full existing protected floor and the incremental restore/suffix/validation/
assembly envelope. Using a path here avoids a circular plan/admission hash pair.
The receipt binds a real immutable fleet observation whose bytes the producer
also authenticates. Age is at most 15 minutes; full-path initial free space must
still fit. A minimum 256-GiB experiment envelope is not an observed peak or
automatic admission. The actual fleet review must protect every current owner,
effective internal/external guard, remaining output growth and overlapping phase.
The admission also binds an immutable `resource_proposal` and numeric
`kernel_limits`: requested memory max/high, swap max zero, tasks, CPU quota in
microseconds per second, and maximum runtime in microseconds. These must come
from qualified whole-path sandbox/resource evidence, not from an initial RSS
guess. The guard checks exact requested manager limits, kernel page-rounded
memory caps, swap, pids limit and CPU quota/period ratio. Raw D-Bus integer
properties bind actual `RuntimeMaxUSec` and `CPUQuotaPerSecUSec` without parsing
humanized systemctl time strings.

Before any archive-body reread or Bank restore, the fresh UID-1000 producer
publishes `continuation-phase.json` and waits up to 90 seconds for a real first
fire of its independent, non-restarting root guard. The guard authenticates its
own persistent unit and the actual supplied producer invocation, then checks
the exact node and worker mapped executable identities, complete producer cgroup,
whole-lane process RSS, worker VMA ceiling, protected disk floor and the complete
own-root physical ceiling. Executable hashes are measured once, with original
identities rechecked on every sample. Unknown cgroup processes fail closed.
The physical scan reuses the existing descriptor-relative guard algorithm.
The complete process census is bracketed by sorted exact cgroup PID sets. After
all per-process reads, every recorded PID/start/executable/mapped-inode identity
is revalidated together; executable descriptors remain open through this check.
A worker appearing late, an earlier PID reused during a later read, incomplete
records or an executable replacement fails closed. Churn shares a bounded
three-attempt retry with stable phase sampling. No observer binary from this
older branch is a replacement for the separately deployed 42bac936-based observer.

Workerless work is allowed only in the closed finite stages `waiting_for_guard`,
`prefix_validation`, `suffix_validation`, `assembly` and `complete`.
`native_restore` includes the exact worker's restore and suffix execution.
Producer transitions are sequential; observed guard phases cannot rewind or
renew the same stage's absolute deadline. Phase and process censuses are retried
together across normal stage changes or disappearing worker PIDs. This does not
add a blanket workerless exemption to the existing standalone guard.

The guard publishes root-owned readonly atomic heartbeats plus an immutable first
fire; a trip creates an immutable stop intent and stops only the still-bound
producer. A producer watchdog rejects a guard invocation change, stop intent or
heartbeat older than 60 seconds, and exits even if an archive read is stalled.
Its required `KillMode=control-group` reaps the worker. These protective guard
checks are separate from the unchanged 30-minute campaign observation cadence.
Precreate the guard's unique directory root-owned and readable/traversable by
UID 1000, with no group/other write permission; the run root stays UID-1000/0700.
Both service definitions explicitly use `Restart=no`, `KillMode=control-group`,
`Delegate=no`; the producer uses `User=ubuntu`, the guard `User=root`.

The actual suffix path performs a fresh complete prefix reread, starts the exact
retained snapshot with its full hash/size pinned, and invokes the new native
barrier from the existing worker's actual pre-entry `RestartProof` hook. It
records the actual independent initialized cursor in memory; it never restores
authority by deserializing an older native JSON. It executes only the 638 or 949
slots, writes and independently reads the actual suffix manifest, reconstructs
V4 from that same actual barrier and writes a durable private suffix receipt
**before** beginning assembly. A separately admitted guarded no-clobber sink
feeds the reviewed V4 merger. Source descriptors and path identities, complete
metadata/PoH/raw-write checks and absent canonical checksums remain mandatory.

An assembly failure preserves the completed suffix, source prefix and all
private receipts. It does not grant an unqualified assembly-only restart; a
future resume adapter must authenticate that actual prior producer's terminal
history and suffix/native receipt rather than reconstructing execution authority
from arbitrary JSON. Final/current-plugin verification, independent adjacent
boundary anchors, exact per-epoch V4 import and canonical publication adapters
remain separate from this private native-suffix source integration.

At this source checkpoint, edition-2024 formatting and diff whitespace checks
pass. The new controller/guard/capture fixtures have not yet run: the shared Cargo
lease is held by other campaign work. The earlier 122 library plus four native
input CLI tests remain the last completed suite; their source is preserved, and
the terminal PID Clippy correction parses the property string as `u64`. Do not
deploy, call these fixtures passed, or claim strict Clippy/release-build success
until the new exclusive build and relevant tests are actually qualified.

The exact remaining source dependency is the fresh full-fleet admission emitter
for `jetstreamer-capped204205-continuation-admission-v1`; its validator and frozen
plan/receipt contract are now present in `capped_control204205.rs`. The next
source action is to connect actual fleet/growth/guard evidence to that emitter,
then exercise its output against this validator. This is owned by the separate
admission agent; no positive receipt is emitted from a plan or old observation.
