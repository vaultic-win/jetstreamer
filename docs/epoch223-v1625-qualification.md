# Private epoch-223 v1.6.25 candidate

This opt-in candidate investigates one-runtime completion of epoch 223. The
v1.6.20 restart-marker correction does not establish that its known failure at
96,767,526 is repaired. Existing v1.6.25 epoch-224 warmup ran beyond that slot,
but recorded no epoch-223 tail archive. Do not repeat a long v1.6.20 run or
pretend the old epoch-224 artifact contains those missing writes.

The cold known-root prefix attempt `5c5a9e56…` subsequently failed on
2026-10-23 during pre-output warmup from snapshot 96,335,538: the batch spanning
slot 96,335,539 entry 515 through slot 96,335,541 entry 5 returned
`InvalidWritableAccount` from fee collection. Snapshot restore/freeze success and
the later 477-slot tail comparison therefore do not qualify v1.6.25 for this
whole prefix. The vendored v1.6.25 account loader adds writable executable and
upgradeable-owned account rejection checks absent from v1.6.20; identifying
that difference is not yet proof of the exact transaction's cause. Preserve the
failure, inspect the canonical transaction and account state, and qualify the
correct historical prefix/restart route before retrying. Do not suppress the
error or weaken SourceExact, checkpoint, or publication checks.

Build both the historical v1.6.25 worker and parent with only
`epoch223-v1-6-25-qualification`. Their ordinary default routes are unchanged.
The parent identifies the exact upstream v1.6.25 revision, executable and
environment override. The candidate accepts only focused epoch 223 in one
isolated `qualification-223-v1625-*` private root, explicit verification,
snapshot/checkpoint inputs, and an exact full/tail terminal of 96,767,999 or
the separately namespaced known-root prefix described below. Ordinary
replay, root cohorts, recovery, inherited leases, and early maintenance/recovery
entrypoints are rejected before they can touch artifacts. Existing generic
filesystem-only checks reject aliased private roots/children; no epoch-225
launch or assembly policy is reused.

Two exact snapshot slots are admitted:

- **96,767,522**: first run the small 477-slot tail comparison through
  96,767,999, covering the known 96,767,526 vote. This is not a complete epoch,
  checkpoint-continuation qualification, or publishable artifact.
- **96,335,538**: the cold candidate remains dormant even after a successful
  tail comparison and sufficient resources. The retained checkpoint input
  binds this snapshot and the 96,767,522 root, but not the required full-epoch
  terminal at 96,767,999. Replay would start at 96,335,539 and full output at
  96,336,000; do not launch that 432,000-slot path with a bootstrap-only policy
  or infer its terminal commitment from the private tail result.

The initial parent attempt stopped before worker spawn because ordinary
focused qualification correctly requires an independently known terminal root;
none is supplied at 96,767,999. Keep that gate unchanged. The separate explicit
`--epoch223-tail-comparison` mode is restricted to the 477-slot tail and its
private `qualification-223-v1625-tail-*` namespace. It binds the canonical
bootstrap, rejects invented post-bootstrap expectations, retains SourceExact
transaction checks, and records an unqualified terminal checkpoint. It does
not qualify a cold prefix or authorize publication. Cold focused qualification
still requires a trusted terminal root or a separately reviewed later-root
verification/continuation route; this flag cannot make a cold run pass.

The private prefix route is a cold prefix ending at the
known 96,767,522 root, followed by an independently qualified native restart
and the remaining 477 slots. Such a prefix would replay 431,984 slots including
warmup and record 431,523 epoch slots. The existing checkpoint rules accept the
two known commitments for that span. The isolated CLI admits only this exact
prefix span in an exclusive `qualification-223-v1625-prefix-*` root. That
namespace cannot request the tail, a full epoch, recovery or a cohort; the tail
comparison flag cannot bypass its ordinary terminal-checkpoint gate. Both the
cold bootstrap and terminal accounts commitments are independently pinned in
the prefix expectation validator. Default builds and full-cold terminal rules
are unchanged. This source route is not a staged launch or resource approval:
it still needs exact-package capability and closed worker bounds, real cold-snapshot
qualification, a qualified full-prefix
reread, the exact native restart tuple and independent write-cursor mapping,
private assembly/provenance and full/plugin/publication gates. A short-tail
resource measurement is not a full-prefix peak bound. Preserve every existing
artifact and do not treat the current diagnostic tail as a reusable qualified
suffix before those obligations are proven.

The separately opt-in `epoch223-root-prefix-resource` utility profile pins
the separately preflight-capable parent `90474659…`, unchanged worker `fde3ba53…`, cold
snapshot `301110ca…`, two Rayon threads and natural parent completion at
96,767,522. It cannot run the 477-slot tail or request the unknown full-epoch
terminal. Both bootstrap and terminal Bank/accounts commitments, exact output
coverage and absent sidecar are required in its producer manifest. A progress
line alone never completes the attempt. The existing epoch 203 profiles retain
their own compile-bound scope and are not replaced.

Its 72-hour runtime and 1,280-GiB terminal scratch bounds are diagnostic caps,
not measured full-prefix peak qualification. Fresh admission must reserve the
complete conservative 1,536-GiB incremental envelope (scratch plus archive and
buffers), all older live growth, and the current century floor. Its startup
minimum of 2,584,751,391,635 bytes is only a rejection baseline: thirteen-sample
floor 248,289,182,611 + unchanged 225 growth 640 GiB + candidate 1536 GiB. It does
not account for a still-live203 owner; do not launch before fresh full-fleet
admission proves every claim fits. Bind the exact producer to a proven actual
free-space/VMA guard, protecting older claims. No new launch, guard or automatic
admission trigger is installed merely by adding this utility. Preserve the
existing 203/225 workers and their guards. After natural success, independently
reread the prefix; producer success still grants no restart, assembly, complete
epoch, plugin, canonical-sidecar or publication authority.

The fleet's distinct `jetstreamer-private-epoch223-known-root-prefix-launch-v1`
contract registers only the fixed cold-prefix resource supervisor, readable
sealed plan, exact parent/worker/input digests and the real prefix capability
receipt. It never reuses the 477-slot tail contract. It retains the failed
incident state and labels live work `private-known-root-prefix`, without a
sidecar countdown or complete-epoch authority. Its same-observation admission
requires the exact nested scratch path and the real one-worker first-fire guard.

For the first prefix attempt, the original 203producer's clean natural terminal
and independently reread prefix are preserved in
`horizon-prefix203-terminal-independent-evidence-v1`. The fleet authenticates
that exact terminal handoff receipt before accepting release of its old 960 GiB
remaining-growth claim; this does not qualify 203's suffix or any new 203work.
Admission still reserves the unchanged 225640 GiB, the full 2231536 GiB trial and
the thirteen-sample century floor: 2,584,751,391,635 bytes. The 223 guard protects
225 plus a64 GiB buffer and that floor: 1,004,203,426,707 bytes. No entry launch
is granted by registration, capability, cache cleanup or terminal 203evidence
alone: require fresh full-fleet/resource admission and a proved invocation guard.

The independent reader has a separate closed prefix profile for
`qualification-223-v1625-prefix-*/output/epoch-223.jet`, output slots
96,336,000–96,767,522, the exact candidate worker digest and upstream revision.
It requires both independently preserved accounts and Bank commitments: cold
Bank `8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F` and terminal
Bank `EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB` alongside the
two checkpoint accounts hashes. It cannot fall back to generic through-slot
naming when any bound differs. The complete independent reread retains absent
canonical sidecars and explicitly denies full-epoch, native-restart, assembly,
peak, runtime-promotion and publication authority. Passing it does not qualify
the complete prefix-to-sidecar path.

Before replay, use the same tail arguments plus `--epoch223-tail-preflight`
against the exact sealed parent. It must reach the post-bootstrap planning
stage, report the actual v1.6.25 descriptor/revision/worker and the explicit
partial policy, then return without spawning a worker or creating an archive.
Preflight requires preseeded regular genesis, forbids ledger extraction and
performs no download. It is not snapshot-content verification or admission.
Capability probes that stop at a missing snapshot do not prove this later gate.
The second attempt exposed another gate inside the actual replay entrypoint:
candidate execution also requires a trusted post-bootstrap checkpoint. The
first preflight returned before that check. Its schema-v1 report therefore
does not prove readiness to reach a worker. The revised schema-v2 preflight
runs through the actual replay entrypoint and returns a distinct planning-only
outcome at the real pre-worker barrier, after shared runtime/checkpoint and
handoff validations. Only its exact explicit private 477-slot comparison may
run with the known bootstrap alone; ordinary, cold, carried/cohort and restart
paths retain their existing post-bootstrap obligations. Never turn a planning
outcome into completion or construct a fictitious terminal expectation.
The static audit also found the compiled IPC worker-profile identity had not
included the epoch 223 feature in its v1.6.25 overrides, although the registry
descriptor already did. Bind and test both identities. The pre-worker report
must now validate that profile and resolve its worker executable as well.
The old static era label includes v1.6.20; the selected descriptor is v1.6.25,
as asserted by the actual bootstrap-selector regression and new preflight.

The distinct `--epoch223-prefix-preflight` flag admits only the exact cold
prefix 96335538..96767522 and its prefix namespace. It cannot be combined with
either tail flag. It retains both independent checkpoint obligations and
returns a `jetstreamer-private-epoch223-prefix-planning-preflight-v1` report
only at the actual replay entrypoint's pre-worker barrier. Like tail preflight,
it requires preseeded genesis, forbids ledger extraction and performs no worker
spawn, entries or archive creation. It is package capability evidence, never
snapshot-content verification or resource admission. A rebuilt parent needs
new immutable digest bindings before any supervisor may use it; do not edit
the older sealed package or treat its tail-only flag as prefix capability.

`jetstreamer-epoch223-prefix-capability` is a separate closed Rust checker for
`horizon-223-prefix-preflight-a928381d-v1` and parent `90474659…`. It rehashes
the complete native-sealed package before and after the real no-worker probe,
including the unchanged cold snapshot and worker, and validates one exact
prefix preflight report with every non-authorizing field. It creates a fresh
private prefix-capability root, preseeds and rehashes genesis in ledger/output,
drops supplementary groups then GID/UID1000 before executing the parent, and
rejects any archive or sidecar in its bounded artifact census. Run only as a
persistent root oneshot with the minimal DAC_OVERRIDE/CHOWN/SETUID/SETGID
capabilities, a private network, read-only home/package and exact writable
probe/receipt paths. Its native-sealed immutable plan and self-digests remain
independent inputs. Successful capability evidence proves no snapshot contents,
resource admission, prefix replay, restart, assembly or publication. The prior
tail checker keeps its own fixed package and report scope; only its unchanged
immutable-file/persistence/artifact-census primitives are shared internally.

The new worker feature restores the two future restart markers 96,542,804 and
96,542,805 using the same native algorithm tested in the v1.6.20 correction.
It validates the full four-marker list before mutation, requires every already
applied marker, and never increments an existing marker. The actual retained
pre/post snapshot metadata and their independently hashed inputs are described
in `epoch223-hard-fork-metadata.md`. Feature-specific tests also bind exact
snapshot and entry limits; no input at or beyond 96,768,000 is accepted.

For the existing ignored snapshot-load and runtime-initialization tests, bind
`JETSTREAMER_V1_6_25_EPOCH223_TEST_ANCHOR` to the exact selected cold or tail
slot and bind the corresponding independently hashed snapshot path. The default
test anchor is the cold snapshot; arbitrary anchors are rejected. This test-only
selector cannot change production snapshot or entry bounds. Run the two real
snapshot tests separately from the serial synthetic suite, under fresh resource
admission and the pinned historical workspace/toolchain.

Before any launch, require source/tests/normal SSH push, a new native-sealed
package, exact-node capability and real-snapshot verification, complete fresh
admission, disjoint ownership, isolated output, and invocation-bound disk/VMA
guard with its first successful sandboxed fire. Keep older growth claims and
guard floors unchanged. Do not use an unavailable observer receipt for
admission or start a new resource poll inside the 30-minute cadence.

Focused outputs stay private and receive no canonical checksum. Tail success
does not qualify the cold prefix; a source build or transaction-status match
does not prove a canonical checkpoint. No registry promotion, canonical sidecar,
archive import, R2 upload or retirement is authorized until the complete
candidate passes all independent qualification, current-plugin and publication
gates. Preserve the original failed invocation/partial and keep the repair open
until epoch 223 reaches a verified R2 ready pair.

The shared RAM-only snapshot supervisor has a distinct
`epoch223-tail-snapshot-tests` build profile, incompatible with its epoch 225
and released-CPU profiles. It accepts only the exact sealed epoch 223 test
harness and tail snapshot, its own plan/unit/receipt namespaces, and the
complete fresh 201–300 fleet with the unchanged live epoch 203/225 identities.
The 13 independently established canonical size samples bind the century
floor to 248,289,182,611 bytes. A changed census requires a reviewed update.

Its separate `epoch223-cold-snapshot-tests` build accepts only the sealed cold
snapshot in `horizon-223-known-root-prefix-b1670f57-v1`, SHA-256
`301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665`,
9,815,262,303 bytes, and test anchor 96,335,538. It reuses the unchanged
optimized epoch 223 harness, not the tail input or tail plan. Plans use schema
`jetstreamer-private-epoch223-cold-ram-snapshot-test-plan-v1`, units
`archive-223-cold-snapshot-test-*`, and receipts `ram-snapshot-test-223-cold-*`.
Cold and tail profiles cannot be compiled together or borrow one another's
schema, input hashes, names or result schema. Both keep identical memory,
tmpfs, task, CPU, credential-drop, full-fleet and century-floor gates. They
run no entries and grant no prefix replay, restart, assembly or publication
authority. Run the cold capability proof and then the two actual tests only
after fresh coordinated observation and matching complete fleet evidence.
The fleet reconciler's closed `private-cold-snapshot-verification` role binds
the exact actual-test unit, immutable plan and supervisor digest to the
Rust-generated durable test intent. While live it remains private qualification
with no sidecar ETA, and epoch 223 stays in `failed-needs-repair`. It never
relabels a snapshot test as an ordinary replay or post-replay delivery stage.

Run its capability mode under the same actual sandbox before snapshot mode.
The supervisor requires private 512-GiB tmpfs with 1,048,576 inodes, 128-GiB
memory maximum, 112-GiB memory high, no swap, eight-core CPU quota and 512
tasks. Only its exact root-private receipt directory is host-writable.
The child drops to UID/GID1000 with no supplementary groups/capabilities,
has no network, and runs exactly the two ignored load/initialize tests with
anchor 96,767,522, 128-MiB test stack and two Solana Rayon threads. Its
prebuilt harness was compiled in the historical workspace with Rust 1.51;
the runtime working directory is private tmpfs, never the mutable workspace.

Fresh sampled and actual available memory must cover the 448-GiB host stop
reserve plus the full 128-GiB test cap. The existing bound supervisor enforces
its 30-minute runtime cap and memory/tmpfs reserve during the child and
fsyncs cgroup counters before exit. This RAM-only check neither reduces disk
growth claims nor creates replay output, canonical sidecars or publication
authority. A successful snapshot check is still not a tail replay or a cold
epoch qualification.

Use the optimized (`cargo test --release`) epoch 223 test harness for new
snapshot checks. The previous epoch 225 debug attempt exhausted its 30-minute
bound before finishing the first test; its optimized counterpart passed both
checks within the same bounds. Epoch 223's initial debug attempt remains
independently sealed and supervised. Prepare a distinct optimized package and
attempt instead of changing its executable, extending its timeout, or treating
a timeout as a canonical mismatch. The optimized harness has the same source,
feature and assertions, with 60 synthetic tests plus IPC passing; it still
requires the two real snapshot tests. The replacement profile rejects the old
debug digest and binds a distinct immutable release-harness directory.

After natural completion of the 477-slot replay, independently reread its
archive with the separately sealed `jetstreamer-qualification-verify` reader.
Its closed epoch223-tail profile accepts only the exact private
`qualification-223-v1625-tail-*` root, `output/epoch-223.jet`, bootstrap
96,767,522, output 96,767,523–96,767,999, v1.6.25 and candidate worker digest
`fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c`.
It binds bootstrap accounts hash `3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7`,
serialized/frozen Bank hash `EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB`
and upstream revision `7de8a55b54d3e11058b82f9483bb405d143b455c`.
The reserved tail namespace cannot escape into generic through-slot naming.
Use the durable segment's exact output start/count, require full independent
archive/manifest validation and absent canonical sidecar, and retain the
normal private receipt identity/durability checks. Its receipt explicitly
denies complete-epoch coverage, canonical-prefix/peak qualification, a known
independent terminal root, runtime promotion, sidecars and publication. A
successful tail reread remains evidence only; no production plugin or R2
upload is authorized for this partial artifact.
