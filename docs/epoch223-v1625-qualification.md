# Private epoch-223 v1.6.25 candidate

This opt-in candidate investigates one-runtime completion of epoch 223. The
v1.6.20 restart-marker correction does not establish that its known failure at
96,767,526 is repaired. Existing v1.6.25 epoch-224 warmup ran beyond that slot,
but recorded no epoch-223 tail archive. Do not repeat a long v1.6.20 run or
pretend the old epoch-224 artifact contains those missing writes.

Build both the historical v1.6.25 worker and parent with only
`epoch223-v1-6-25-qualification`. Their ordinary default routes are unchanged.
The parent identifies the exact upstream v1.6.25 revision, executable and
environment override. The candidate accepts only focused epoch 223 in one
isolated `qualification-223-v1625-*` private root, explicit verification,
snapshot/checkpoint inputs, and an exact terminal of 96,767,999. Ordinary
replay, root cohorts, recovery, inherited leases, and early maintenance/recovery
entrypoints are rejected before they can touch artifacts. Existing generic
filesystem-only checks reject aliased private roots/children; no epoch-225
launch or assembly policy is reused.

Two exact snapshot slots are admitted:

- **96,767,522**: first run the small 477-slot tail comparison through
  96,767,999, covering the known 96,767,526 vote. This is not a complete epoch,
  checkpoint-continuation qualification, or publishable artifact.
- **96,335,538**: only after the tail comparison and fresh full-run admission,
  evaluate the cold candidate. Replay starts at 96,335,539; output starts at
  96,336,000 and contains exactly 432,000 epoch slots. Bind the existing trusted
  96,767,522 root account hash in the checkpoint file and independently verify
  its reproduction, the remaining tail, and every canonical transaction outcome.

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
included the epoch223 feature in its v1.6.25 overrides, although the registry
descriptor already did. Bind and test both identities. The pre-worker report
must now validate that profile and resolve its worker executable as well.
The old static era label includes v1.6.20; the selected descriptor is v1.6.25,
as asserted by the actual bootstrap-selector regression and new preflight.

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
`epoch223-tail-snapshot-tests` build profile, incompatible with its epoch225
and released-CPU profiles. It accepts only the exact sealed epoch223 test
harness and tail snapshot, its own plan/unit/receipt namespaces, and the
complete fresh 201–300 fleet with the unchanged live epoch203/225 identities.
The 13 independently established canonical size samples bind the century
floor to 248,289,182,611 bytes. A changed census requires a reviewed update.

Run its capability mode under the same actual sandbox before snapshot mode.
The supervisor requires private 512-GiB tmpfs with 1,048,576 inodes, 128-GiB
memory maximum, 112-GiB memory high, no swap, eight-core CPU quota and 512
tasks. Only its exact root-private receipt directory is host-writable.
The child drops to UID/GID1000 with no supplementary groups/capabilities,
has no network, and runs exactly the two ignored load/initialize tests with
anchor 96,767,522, 128-MiB test stack and two Solana Rayon threads. Its
prebuilt harness was compiled in the historical workspace with Rust1.51;
the runtime working directory is private tmpfs, never the mutable workspace.

Fresh sampled and actual available memory must cover the 448-GiB host stop
reserve plus the full 128-GiB test cap. The existing bound supervisor enforces
its 30-minute runtime cap and memory/tmpfs reserve during the child and
fsyncs cgroup counters before exit. This RAM-only check neither reduces disk
growth claims nor creates replay output, canonical sidecars or publication
authority. A successful snapshot check is still not a tail replay or a cold
epoch qualification.

Use the optimized (`cargo test --release`) epoch223 test harness for new
snapshot checks. The previous epoch225 debug attempt exhausted its 30-minute
bound before finishing the first test; its optimized counterpart passed both
checks within the same bounds. Epoch223's initial debug attempt remains
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
