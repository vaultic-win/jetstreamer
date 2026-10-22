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
