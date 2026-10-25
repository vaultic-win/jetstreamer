# Epoch 207 after authenticated first-root metadata admission

This plan is based on the clean, reviewed coherent R2 source at `df57e9c0`,
including capped 204 work accounting, epoch 233 adapters and V4 delivery gates.
No Rust source or admission policy is changed by this preparation. No Cargo,
shared-target access, GCloud, snapshot body, native/runtime/service operation,
resource/replay poll or R2 action occurred.

## Exact next gates

The metadata repair succeeded. The new reviewed manifest is SHA256
`801707df48654c272b0fffc1005eea97b90dbd1ffe59190aede1c1616e134379`,
fingerprint `sha256:9df04afe0f7ced39c179f2e5dafc34dac2aa6724fe1a8285b38cbfb528834db7`.
Directly rehashed authenticated metadata evidence is SHA256
`41262e1c49c26c72009ef5ec3d6fbdee081873cbb64c4983398f9d7555478176`.
It preserves the existing native proof
`ed39b654d78d4530f82877866d4474435beb353503ad1d3ebfcae04823489819` and denies
runtime, restore, resource, replay and publication authority.

1. The metadata evidence output is root-owned mode 0600. Prepare an immutable
   Rust-sealed copy before a new immutable admission reader binds it. The
   proposed seal plan copies its exact bytes into a fresh reviewed package;
   it does not change the receipt or assert new execution evidence.
2. Capture a new metadata-only singleton preflight for fingerprint `9df04afe`.
   The retained v3 preflight proves only the old `50896e94` fingerprint. Its
   stdout or immutable pin must not be rewritten or relabelled. The proposed
   command uses the existing sealed node SHA `08e14bb0`, the new reviewed
   manifest and `--epoch207-singleton-preflight`; it is not a replay command.
   Keep actual loaded manager state until capture (RemainAfterExit), preserving
   raw journal, IID, exact command, natural zero exit and all zero-entry flags.
3. Before any full replay, qualify a closed full epoch 207 resource/admission,
   guard, observer/fleet registration and status path in the current coherent
   R2 source. The inspected source has bootstrap-only native 207 paths and full
   singleton 209/210 routes, but no full singleton 207 admission counterpart.
   Metadata admission is therefore not yet full replay readiness.

No source pin inside `epoch207_singleton.rs` needs changing merely for this MD5:
`validate_plan` checks the exact bootstrap and two canonical roots, and the main
preflight branch reports the supplied checked fingerprint before any restore or
worker starts. The actual new preflight remains a separate qualification gate.

## Preserve these boundaries

The exclusive singleton is bootstrap slot 89423444; output slots
89424000..89855999; canonical roots 89523820 and 89855469; exactly 432000 output
slots. Preserve the 530-slot suffix after the last root. Do not invent an extra
accounts root at the epoch boundary or include epoch 208. The ordinary checkpoint
policy accepts the supplied post-bootstrap roots inside the full epoch; this is
not a focused qualification requiring a new terminal root at the final slot.

Do not revive `horizon-qualify-207-complete-span-ca2e38b-v2.service`. That dormant
unit runs focused replay through slot 90287519, crosses into epoch 208, uses a
private successor tail, and has an unrelated old resource/admission envelope.
The new closed singleton explicitly forbids that range and those overrides.

The original native proof retains slot 89423444, bank/accounts/blockhash,
capitalization, transaction count, tick height and next-write-version, with
`replay_entries=0`, `bootstrap_writes=0`, `entry_replay=false` and no full epoch
qualification. Preserve its bytes and tuple. Do not change native 207's scope or
reuse its bootstrap-only admission as a full replay admission.

## Narrow immutable pins for a future full singleton 207 adapter

Add new closed 207 constants/readers; do not overwrite old artifacts or replace
other epoch profiles. Bind:

- Reviewed manifest path, SHA `801707df...` and fingerprint `9df04afe...`.
- Immutable copy of authenticated metadata evidence, SHA `41262e1c...`, together
  with its exact candidate binding, root slot/generation/URI/checksums, source
  helper identity `aaa0d9ff...`, root-witness trust statement and denied runtime
  authority. JSON checksum fields alone do not establish transport authentication.
- Existing base manifest SHA `a921cb0b...`; independently reconstruct the one-MD5
  transformation and preserve all bootstrap/roots/range/runtime fields.
- Existing native proof SHA `ed39b654...` and complete original zero-entry tuple.
- Actual new metadata-only preflight receipt and manager evidence once obtained;
  their future SHA/IID must not be guessed.
- Exact qualified node, worker, bootstrap and genesis identities. The old
  singleton node is SHA `08e14bb0...`, existing store8 worker `3f5e8efe...`,
  bootstrap `8af3cd20...`, genesis `133f7eae...`. The worker is not the native-test
  executable (`3a2a21e2...`); bind their reviewed runtime/source relationship and
  retain the native proof, rather than asserting executable equality.

A shrink-budget worker substitution would be a separate reviewed worker/producer
change. Do not silently borrow singleton 209's `4aeca563` worker, capability,
native proof or envelope. Ordinary replay may validate its initial checkpoint
against the retained native tuple during its required startup; no extra native
or bootstrap run is requested just for metadata. A new worker/barrier route
would need its own exact source qualification before launch.

## Resource/campaign qualification still required

Use the coherent neutral capacity transaction and current complete owner/guard
view, including the real guarded epoch 204 continuation and every other live
role. Do not copy singleton 209's older fixed guard roster or 223-only peer
exceptions as-is. Preserve epoch 233, capped 204 and unresolved/failure history.
Fresh fleet/resource evidence, protected peer remaining growth, century disk
floor, output reservation and memory policy remain mandatory. No current free
capacity, lane count or start time is inferred from this metadata work.

The new 207 route needs exact inactive/pending owner checks, bounded memory/root
and worker-VMA controls, explicit Tokio/Rayon/download thread sizing and affinity,
actual first guard fire, launch/start capture, full replay work registration,
30-minute progress/status updates and authenticated terminal cleanup. Native 207
status callbacks alone do not cover those full replay phases. Main replay must
retain both canonical checkpoints and its standard finish checks. Final archive,
plugin, provenance/boundary and transactional publication gates remain separate.

## Focused qualification for that future source delta

Use an isolated branch from the current coherent R2 source. Positive fixtures
should join the exact admitted manifest/proof/native tuple and genuine new
metadata preflight. Negative fixtures must reject old manifest fingerprints,
only asserted metadata authentication, foreign/mutable proof, altered native
slot/cursors or entry counts, omitted roots, epoch 208 tail, wrong runtime/worker,
stale/incomplete peer census, omitted guarded 204 continuation, underreserved
memory/disk and premature status/publication authority. Preserve existing 233,
capped 204 and full singleton tests. Run only the necessary focused suites and
strict Clippy under a separately coordinated lease; no new replay/resource
observation is needed for source qualification.
