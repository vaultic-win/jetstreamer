# Epoch 250 replacement source packet

The Rust generator renders the exact epoch 249 sealed producer/guard/timer recipe
into the distinct epoch 250 names under `packet/`. It binds the accepted 250
input-custody receipt, accepted cache capability v4, and sealed successor-boundary
diagnostic before writing anything. The producer uses the accepted bootstrap,
sealed manifest and fingerprint, epoch 249/250 cache mounts, and the retained
251,041,591,296-byte MemoryMax and 506,191,984,640-byte root cap.

This packet is source only. No unit has been installed, started, or admitted.
The existing epoch 250 input root contains the bootstrap, final root and genesis;
the launcher must separately prepare its `state`, `tmp`, and `output/compact-indexes`
children and prove custody before use. The producer uses an isolated empty GCloud
configuration. The node resolves the CAR root over HTTP before opening cached
indexes, so its service-effective network route still needs a sandbox proof.

The prior three-lane memory obligation plus the candidate hard MemoryMax and
control allowance exceeds host memory by about 20.7 GB. This source therefore
requires a positively observed terminal lane event and fresh Main admission for
replacement, unless a newly qualified four-lane capacity proof supersedes it.
The exact producer, guard and timer still need a sealed runtime package, complete
launcher validation, actual guard plan, and first guard fire. `source-plan.json`
explicitly denies replay launch, admission and remote mutation.

Verification: `cargo test --offline --locked`, strict Clippy, and release build
passed. `systemd-analyze verify` accepted all three generated units; its two
messages concern unrelated installed XFS units. The generated packet hashes are
recorded in `source-plan.json`.

The first sealed static package left the accepted bootstrap inside a writable
worker root. The corrected immutable `packet-v2/` adds the entire accepted
`input/` directory to `ReadOnlyPaths`. It was separately sealed as
`/var/lib/jetstreamer/horizon250-reboot-20261117-static-v2`; receipt SHA-256
`9bbc1af99e689c1ddf614a8a79c91d561e18a66716782658f6b2c8688de6be1f`.
The v1 package remains historical evidence and is not a launch source.

## Epoch 251 replacement

`prepare-251 OUTPUT_DIRECTORY` renders a distinct dormant 251 packet from the
hash-bound 250 v2 templates. It binds the completed native input test, sealed
singleton manifest, structural index receipt, and the original successor probe's
exact PID1 start/success journal records and output. The probe used a diagnostic
node: the packet does not promote it to qualification of the deployed replay node.

The candidate reads the already sealed bootstrap directly and mounts sealed
genesis read-only, avoiding duplicate input storage. Canonical checkpoint
expectations come from the manifest; no final-root snapshot copy is required.
CPU affinity targets the 247 replacement claim. The future launcher must prove
that claim released and preserve 248–250, or separately qualify a capacity
transition. Hard limits remain unchanged; the RSS scheduling allowance is recorded
separately. The packet names the remaining exact-node, namespace, launcher,
admission and first-guard gates and grants no launch or publication authority.

`capture-251-network OUTPUT_JSON` captures the retained successful 4 KiB CAR
header probe. It checks the exact invocation, command, sandbox properties, cache
and genesis mounts, HTTP 206 range, canonical CAR header and expected root CID.
Manager and file identities must remain stable during capture. This establishes
the tested network route, not deployed-node cache-reader or replay qualification.

`prepare-251-fifth OUTPUT_DIRECTORY` stages a separately qualified fifth-lane
candidate with a 128 GB hard cap and 100 GB soft limit. It binds the accepted
19:20 observation and fleet, checks all four live invocations and their unchanged
hard limits before and after preparation, and budgets their full hard growth.
The 64 GiB host reserve covers measured non-lane resident usage and five guard
maxima; the candidate controller allowance is separate. The smaller candidate
fits the host arithmetic without checkpoint relief or releasing a live claim.
Its replay throughput and smaller full-replay profile remain unproven.

The source retains the original root cap, VMA guard, first-fire token gate and
dormant root. Its CPU set is disjoint from all four retained live sets. The disk
calculation takes no occupied-allocation credit, preserves the inherited guard
floor and requires a fresh century census at admission. The assessment and source
packet do not install units, admit work or authorize a replay launch.
