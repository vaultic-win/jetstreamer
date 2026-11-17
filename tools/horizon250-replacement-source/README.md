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
