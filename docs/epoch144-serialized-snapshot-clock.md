# Private epoch144 source observation

The distinct `epoch144-snapshot-clock-diagnostic` feature and
`jetstreamer-epoch144-snapshot-clock` executable reuse the pinned v1.4.25 typed
serialized-clock engine,not its native worker or any replay route. Build/test
from `historical-runtime/v1_4_25` with exact Rust1.46.0,locked/offline Cargo,
`RUST_MIN_STACK=134217728` and bounded `SOLANA_RAYON_THREADS`. Both140/144profile
suites must pass. The two observation features are mutually exclusive.

The immutable144profile binds slot62639490,the exact retained snapshot path,
size2569233422,SHA256`f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae`,
device64512/inode105578509 and retained protection4740696923590bytes. It checks
the unchanged typed-layout source hash and rehashes the full compressed input,
then streams the hardened tar census without extracting or constructing Bank.
It writes a private no-clobber footprint/clock receipt and initial guard.
All consensus integers remain Rust u64;do not transcribe them through float JSON.

Fresh `jetstreamer-r2 admit-clock144 SPEC --spec-sha256 HEX --self-sha256 HEX`
uses the same accepted fleet/owner/floor checks as compressed-source admission,
but a separate clock-only schema,output namespace and exact executable binding.
It deliberately retains the larger compressed-object-plus64MiB candidate budget
for this read-only scan;this is conservative rather than a native-restore bound.
The spec's historical `downloader` field names the exact clock executable for
this mode. Its receipt never authorizes downloading,restoring or replaying.

Seal the clock,admission helper/spec and exact launch intent with the Rust sealer.
Launch only after admission under persistent non-restarting private-network
strict-fs/read-only-home systemd,CPU/memory/task bounds and only the exact private
receipt directory writable. Pass `--output ABSOLUTE_NEW_RECEIPT
MINIMUM_PROTECTED_FREE_BYTES --self-sha256 HEX`. Reserve receipt space above the
retained floor and observe the actual initial guard before unattended execution.
The internal900-second/free-space guard runs on every compressed read.

Serialized fields and unpacked logical/stored byte counts do not prove a native
checkpoint,accounts hash,PoH continuity,resource admission for restoration,suffix,
assembly,plugin compatibility or publication. The independent prefix pass and
exact executing worker's full native tuple comparison remain separate gates.
