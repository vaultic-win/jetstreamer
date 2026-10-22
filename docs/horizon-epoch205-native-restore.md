# Dormant epoch-205 native restore comparison

The opt-in `epoch205-native-restore-diagnostic` feature builds
`jetstreamer-epoch205-native-restore-probe`. This is a separately pinned private
profile, not a relabelled epoch-203/213 receipt or a new ordinary runtime route.
It shares the restore-only engine with the existing epoch-203 probe; every
epoch, snapshot, worker, source-prefix path, schema and attempt namespace is
fixed at compile time. The epoch-203 profile retains its prior bindings and its
already-sealed deployment is not replaced by this source refactor.

The 205 profile pins the unchanged v1.6.16 store8 worker
`3f5e8efe...`, the exact snapshot at slot 88,991,050, its full verified
SHA-256 `1b2a41f022847dc2ba9609e5a13aadc0e79b213b5245166b06954bf8c6d9042f`,
length 8,407,269,066, and accounts root
`BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp`. The compressed input was
generation/CRC32C/MD5/SHA-256 verified independently of this probe. Its presence
does not prove that native restoration or restart semantics work.

The planned source prefix is exclusively
`/home/ubuntu/.jetstreamer-private/qualification-205-prefix-store8-v1/output/epoch-205-through-88991050.jet`.
That is a future artifact, **not** the bounded 205 canary, and it has not been
produced or qualified merely by adding this binary. It must cover exactly
88,560,000 through 88,991,050 from the 88,559,361 bootstrap, retain candidate
single-runtime provenance and the exact worker digest, and receive no canonical
sidecar. A complete independent reader must validate the archive and bind the
entire typed segment-manifest semantic hash, including every terminal field.
The probe requires that exact manifest and reader receipt before spawning a
worker; a range-only, cross-epoch or self-consistently altered receipt fails.

Execution additionally requires a separately sealed input policy and a fresh,
hash-bound restore-only admission receipt covering the century floor and all
older growth plus the full incremental restore peak. The fixed 128-GiB peak
and thirteen-sample century floor are rejection minima, never a complete host
admission or a full cold-epoch bound. Require the intended UID1000 persistent
zero-restart invocation, exact isolated private paths, VMA/inode headroom,
bounded environment, and a proven invocation-bound reserve/VMA guard. Do not
install a launcher, automatic retry or admission trigger from source/test
success alone.

The engine initializes, freezes the restored checkpoint, records resource and
phase timings, and shuts down. It sends **zero replay entries**. Compare slot,
bank/accounts hashes, last blockhash, capitalization, transaction count, tick
height and completeness with the independently verified prefix. Require zero
bootstrap writes and no advance of the restored validator-local cursor; do not
force that cursor to equal the original producer's independent namespace.
Revalidate source evidence before writing the private no-clobber outcome.

Even a real successful comparison leaves the final **949 slots**, native tuple
validation in the actual suffix worker, explicit cursor/lineage normalization,
assembly, independent complete-archive/current-plugin checks and authenticated
R2 delivery unqualified. The probe grants no replay, suffix, assembly, canonical
sidecar, publication, local-retirement or remote-mutation authority. Ordinary
replay and the runtime compatibility registry remain unchanged.
