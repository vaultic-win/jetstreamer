# Epoch 141 original-entry transaction equivalence

`jetstreamer-epoch141-source-equivalence` is a private, fixed first-target
diagnostic for slot 60911776 (parent 60911771). It never launches replay,
changes a runtime route, publishes an archive, or accesses R2.

The tool binds the exact retained raw-shred target and its prior complete PoH
diagnostic, plus independently qualified typed/native snapshot clock evidence.
It makes one bounded finalized `getBlock` request to the fixed mainnet RPC,
retaining the request and exact response bytes (base64 plus SHA-256), including
failure responses. The parent, previous hash and final hash must match the
retained finalized anchors. Transactions must be explicitly legacy and have
canonical base64 packet-sized wire encodings.

The shared `horizon_legacy_source` helper compares every original transaction
byte in complete assembled batch order with the independently obtained source
sequence, then reexecutes the complete original PoH chain. It retains every
original tick, transaction entry, hash and hash-work count, and maps original
entry indexes to source transaction indexes without normalizing or regrouping
transactions. A mismatch returns no partial mapping. Slot-wide byte, entry,
transaction and hash-work limits remain independent; guards can abort work.

The root-private no-clobber completion includes the full entry/index mapping,
counts and input/response digests. This is only first-target wire equivalence,
not complete 18,283-target equivalence, native live-state completeness,
signature verification, canonical ancestry, Bank-root qualification or
publication authority. The running producers must remain untouched.

Before use, seal the executable, its hash-bound plan and a digest-matching curl
copy with the normal Rust deployment sealer. Use schema
`jetstreamer-epoch141-first-source-equivalence-plan-v1` with `curl: {path, sha256}`
and an empty root-owned mode-0700 `output_directory` directly beneath
`/var/lib/jetstreamer`, named `horizon-epoch141-source-equivalence-*`.
Run in a bounded non-restarting systemd unit with only that output writable,
read-only private inputs and minimal private-path traversal capability. The
tool requires its own supplied executable and plan SHA-256, the real systemd
invocation ID, a 30-second RPC deadline and a 90-second overall work deadline.
Normal root/plugin/full-span and publication gates remain separately required.
