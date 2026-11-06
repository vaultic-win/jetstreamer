# Epoch 234 top-level instruction arena repair

This is unqualified source. Rustfmt and `git diff --check` pass. No compiler,
tests, replay or service was run for this change. Separate native test admission
and immutable deployment gates remain required.

The original epoch 234 invocation `42cd9e2dba644e3093f5479da3a3c917` exited after
the recorder could not convert transaction 298 at slot 101249927: its 65
top-level instructions exceeded the 64-element inline message representation.
The exact failure evidence remains in
`/var/lib/jetstreamer/horizon234-failure909-status-event-v1`. This is an archive
representation failure; it does not establish a Bank/checkpoint mismatch.

`MessageInstructions` replaces the two message variants' arrays of full-sized
instructions with small descriptors and one shared byte arena. The maximum
combined account-index and data bytes is 1,232, the complete Solana transaction
packet bound. Each instruction consumes at least three packet bytes, so
`1232 / 3` conservatively bounds descriptor count without assuming that every
recorded message is limited to 64 executed instructions. Message headers,
keys and signatures reduce the true maximum further. Existing individual
account/data checks remain. The historical inner-instruction buffer keeps its
previous 4,096-record capacity, independently of the new top-level count.

The arena does not serialize offsets or change either archive version. It
encodes the original element count and, per instruction, program index and the
two original uncompressed `ZeroVec<u8>` fields. Old valid transaction bytes
are preserved; impossible oversized packet payloads fail closed. Appends check
all bounds before mutation. Decoder sequence/blob budgets remain active, short
streaming reads are supported, and truncated/over-reporting readers cannot
publish an incomplete instruction. In-place message clearing and Legacy/V0
variant reuse retain an all-zero empty representation.

Authored coverage includes the original 0/1/64-element wire codec with and
without context, a 65-element round trip, packet-derived descriptor and byte
limits, unchanged inner capacity, bounded memory footprint, append rollback,
streaming short reads, truncation/reuse, malformed flags, decoder budgets and
an over-reporting safe reader. The conversion regression exercises a
packet-sized synthetic 65-instruction failed transaction through
Legacy/V0/Legacy reuse and preserves its original status/signatures/instruction
contents. It is explicitly not an authenticated fixture of the historical
transaction.

Under a separately admitted native source/test profile, run formatting and the
new arena/conversion tests first, then the complete `jetstreamer-horizon` library
suite and compilation of its examples/benches. Compile/test the affected node,
firehose and current-plugin consumers before selecting production binaries.
Exact failing-transaction fixture acquisition/qualification, normal recorder
coverage, production source/artifact provenance, required feature unions,
immutable sealing, capability probes and fresh replay admission remain open.
Do not replace a live binary or claim the failed replay can resume its Bank
cursor. Preserve its evidence and coordinate any scratch retirement separately.
