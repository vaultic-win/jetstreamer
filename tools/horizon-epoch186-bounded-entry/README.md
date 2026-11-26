# Bounded epoch 186 qualification

Build and test from this directory with `cargo test --offline --locked`.
The source entry binds node `6b0f3089`, the stock Solana v1.6.15 worker
`9339aa0e`, the retained bootstrap at slot 80,351,283, the independent
checkpoint at slot 80,783,539 and the repaired epoch 186 CAR range table.
Its focused node command ends at that checkpoint, 460 slots before the end of
the epoch. Full-epoch delivery requires subsequent replay and independent
archive verification.

- `source` verifies the sealed runtime binaries, CAR table, transport
  receipt, trusted checkpoint list and retained bootstrap identity. It emits
  the exact node command, environment and read-only input projections.
  `rehash-source` also reads the whole 7.3 GB bootstrap and verifies its
  SHA-256. Use this before production entry when the transfer fits the host
  budget.
- `quote FLEET SHA256` takes the existing transition lock, proves the native
  epoch 145 V9 verifier has drained, and invokes the sealed post-V9 provider
  with its supported epoch 145 scope. The epoch 186 report preserves the
  incumbent and donor floors, the retained publication-copy allowance, the
  138 GiB tree reservation, and 96 GiB of producer plus 1 GiB of guard RAM.
  It requires a distinct eight-core producer and one-core guard booking.
  The provider returns source and capacity evidence for controller review.
- `static-guard-plan` emits a synthetic invocation for the deployed guard's
  `--validate-plan-only` mode. Production uses its actual producer invocation
  and the floor from the freshly accepted capacity quote.
- `tail-source` verifies the sealed tail package and bootstrap inode and emits a
  private invocation for slots 80,783,540 through 80,791,699. Only slots
  through 80,783,999 belong to epoch 186. The remaining 7,700 slots establish
  the post-epoch checkpoint privately. The report grants no launch or
  publication authority.
- `repair-tail-index INDEX NATIVE_REPORT OUTPUT` stages a digest-bound epoch 187
  index for the epoch 186 verification tail through slot 80,791,699. It fills
  the two missing rows proven by native CAR decoding. The original index stays
  intact, and the receipt identifies the exact verified range.
- `check-guard held|adopted PLAN PLAN_SHA SAMPLE SAMPLE_SHA QUOTE_SHA`
  checks the stop-enabled guard sample against the selected plan, the exact
  systemd producer, guard service and timer, and the fixed
  `PRESTART_CAPACITY.json` under the epoch 186 runtime state directory.
  `held` requires a workerless guard sample. `adopted` requires exactly one
  bound stock worker and checks its running image, exact node command, local
  CAR environment and read-only input projections. Use the newest completed
  guard invocation.

Use the source report to qualify and seal the host entry. Admission needs a
current complete fleet, an independently priced CPU booking, exact systemd
limits, a held invocation, an authenticated first protective guard sample
and controller-owned observer enrollment and release. All trial scratch,
state and archive output stay on the HOME filesystem.
