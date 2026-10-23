# Epoch 227 capped singleton candidate

Build the original pinned v1.6.20 worker with the exclusive
`epoch227-capped-qualification` feature under rustc 1.51.0. This is a separate
candidate from epoch223's prefix and from the v1.6.25 diagnostics. It admits
only cold snapshot 98,063,464 and entries 98,063,465–98,495,999. The additional
`epoch227-capped-warmup-diagnostic` feature reduces the upper bound to
98,063,480; it cannot substitute for the full singleton worker. Neither feature
changes the default worker or permits another epoch. Combining either profile
with epoch223 or singleton execution diagnostics fails compilation.

The only execution change caps the physical AccountsDb shrink debt at 250,
matching the existing epoch223 storage maintenance candidate. Transaction,
account loading, fees, PoH, Bank hashing and native account updates remain the
original runtime. Synthetic regressions check the exact bounds, reject malformed
out-of-scope batches before decoding or Bank mutation, and confirm storage debt
recovery preserves capitalization, Bank hash, last blockhash, balances and the
global write cursor. These tests do not establish native snapshot equivalence
or full replay qualification.

The retained input package is
`/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1`. Do not redownload or
duplicate its 10,261,480,487-byte snapshot. Its exact SHA-256 is
`77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07`;
the independently pinned accounts hash at slot 98,063,464 is
`4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR`.

The ignored `native_epoch227_cold_input_matches_canonical_accounts_commitment`
test in the warmup build rehashes this exact input, restores it through the
native snapshot loader and freezes the bootstrap Bank without replay entries.
It requires an empty owner-private canonical scratch directory named `scratch`
beneath `/home/ubuntu/.jetstreamer-private/native-input227-v1620-*`, supplied as
`JETSTREAMER_EPOCH227_V1620_TEST_SCRATCH`. Its output compares the canonical
accounts commitment and requires no bootstrap account writes, unchanged native
transaction count and unchanged write version. Seal the executable and plan;
coordinate its memory, disk and runtime envelope with the complete live fleet
before execution. A successful cold-input test authorizes neither replay nor
publication.

The shortest full delivery route uses the existing ordinary node's
`--root-checkpoint-cohort` mode with singleton range 227, the retained
`preflight227-singleton.json`, fingerprint
`sha256:99fa3de5ed1da720b76e33196d4ef4da9dda57202f12af90eaab60f84f9ecd31`,
`--verify`, and the exact retained snapshot override. Bind the separately sealed
capped worker through `JETSTREAMER_HISTORICAL_WORKER_V1_6_20`, opt into the
candidate runtime and use a fresh isolated private output/run root.

The cohort route requires a canonical root within the final epoch, not exactly
at its last slot. This manifest supplies root 98,495,291 with accounts hash
`GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq`. The existing verifier must
observe that exact root, continue through the final 708 slots, and finish while
native terminal completion, ordered archive chain and full output coverage
98,064,000–98,495,999 all pass. No prefix assembly or checkpoint restart is
needed if that unmodified full route succeeds. Independent full/current-plugin,
boundary, authenticated upload/readback and sidecar gates remain unchanged.

Use the user's 300 GB decimal century scratch planning allowance separately
from output, margin and century floor. Fresh complete fleet admission, actual
guard protection, native input proof, exact-package capability and real replay
qualification remain required. Do not treat the old uncapped peak, an early
CLI rejection, a sealed package or these source regressions as those proofs.
