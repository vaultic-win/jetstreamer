# Independent epoch boundary expectations

`tools/horizon_epoch_boundaries.rs` prepares the current reader's independent
parent and terminal expectations before an epoch archive finishes. It reads
finalized metadata from `https://api.mainnet-beta.solana.com`; it never opens a
local archive, launches replay, verifies archive contents or mutates R2.

Run the sealed binary as root with `PLAN --plan-sha256 HEX --self-sha256 HEX`.
The immutable plan schema is `horizon-independent-epoch-boundary-plan-v1`, with
`epoch` in 201–300 and an existing, empty, canonical root-owned mode-0700
`output_directory`. A no-clobber intent prevents concurrent attempts from sharing
that directory. Preserve failures and use a fresh directory for another attempt.

The collector obtains the ordered block census for the first 1,024 epoch slots,
then reads the first block, its parent and the exact terminal slot. The first
block must point before the epoch boundary, its previous blockhash must match
the independently fetched parent, and the terminal parent must lie inside the
epoch. A skipped or unavailable terminal slot fails closed for investigation.
Every blockhash must decode to 32 bytes. TLS validation remains enabled, redirects
are disabled, each request has a 30-second timeout, and each response is limited
to 1 MiB. The containing qualification service also needs a bounded runtime.

Raw responses and request records bind the endpoint, finalized commitment,
requested slots, response hashes and actual collection times. The resulting
`epoch-N.json` includes their exact paths and SHA-256 values and is compatible
with the current-reader plan's `epoch_expectations` map. Every output is created
without overwriting and fsynced with its parent. Seal the expectation and its
evidence before selecting it for a production delivery plan.

Tests reject unordered, duplicate, out-of-range or missing block censuses,
disagreeing parent hashes, invalid boundary relationships and malformed hashes.
These checks provide independent expectations only; full current-reader decoding,
plugin playback, authenticated remote playback and publication gates still apply.
