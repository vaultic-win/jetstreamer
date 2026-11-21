# Epoch 141 private suffix qualification

The default node accepts an explicit `--epoch141-strict-suffix` with the
corrected local Old Faithful index. The earlier original-entry bundle profile
covers bootstrap 60,911,751 through checkpoint 61,328,765.

The suffix starts from the verified 61,328,765 snapshot. Its epoch portion is
61,328,766–61,343,999 inclusive (15,234 positions, 13,183 blocks). The last
position has a block. The independent accounts-hash check lies at 61,414,189,
which requires another 70,190 positions in epoch 142. The resulting private
qualification artifact includes that verification tail. Joining a successfully
verified prefix and suffix into an ordinary full-epoch archive requires a
separate assembly and verification.

The normal Firehose global lookup authenticates the pinned local index and
censuses every suffix position before opening the bootstrap. Decoded parent
edges must agree with that census. Each block waits for its metadata, all
ordered entries and transactions, exact original tick work across the parent
gap and the block's actual final entry hash. The parent verifies signatures
against each complete original transaction. The normal v1.4.25 worker verifies
the full PoH chain, tick heights and Bank checkpoints.
The terminal block and its parent hash are also pinned independently.

The normal input seal is projected read-only at
`/usr/local/lib/jetstreamer/epoch141-strict-suffix-inputs`. It contains
`manifest.json`, the corrected `epoch-141-slot-ranges.raw` (SHA-256
`ed2654c5fdd9a115176d6d799df636ee1ce945fca393c812a0ba2f1db8f909c8`)
and `epoch-hashes.txt`. The bootstrap object is
`gs://mainnet-beta-ledger-us-ny5/61328765/snapshot-61328765-8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY.tar.zst#1634786682225857`,
4,297,291,805 bytes. The terminal commitment comes from
`61328765/hourly/snapshot-61414189-3Nqh4AvG4B3K51pDWbzfFA7CHKbztYuuMZDZDzqpY5Mh.tar.zst#1634786633603582`
in the same bucket.

For a separately funded invocation, stage the pinned snapshot, genesis and a
fresh private ledger, output and scratch directory beneath
`/home/sol/.jetstreamer-private`. Pass the normal sealed node to the existing
native guarded launcher with these arguments and environment. Its resource
contract must include the source, Bank, AccountsDB growth, the verification
tail and retained private output.

```sh
inputs=/usr/local/lib/jetstreamer/epoch141-strict-suffix-inputs
export JETSTREAMER_ALLOW_CANDIDATE_RUNTIME=1
export JETSTREAMER_HISTORICAL_WORKER_V1_4_25=/usr/local/lib/jetstreamer/horizon-v1425-corrected-default-candidate-20261023-v1/jetstreamer-historical-worker-v1-4-25
export JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST="$inputs/manifest.json"
export JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256=843e0a479dcd3f7634f026ab8f0f4857fb52778e1769059397c972e605d6078c
unset JETSTREAMER_FORCE_LEGACY_INDEX
"$node" 141 "$ledger" --verify --epoch141-strict-suffix \
  --snapshot-archive="$snapshot" --epoch-hashes="$inputs/epoch-hashes.txt" \
  --qualification-end-slot=61414189 --replay-scratch="$scratch" \
  --horizon-output="$out/epoch141-suffix-through-checkpoint-61414189.jet"
```

The offline source executable takes a directory of the three retained CAR
ranges and the corrected raw index. Run it with the same manifest projection
and environment in a private network. It verifies all 432,000 global reader
lookups, every CAR section CID, exact block-entry-transaction links and
transaction indexes, then reexecutes every v1.4.25 PoH step from independently
recorded parent and final blockhashes. The fixtures use the four skipped slots
61,328,812–815 and the two restored block rows 61,333,100 and 61,341,144.
