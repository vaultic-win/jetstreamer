# Epoch 159 boundary feature reference

A finalized mainnet feature account records activation of `check_init_vote_data` at slot 68,688,000. The original v1.5.6 reference first produced a different Bank at this slot, after its preceding Bank matched. The feature address is `3ccR6QpxGYsAbWyfevEtBNGfWV4xBffxRj2tD6A9i39F`. Its original snapshot account held 953,520 lamports and nine zero data bytes. The finalized data encodes `Some(68_688_000)`. Upstream added the feature in `241fb938c14d82a5555091b7718f263b6e0a88bc`, released in v1.5.9. Its program semantics affect vote initialization and caching of uninitialized vote accounts.

The bounded differential uses the existing v1.5.19 protocol-v5 worker, SHA-256 `55b09fd3cc1c67e10adcaf72d9ffa362fa3202156314dd092f6226bdabe31e94`. Its HELLO reports Solana revision `936ff7424e1306b0df07dabcd6863bf7896d2cb5`. This later diagnostic image is eligible for testing against the original snapshot. Acceptance requires the original bootstrap checkpoint, exact pre-transition signed Bank, actual nine-byte feature write at the first epoch slot, signed Banks for both epoch 159 slots, complete SlotHashes, original PoH inputs and success of the original signed vote. The physical outcome determines compatibility.

Deploy the original reference package layout with the current `native.py`, `trace.py`, `service.py`, and additional `feature19.py`. The package must be sealed at `/var/lib/jetstreamer/horizon_runtime_data/epoch159-vote-feature-reference-20261123-v1/package-v1`. It accepts a separately priced grant for this generation under the original 2-CPU, 48-GiB, zero-swap and HOME scratch limits. The grant must include all ten original donor units. Its focus-donor route requires a genuinely free lock and no live V5m verifier that checks that lock. The grant, intent, images, service and extracted evidence all belong to the new generation.

The owner can check all immutable mounted inputs through the isolated account before allocating scratch.

```sh
sudo -n /usr/bin/python3 -IB package-v1/service.py --feature19 check-mounted-inputs
```

After the fresh physical grant, the owner runs the following command from the new generation directory.

```sh
sudo -n /usr/bin/python3 -IB package-v1/service.py --feature19 dispatch "$admission_sha256"
```

Inspect `attempt-v1/retained/outcome.json` for actual feature writes, the target vote and signed Bank comparisons. None of the bounded diagnostic receipts make a whole epoch ready.
