# Finalized parent-gap audit

`jetstreamer-horizon-gap-audit PLAN --plan-sha256 HEX --self-sha256 HEX`
creates one private, fsynced, no-clobber diagnostic receipt. Run only a sealed
root-owned binary and bind the actual executable SHA-256 separately.

Plan schema `jetstreamer-horizon-finalized-gap-audit-plan-v1` contains `first_slot`,
`last_slot`, `block_list_request`, `block_list`, `rpc_batches`, and an absolute `output` filename below
a canonical root-owned mode-0700 directory. Every input is an absolute canonical,
immutable, singly linked root-owned regular file, at most 8 MiB, referenced as
`{"path":"/sealed/input.json","sha256":"64 lowercase hex"}`. Each batch contains
one bound `request` and one bound `response`. Seal the plan and all inputs with
the standard deployment sealer before running it.

The block list is a successful `getBlocks` JSON-RPC response whose strictly
increasing slots include both interval endpoints. Its separately hash-bound
request must specify the exact interval and finalized commitment, with an integer
ID matching the response. The interval may span at most
432,000 slot increments. Every adjacent jump becomes a mandatory target.

RPC batches must use `getBlock` with the slot as integer ID, explicit `finalized`
commitment, `transactionDetails: none`, `rewards: false`, and
`maxSupportedTransactionVersion: 0`. Only target slots may be requested. Every
request must receive exactly one response. Error responses remain hash-bound and
are counted, never treated as data; a later separately bound successful request
may fill the missing target. Successful duplicate responses must agree exactly
on parent and both PoH hashes. No target may remain unresolved.

The audit binds each target's independently finalized parent slot and final and
previous PoH hashes, rejects disagreement with the complete block list, and
reports present slots, skipped slots, target count, and expected tick-boundary
count. Hashes must decode to exactly 32 bytes. They are PoH hashes, **not** frozen
Bank hashes or SlotHashes sysvar values.

This is a planning/diagnostic census. It does not prove the CAR omits ticks,
recover hidden hashes, authorize a bulk download or replay, promote a runtime,
create a canonical sidecar, publish an archive, or mutate R2. A raw-shred scan
must still examine the complete generation and honor all LSM versions and
tombstones before selecting values. All ordinary qualification and publication
gates remain independent.

Run package tests and clippy, and explicitly execute the
`root_input_integrity_and_private_no_clobber_output` test as root before sealing.
