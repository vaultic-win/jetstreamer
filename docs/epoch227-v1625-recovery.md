# Epoch 227 v1.6.25 recovery qualification

The actual v1.6.20 capped producer failed at slot 98091122, entry 232,
transaction 223, after four hours. Its invocation was
`a10f37b57711425a81633c62c66438d5`; the sealed raw journal is
`/var/lib/jetstreamer/horizon-full227-failure-a10f37b5-v1/journal.json`,
SHA256 `97b9b039efb30bb8c209a4b60c2519908068cd905d78f313a4ee2bf7fad8cb5e`.
The original partial archive, scratch, snapshot and inputs must remain intact.
Do not restart that unchanged producer.

Finalized RPC evidence is sealed in
`/var/lib/jetstreamer/horizon-full227-finalized-vote-diagnosis-v1`.
The successful canonical failing signature
`3f6mTJHfWLvB12a6VJizegs8XZu9hXGphZwCcYg4yc5ZEoDqLzU4xmyAvcCdcHCGUh6fZtcSvLy9HDsAY2Z8TtRt`
votes solely for 98091121, expecting Bank hash
`BLAJ7oikrxpvcYMZnLjr9iApJGeLuhLjzyQ8Yw82WH73`.
The actual runtime's vote-program Custom(2) is SlotHashMismatch.
This proves a disagreement in the reconstructed parent Bank hash; the journal
does not contain the computed hash or an independent earlier matching bracket.

The finalized raw parent block 98091121 has 546 transactions. Exactly one
successful transaction marks a directly invoked program writable:
index 78, signature
`5SZbyiFj1XnvQbE7AGdn8DK8JoWnVzsLzXP34gvRP4FUPvcYEKopyt3TdScfqCKN22BWDZwCXziRhTmYQvH5rpSU`.
SPL Token is key 8 among 15 keys, with 4 readonly unsigned keys. It is both
passed to another program and invoked directly. Canonical pre/post lamports
are 1089991680. The v1.6.20 SDK preserves this called program's writability;
v1.6.25 demotes it. The wire fixture regression establishes this source-shape
difference and excludes the Token key from writable-write attribution.
This is the same concrete lead previously observed for 225, not proof of the
underlying 227 divergence cause.

Two mutually exclusive v1.6.25 build profiles use only the retained snapshot
98063464. The diagnostic profile accepts entries 98063465 through 98091122;
the qualification profile accepts entries 98063465 through 98495999.
Both preserve ordinary conflict-wave execution and existing storage maintenance.
They cannot combine with each other, singleton diagnostics, or 223/224/225 profiles.
Neither changes the default era, node routing, ordinary publication admission,
canonical sidecars, fleet admission or R2 permissions.

The ignored test
`runtime::tests::native_epoch227_v1625_cold_input_matches_canonical_accounts_commitment`
requires an empty owner-private `scratch` child beneath
`/home/ubuntu/.jetstreamer-private/native-input227-v1625-*`,
named by `JETSTREAMER_EPOCH227_V1625_TEST_SCRATCH`.
It rehashes the exact immutable original snapshot, restores/freezes only the
bootstrap Bank, compares canonical accounts commitment
`4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR`, and requires unchanged write
version/transaction count with zero bootstrap writes. It prints actual Bank,
accounts, capitalization and write-cursor values. It must be separately sealed,
admitted and invocation-bound; a passing synthetic test does not qualify native input.

After native qualification, a separately admitted bounded comparison must
independently reproduce the successful canonical vote at 98091122 and the
parent 98091121 Bank hash above. The profiles print actual freeze diagnostics
for 98091119–98091122. This local match does not authorize full replay or publication.
Full qualification must also reproduce root 98495291 and canonical accounts hash
`GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq`, retain the708-slot tail,
and pass all complete-archive/current-plugin/boundary gates.

Any actual replay requires new exact parent/worker/capability/native-proof,
guard/admission/capture/fleet/status bindings, fresh complete fleet evidence and
protected remaining-growth/floor budgets. The original 1.6.20 proof does not
qualify this 1.6.25 route. Keep every replay, publication and R2 gate closed until
its independent evidence exists. Parent owns launch, observation and all R2 work.
