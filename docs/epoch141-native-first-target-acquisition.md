# Private epoch141 first-target acquisition

This is acquisition-only source support, not a deployed recovery route. The
distinct native plan schema is
`jetstreamer-epoch141-ledger-native-first-target-acquisition-plan-v1`; its unit
must use the separate `horizon-epoch141-native-full-census-acquisition-` namespace.
It requires the complete existing 18,283-target finalized census but acquires
only its first exact target, slot60911776/parent60911771. Neither one-target
acquisition nor the older eleven-target proof is full recovery.

The pinned complete SlotMeta decoder retains `is_connected=false`. A separate
raw-acquisition planner requests target and parent `meta`, `root`, `dead_slots`
and `orphans` keys, followed by every target `data_shred` index. Slot and shred
keys follow the independently hashed893cc764 `blockstore_db.rs` layout. The
observed last index777 requires778data shreds and786second-batch queries. The
strict recovery planner and connected SlotMeta assembler remain unchanged and
continue to reject the disconnected target.

One admitted read-only native session executes two bounded batches. It must
rehash the entire retained collection before open and after close, preserve
exact query order and null logical outcomes, and recheck unchanged target
metadata. Native read/guard/source failures remain fatal. Missing shreds and
unexpected raw lengths are explicit diagnostic counts, not silently dropped
records or completeness claims. Parent metadata and ancestry-marker outcomes
remain raw evidence, never inferred canonical ancestry. The final no-clobber
receipt is written only after successful session close/source revalidation and
all independent bound-input rechecks. It explicitly denies full-target
completion, source completeness, historical liveness, ancestry, clock/PoH,
runtime promotion, replay, publication and remote/R2 mutation.

The new driver requires admission profile
`epoch141-read-only-first-target-acquisition-v4` and its own executable binding.
Older immutable admission helpers still accept only their original two exact
binaries and must not be renamed or bypassed. The explicitly extended helper
pins this exact candidate under a distinct profile and 1 GiB incremental allowance;
the 32 GiB full-census allowances and inherited protected reserve stay unchanged.
Source tests alone authorize no launch. Native fixture and retained-metadata
planning tests have passed; sealed exact binary/plan, independent admission,
fleet/guard handoff qualification, fresh complete admission and actual sandbox
proof still precede launch. Preserve both previous failed native attempts and
the successful post-close metadata-rejection evidence.
