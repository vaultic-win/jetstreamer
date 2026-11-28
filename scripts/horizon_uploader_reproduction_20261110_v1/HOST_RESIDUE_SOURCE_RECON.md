# Host-residue source reconciliation

Source-only. No build/test/native execution, observation, lease, resource change, timer, Git or R2 operation occurred. Healthy replay lanes and all runtime files remain untouched. Proposed pure Rust source: `host_residue_semantics.rs` (rustfmt parsing passed; four proposed tests were not run). Exact inspected bindings are in `INSPECTED_BINDINGS.json`.

## Main finding: 46,288,089,088 is not all measured host memory

The genuine1530 selection's inferred non-peer remainder is270,163,259,392. Subtract verifier128/native16/shared64/cadence512MiB (223,875,170,304) and one obtains46,288,089,088. But the accepted1530 observer's actual same-end hostRSS+kernel maximum is **43,603,734,528**, not46,288,089,088:

- Before: hostRSS4,198,072,320 + kernel39,405,662,208 =43,603,734,528.
- After:4,197,457,920 +39,405,932,544 =43,603,390,464.
- Difference **2,684,354,560 =five512MiB input161 rows**.

This is an exact source-semantics discrepancy between peer sums, not unexplained physical consumption. `charge136_retry0005_admission.rs:246` computes the measured host/kernel sum and separate pools, then calls `terminal199_memory::raw_peer_memory`. `retry0005_memory_shape.rs:129` conservatively counts a missing `native_pool_suballocation` tag outside the pool. Its actual raw peer sum is834,834,268,160. The captured141 selector (`captured141_memory_retirement/selector.rs:146`) instead sums only explicit `native_pool_suballocation==false`, reporting832,149,913,600. The five positive missing-tag input rows explain the2.5GiB gap exactly. Each also appears with the same unit/IID/512MiB in `native_pool_suballocations`, but that membership alone does not retroactively qualify a tag or a reduction.

Checkable identity:

`223875170304 pools +43603734528 measured host +834834268160 conservative peers =1102313172992 raw total`.

The four source files are byte-identical between Helper40 and the **actual** reader image197818d0's accepted Reader2-v2 source. Its normal artifact proof binds that exact source/compiler graph. All original raw rows and both sum semantics must remain intact.

## Complete current numeric ledger

Current head `/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json`, SHA `2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa`, preserves memory759,789,531,136 and DATA6,229,838,610,226.

| Component | Bytes |
|---|---:|
| Seven166–172 actor caps,68GiB each |511101108224|
| Normal10GiB, including seven1GiB guards +observer2 +Root1 |10737418240|
| Effective verifier96GiB |103079215104|
| Native16GiB, original input/reader suballocations retained inside it |17179869184|
| Fixed shared64GiB |68719476736|
| Inherited cadence/foreman512MiB allowance |536870912|
| Original199 controller512MiB +guard512MiB |1073741824|
| Cached145 guard512MiB after parent-only retirement |536870912|
| Old722 guard256MiB after actor-only ending |268435456|
| Failed74 exporter guard256MiB after actor-only ending |268435456|
| Five input161 missing-tag outside-pool conservative promises |2684354560|
| Actual original1530 measured host/kernel component |43603734528|
| **Total** |**759789531136**|

Thus the prior compact decomposition “seven caps+pools+46.288GB residue+2.5GiB small owners” is numerically correct but mislabels the residue: it contains a further2.5GiB of input promises. No failed1530 guard is added here; its genuine actor/guard ending was already consumed. No old722 duplicate ending is reused: the exact conservative correction restores the second deduction. Original154's new selection changes DATA only.

The selected ancestry source capture retains66 traversed immutable nodes/edges and explicitly stops at a cache-QA closure whose predecessor uses `prior_booking`; it is **not** a claim of complete new native ancestry qualification. The genuine45-node duplicate audit plus original166 binding to the1530 selection anchor the known effective history. A future selector must finish its own complete consumed-claim/edge proof rather than turn this numeric table into authority.

## Smallest useful qualification

**First qualify this split as a report-only component ledger**, using the proposed pure module plus normal bounded/hash-stable source readers. Bind the exact current2f88 head, genuine1530 selection, all four original reader outputs, original observer, exact reader artifact/source graph, corrected duplicate-audit chain and the once-only ending history. Recompute both peer sums, both same-end host values and every component; retain all missing tags and all original amounts. Four strict compiler configurations, focused ordinary negatives and one genuine finite native metadata execution must pass before any effective selection. This is a metadata/custody transaction, not a new resource observer.

The smallest **potential future-promise correction** exposed by the split is the five input161 pool overlaps, at most2.5GiB. Their exact original IIDs are690c8b040c894b8eae128b74064aefe3,d2a7aefa7309420fbcaf8736b263d8fa,05ed2edc17c64bce9a35e46c0ac5cdea,8e3c68756ae440db911caf180abe1b89,46d089177fb64c25917867a51006bc6e. A separate effective selector must authenticate their original admissions/lifecycles, same pool rows and preserved native16 commitments (historical4,831,838,208 retained), prove no intervening rebooking/previous consumption, and remove only the duplicate **outside-pool** increment through a unique no-clobber selection. Never edit raw tags, end those original claims again, lower native16 or count cache/RSS. Reconcile full consumers/guards separately before fresh admission. This source finding has selected **zero** bytes.

## Qualification for the actual host component

The remaining43,603,734,528 is a historical measured scheduling component containing processRSS and **whole Slab**. It has no single terminal actor/IID and cannot use an actor-ending tool. It is not evidence of current nonreclaimable consumption. The accepted10:00 report has52,697,112,576 nonlane resident planning bytes, larger than the original true host component; simply rebasing the same broad RSS+Slab formula would not free memory.

A safe remaining-growth route retains that component and shared64, then separately proves already-consumed **disjoint nonreclaimable** bytes. Extend the existing finite V12 checker’s `/proc/meminfo` parser to preserve strict units/duplicates and capture SReclaimable/SUnreclaim with Slab plus KernelStack/PageTables/Percpu at its two actual native endpoints. Prove kernel-version counter semantics and non-overlap with the seven already credited cgroup anonymous endpoints and every other consumed component. Use a conservative minimum/margin capped by the one matching host component; add no current RSS/file/cache/wholeSlab credit and do not also consume the same kernel bytes under an actor or shared pool. Source/ordinary controls must reject duplicate global/child counters, reclaimable Slab credit, malformed/racing decompositions, wrong head and expired/mismatched fleet. Then actual native execution under the existing qualified finite booking yields only a report. Existing observers do not contain SUnreclaim, so their bytes cannot retroactively qualify it.

A future **reserve reduction** needs a different scope: complete future host/system/uncapped-uploader obligations and an independently accepted exclusive component budget, plus registered effective consumers. Current low RSS and the clean owner census cannot prove that bound. Preserve shared64 until that work succeeds.

The V12 gap91,548,504,064 is historical. Even the unqualified mathematical upper bound of removing the entire inferred46,288,089,088 would leave45,260,414,976. The2.5GiB pool overlap alone would leave88,864,149,504. Neither route alone establishes a fit, and no unchanged fit retry or epoch173 admission is justified by this packet.
