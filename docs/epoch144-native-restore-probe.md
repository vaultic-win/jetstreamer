# Private epoch 144 native comparison

The separate `jetstreamer-epoch144-native-restore-probe` executable requires
`epoch144-native-restore-diagnostic`. It does not change the ordinary node CLI,
worker protocol, runtime registry or immutable v1.4.25 worker. It reuses the 140
probe's existing client, full native comparison and immutable-I/O helpers at
crate visibility only; the 140 plan, source checks and execution behavior remain
unchanged. Its own strict 144 plan cannot borrow the 140admission or source profile.

The executable plan uses schema
`jetstreamer-private-epoch144-native-restore-probe-plan-v2`:it contains an
`inputs`binding and an `admission_receipt`binding only. Seal the strict
`jetstreamer-epoch144-native-input-policy-v1` first, then admit that policy and
write a `jetstreamer-epoch144-native-admission-receipt-v2`, then seal the final
plan. The receipt binds `input_policy_sha256`, not the final plan hash. This
one-way order avoids a circular dependency on its own receipt hash. The earlier
dormant 5c46probe's V1layout was never launched and must not be selected.

The standalone `--check-inputs-only POLICY --policy-sha256 HEX
--self-sha256 HEX --receipt ABSOLUTE_NEW_RECEIPT` path authenticates the exact
policy,worker/genesis/prefix/clock and full compressed snapshot under UID 1001,
but never spawns a worker. It guards free space on every compressed read and
revalidates the input identity. The receipt explicitly denies native/replay
authority. This can qualify a private systemd read-only bind of the original
root-private frozen snapshot into a dedicated `/run` input view, without copying
it or changing its original 0700ancestor permissions. Use `PrivateMounts=yes`,
read-only home/system/input bindings and no worker DAC capability. Such a bind
does not remove the executing client's own mandatory private hash-bound copy.

`jetstreamer-r2 admit-native144 SPEC --spec-sha256 HEX --self-sha256 HEX`
is the separate resource gate. Its strict spec retains the existing observer,
full fleet/plan,protection,floor and metadata bindings, and the `downloader`
field names the exact native probe. A mandatory `native`object binds `inputs`,
`capability` and `resource_proposal`. It requires the exact completed input
capability and unchanged frozen source identity; recomputes the audited century
floor; reauthenticates every older live owner through two complete censuses; and
requires 40 GiB above all retained claims, 192 GiB available memory including reserve,
and the existing host VMA ceiling. Snapshot/clock modes cannot borrow this spec.
The receipt binds the input-policy hash and explicitly leaves guard/fleet launch
gates required. No `OnSuccess` trigger or worker is started by admission.

The source tuple comes mechanically from the hash-bound original 144segment
manifest and independent focused-prefix pass. The separately verified snapshot
and typed serialized-clock receipt must match that tuple before initialization.
It preserves exact u64consensus fields and independent raw write-version cursors.
The exact worker 2cca5001initializes from the full SHA-bound compressed copy,
freezes 62639490 and compares slot,bank/accounts hashes, lastblockhash, capitalization,
transaction count, tick height, complete state and ticks-per-slot. Bootstrap writes
must be empty and the worker's own initialized cursor must remain unchanged.
No replay entry-processing API is called. Shutdown and comparison outcomes are
recorded separately; the admitted scratch is censused before client teardown.
That census is diagnostic resource evidence, not a deletion or full-cold budget.

The dormant probe requires its own exact native-only admission receipt, 40 GiB
incremental scratch budget above all4,740,696,923,590older-growth/floor bytes,
fresh actual free space and inode/VMA checks. Immutable snapshot-package copying
is additional admission debt before the copy exists. The measured source has
14,549,543,345logical bytes and 392,250members; the client makes one private 2.57 GB
compressed copy. The worker extracts once and the pinned runtime renames
AppendVecs into same-filesystem account paths, with a per-file fallback move.
Use the separately sealed resource analysis for conservative rounding/metadata/
copy allowances; these facts are not authority to skip fresh admission.

Before launch, seal and attest the exact inputs/probe/plan;qualify the no-replay
capability path, the standalone invocation-bound reserve/VMA guard and the full
fleet's private native-diagnostic capture/profile. Launch under observation as
UID 1001 with rayon 2 and explicit control60s/initialize900s/checkpoint600s/reap120s
timeouts, non-restarting persistent systemd,CPU/memory limits and isolated private
scratch/output. Prove the real sandboxed guard before unattended execution.
No native owner has been launched merely by building or testing this tool.

A successful native-only proof does not authorize suffix replay. The actual
executing suffix worker must repeat the full native barrier before any entry;
509slots,provenance-aware assembly, independent final/current-plugin gates,
canonical import and authenticated R2 delivery remain independently required.
Preserve the original prefix and all inputs on any failure. Never cold-replay
the verified prefix, force cursors equal, or use epoch 213's build-bound continuation.
