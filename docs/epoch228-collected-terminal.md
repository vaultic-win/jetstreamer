# Exact native 228 collected-terminal recovery

This adapter preserves the real not-found state of the transient native-input
unit. It does not recreate a unit, rerun a Bank, start a process, or access R2.
The generic loaded-terminal validator continues to reject not-found defaults.

Only original IID `1b207be826cc45979d5a92a44de4bd14`, PID 297588, captured origin
SHA256 `f53486f4fca27ae950f0af4412d262e5f1946769f2cdbe97ae62c8fc1193a349`
and sealed canonical journal SHA256
`5894b7b9c0e612f8e10d984fe22a8d4087b3cca522d076f2d7ecd3b690325710`
are eligible. Existing terminal verification still independently checks the real
98495291/Gfi marker, all raw consensus integers, the exact test success, original
PID/IID, PID1 success, immutable input bindings and2700-second execution bound.

Capture additionally requires a fresh accepted observer/fleet containing exactly
this registered 228 pipeline claim, no other staged/live228 owner and the existing
blocked-qualification gate. It brackets the complete producer census, preserves
all other owners (including full 209), checks the original cgroup is absent, reads
the complete discovered service/job tables, and validates fresh original-unit
PID1/child history from before the original start. Missing starts, later starts,
foreign IIDs/PIDs, queued 228 work, loaded replacement units, any retained cgroup,
or a changing census fail closed. No additional replay/resource sample is made.

The terminal proof stores a hash-bound-to-inputs collected_terminal witness with
both actual metadata snapshots and raw manager history. Historical validation
uses those immutable captured observations; it does not create a permanent
requirement to retain the live journald history. The immediate terminal-event
reconciliation repeats current no-owner/no-replacement checks. Neither path grants
full-epoch qualification, runtime promotion, archive/sidecar publication or R2
mutation authority. No status deletion is required for this attempt: a228 status
object was never published.

The existing capture-native228-terminal command/spec schema is retained. Root
must supply a NEW immutable spec bound to its latest accepted observer/fleet and
a new absent proof output; the old 004f... spec cannot discard full 209 or later
accepted history. The adapter chooses the narrowly pinned collected path only
when the actual unit is not-found. Loaded units retain the ordinary strict path.

The ignored read-only end-to-end actual-host regression accepts the pair
`HORIZON_NATIVE228_CHECK_SPEC_PATH` and `HORIZON_NATIVE228_CHECK_SPEC_SHA256`.
They select only a separately sealed capture spec, not replacement origin/journal
pins. Both must be set together. The default is root's337/v2 spec; after that
sample expires, supply the new current338-or-later spec without rebuilding or
backdating any clock. It exercises the same checked_proof path as capture and
asserts the proof output remains absent. These variables exist only in cfg(test).
