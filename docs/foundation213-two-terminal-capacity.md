# Foundation epoch 213: closed two-terminal capacity basis

This source candidate adds the separate basis schema
`jetstreamer-foundation-holding-terminal-pair-basis-v2`. The old v1 basis and
its strict five-owner continuation guard wrapper remain unchanged. The v2 path
permits only the actual healthy replay owners for epochs 225, 209 and 223 after
both original epoch 204 and epoch 205 producers have naturally completed.

The closed basis contains `schema`, `observer`, `fleet`, `inherited_capacity`,
`historical_guards`, `protected_guards`, and `terminal_originals`. Every file
binding has an absolute `path` and lowercase `sha256`. `historical_guards` has
exactly the original five owner keys. `protected_guards` has exactly the three
current replay owner keys. `terminal_originals` has exactly keys `204` and
`205`; each contains `launch`, `producer_result`, `terminal_properties`, and
`manager_journal` bindings. Unknown fields are rejected.

The terminal proof binds each original launch path and digest, invocation,
executable and snapshot digests, canonical target root slot, successful child
exit, absent external signal, natural producer completion, and unchanged
terminal command. It checks immutable root-owned sealed evidence and the
complete actual PID 1 journal in the current boot. The history must include one
Started event and one natural success, with unique ordered event cursors and
clocks, and no failure or forced stop. Current ownership must still be genuinely
inactive or collected. Before/after census and journal comparisons reject a
replacement invocation, live-original race or changed history. Pending triggers
remain disallowed. A scanner or new native job is a competing live owner.

`inherited_capacity` binds a sealed old v1 capacity result, directly or inside its
v1 restoration admission. That result must bind all five historical guard
receipts. Its old fleet must retain exactly the five original owners, and every
historical diagnostic launch must occur exactly once in the new fleet. The new
fleet and observer remain byte-bound inputs. Admission requires the actual
fresh accepted fleet; an older fleet cannot be relabelled as fresh.

All five original guard floors remain charged, including floors belonging to
terminal producers. Each current guard retains its original sealed plan, owner,
invocation, minimum floor, stop semantics and caps. Only the three genuine live
guards enter the unchanged peer growth checks. Current completed protective
fires and active timers are checked throughout continuation. The protected
minimum is the maximum of century floor plus current live growth, current guard
floors, all five historical guard floors, inherited capacity minimum and the
running restoration's held minimum. Checked arithmetic and actual free-space
checks apply. A typed continuation preserves its original entry clock and can
hold or raise its existing reservation.

No memory release or disk reclamation is credited. No observer bytes or host
memory bytes are rewritten. The returned capacity schema is
`jetstreamer-foundation-holding-capacity-v2`; it records historical floor and
terminal evidence, current guards and censuses, and zero reclamation credit.
It authorizes no replay launch, local retirement, publication or R2 mutation.

The included fixtures are static parser inputs derived from sealed metadata;
`fixtures/provenance.json` records their source hashes. The unchanged journal
and launch bytes preserve historical markers. These fixtures do not represent
new resource observations or authorize service operations. At source freeze,
rustfmt parsing and whitespace checks are available; Cargo qualification and
production build require the coordinator's separate serialized target grant.
