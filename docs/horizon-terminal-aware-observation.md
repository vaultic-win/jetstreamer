# Preserve observations across singleton completion

The ordinary observer requires every configured primary producer to remain live.
When a singleton finishes, its missing worker or retired scratch can reject the
entire sample, delaying status refreshes for unrelated healthy lanes.

`tools/horizon_terminal_aware_observe.rs` wraps the existing sealed observer for
Foundation singletons 247–251. Its root-owned, separately hash-bound plan names
the original observer config, each producer's sealed delivery-handoff plan, a
private state directory and a new immutable config deployment. Run:

```text
terminal-aware-observe check-plan|observe PLAN --plan-sha256 HEX --self-sha256 HEX
```

`check-plan` reads static bindings only. `observe` enforces the original routine
clock before reading any producer: at least 1,800 seconds after the previous
accepted sample and no earlier than the configured deadline. It does not create
an additional observation cadence or change an existing producer.

The prescreen requires the exact loaded unit, original invocation, zero restarts
and complete command from the sealed handoff plan. Active/running producers stay
in the ordinary observer. Inactive/dead or failed/failed producers with both
manager PIDs zero are recorded separately, with their raw result, exit status
and cgroup. Missing, replaced, restarted or transitioning owners fail closed.
In particular, omission is not a successful-archive or drained-cgroup claim.

The helper fsyncs the complete prescreen, filters only the terminal primary rows,
seals the effective config through the qualified Rust deployment sealer, then
runs the unchanged observer once. It rechecks omitted owners afterward and writes
a completion receipt. Every omission explicitly retains its reservations and
requires independent terminal handoff and full fleet reconciliation. No process
is signaled, no replay is launched and no R2 object is mutated.

For the same control cycle, the operator must:

1. Retain every original producer in the fleet's `tracked_units` and bind the
   prescreen/completion evidence. Inspect omitted owners' terminal history and
   capture the committed output through the singleton handoff helper. A failed
   producer remains an open repair; omission never removes it from the backlog.
2. Build the ETA model for exactly the successfully observed live ranges. A
   prewritten five-range model must fail after a terminal row is omitted; do not
   weaken that check. Publish downstream status only after binding its actual
   live owner and the original producer clock.
3. Preserve omitted owners' memory and disk obligations until the normal fresh
   admission proves their release. An observation with fewer primary rows is
   not permission to admit a replacement.

If every configured owner is terminal, the helper preserves its prescreen and
stops before calling the live-only observer. The operator must perform the full
terminal fleet transition. If a producer finishes during the ordinary sample,
the original observer still fails closed; preserve that attempt and use the
actual completion event to prepare the next transition. Do not restart a healthy
producer or overwrite an observation to repair monitoring.

Qualification includes invalid/missing/restarted/transitioning identities,
exact-command checks, clean and failed terminal classifications, original-clock
enforcement, invalid UTC dates, and a real bounded systemd live-to-terminal
transition. The native test reads only its own disjoint fixture unit. Production
deployment still requires published source, a sealed artifact and static plan
validation; no production terminal event is claimed by these tests.
