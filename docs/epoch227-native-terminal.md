# Native227 terminal handoff

This handoff proves only the exact bounded cold-input attempt. It never launches
entry replay, changes an epoch completion gate, or grants archive publication.
Use the scheduled observation or a single positive terminal notification; do not
add another polling loop.

Source integration adds `mod singleton227_terminal` in `fleet.rs`, exposes
`capture_native227_terminal()` forwarding to `singleton227_terminal::capture()`
and `native227_terminal_status_identity(&Value)` forwarding to that module, and
adds CLI alias `capture-native227-terminal SPEC --spec-sha256 SHA --self-sha256 SHA`.
Route metadata schema
`jetstreamer-private-epoch227-native-input-terminal-event-v1` through
`singleton227_terminal::terminal_predecessor` alongside the native223 terminal
branch. Call `singleton227_terminal::terminal_census(&plan,&before)` alongside
native223's terminal census. Preserve pipeline claims and tracked units.

For inactive-status cleanup, add `mod native227`, recognize only epoch227 with
`native227::recognized(terminal_fleet, owners)`, call `native227::validate`, and
exclude that positively validated case from generic terminal-owner validation.
Keep the ordinary fresh census, queued-trigger checks and conditional R2
status deletion/readback gates.

Successful native qualification uses `capture-singleton227` with the existing
schema and `mode: native-cold`, `native_running: false`, plus mandatory
`running_origin` and `terminal_fleet` bindings. Preserve the original admission,
first successful native guard sample and guard-plan bindings. `running_origin`
binds the already registered intent; `terminal_fleet` binds the current accepted
fleet. Output is `/var/lib/jetstreamer/horizon-227-capture-native-terminal-v2/native.json`.
Seal the spec before execution. The admission's900-second window applies to
the original producer start and initial guard/capture, not terminal capture.
PID1's successful terminal journal outcome must still fall within the2700-second
bounded attempt. Preserve the exact original start and terminal elapsed time
when systemd clears current invocation/PID fields.

Then capture the lifecycle event using schema
`jetstreamer-private-epoch227-native-terminal-capture-spec-v1`, with bindings
`running_origin`, current `observer`, current accepted `fleet`, successful
`native_qualification` (or JSON null for a positively proven failed attempt),
and `output: /var/lib/jetstreamer/horizon-227-terminal-native-v2/event.json`.
The output parent must be root-private and precreated. Seal the spec; execute
`capture-native227-terminal`. The tool preserves a bound `journal.json`,
requires the exact child IID/PID and unique PID1 terminal outcome, and brackets
the complete owner census without taking a resource sample.

For the same-sample terminal fleet, copy the current accepted plan, replace only
its previous-fleet/event bindings, event output path and227gate next action/
append-only evidence. Retain every claim, tracked unit, unrelated gate and
diagnostic. The227completion state remains unchanged. The event binds that
exact previous fleet and observer. On success, epoch227evidence may append the
event and native qualification bindings. On failure, append the event and leave
repair open. Reconcile and then use the accepted terminal fleet for inactive
status cleanup if no active replacement/downstream owner exists.

The running origin is
`/var/lib/jetstreamer/horizon-227-capture-native-running-v2/intent.json`, SHA
`e0534c1c38b26d29e75e2a0141d70e033d09f7b1dd80a837805f1218fb6492e5`.
Its owner IID is `60668cee1eb54c7fb5c235f8e7302aa6`, PID16750. Reuse the exact
guard and admission bindings from that origin, not a later timer sample.
