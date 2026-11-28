# Private 144 natural completion and stale status

The exact `ea4a8069…` focused diagnostic finished successfully on October 21.
PID 1's authenticated manager journal records clean deactivation at 17:14:37 UTC;
the installed unit is now inactive/dead with its invocation ID cleared. That is
not a complete epoch: the private segment ends 62639490,509 slots short of the
epoch end. Preserve it for an independent reread and later qualified recovery.

The inactive-status path accepts this one owner pair only through the separately
sealed `jetstreamer-private-epoch144-focused-terminal-evidence-v1` evidence and
exact segment-manifest digest. It repeatedly authenticates PID 1's latest start
and clean deactivation of that same invocation. Missing journal, newer start,
different invocation, nonterminal unit, failed outcome or changed manifest fails
closed. The original full claim census, pending-job/trigger checks, latest owned
publication/payload/ETag gates, remote delivery checks, conditional status-only
delete, authenticated absence and durable intent/completion remain mandatory.

Only the exact accepted 17:38 completion may normalize its own metadata oneshot
row from activating to successful/exited under the same invocation and command.
Every other census row must remain identical. This does not generalize terminal
proof to another producer or grant replay, archive/sidecar publication, runtime
promotion, retained-data retirement or any archive/sidecar mutation authority.
