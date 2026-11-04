# Inactive dashboard status cleanup

`jetstreamer-r2 status-delete-inactive PLAN --plan-sha256 HEX --self-sha256 HEX
[--check-only]` is a separate path from completion-only `status-delete`.

The general campaign command, added concurrently by the other host, is
`status-retire-inactive`; see [its contract](horizon-inactive-status-retirement.md).
This narrower profile supplies additional host-specific process, local-artifact,
remote-inventory and multipart checks for the original 183–186 incident. Both commands
delegate to the same canonical-key, ETag-conditional mutation boundary. Qualify
the chosen command and plan explicitly; do not mix their receipt schemas.

The profile intentionally supports only epochs 183, 184 and 186 from the failed original 183–186 owner on
dev-samjohnson. It binds the exact controller/producer invocation IDs, pinned
terminal incident, latest authenticated status publication, historical owner
observer, current complete-range fleet, and persistent open repair backlog.
It does not grant archive completion, replay, retirement, or incident closure.
Extending it to other failures requires source review and separate qualification;
do not change plan fields to impersonate this owner.
Epoch 185's live replacement is explicitly excluded. Epoch 186's new dormant
controller is not the old status owner; its terminal/no-trigger state and the
complete absence of active or queued replacement work must still pass every gate.

The root-owned sealed plan names the actual campaign directories, bucket,
unique intent/completion paths in an existing root-private directory, and exact
passive watcher identities/commands. Only the explicitly reviewed idle receipt
watchers may be excepted. They still cannot hold the target archive open. The
tool examines all loaded service commands, queued jobs, terminal owner state,
automatic triggers, and process commands/maps/cwd/root/exe/descriptors. A failed
observation, permission denial, replacement, queued launch, archive reference,
canonical local artifact, remote staged pair, or multipart transfer fails closed.
The current operational range assignment must remain disjoint across hosts;
this tool is not a distributed lease or authority to disregard another host's
authenticated handoff. Do not execute it when such a handoff exists.
The plan must set `exclusive_local_epoch_ownership: true` and explicitly supply
`authenticated_other_host_handoffs: []`; both fleet sample and receipt expire
after 30 minutes.
When systemd has cleared a loaded, successfully stopped controller's invocation
ID, the narrow profile additionally requires the root manager journal's latest
lifecycle to name the exact original invocation and contain its completed stop
after its last start. That journal proof is retained in the census receipt;
empty identity alone never establishes ownership or terminal success.
The full census accepts canonical systemd `\xHH` escaped service names and
checks pre/start/post commands. A valid stop-only service with no start command
is inert only with an explicit zero-PID terminal or active/exited state; a
missing command for a live process remains a failed observation.

`--check-only` authenticates remote status bytes/ETag, checks current archive
inventory and multipart transfers, and performs the local census without writing
an intent or making a remote mutation. Production rechecks claims and publication
ownership, fsyncs a no-clobber intent, conditionally deletes only the derived
`epoch-N.epoch-status.json` key using its exact ETag, verifies authenticated
absence, rechecks claims and remote delivery, then fsyncs completion. A 412 is a
hard stop, never an unconditional retry. Interrupted work may recover only with
its matching intent and evidence; unexplained absence is not successful cleanup.
If the old fleet evidence has expired, preserve the intent and investigate rather
than changing its bound plan or bypassing freshness. A new owner after deletion
requires normal evidence-bound fresh status publication; no completion receipt
is written for that race.

Publication/deletion receipts and the open repair backlog are retained. Removing
stale metadata never marks these epochs ready. A passing unit test, source commit,
or documented policy is not evidence of deployment or authenticated cleanup;
record those separately after sealed qualification and actual execution.
