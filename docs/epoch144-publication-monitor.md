# Exact epoch144 publication ownership

`jetstreamer-publication144-track` captures the separately admitted exact V4
publisher; it cannot launch it, copy an archive, publish a checksum, or call R2.
Seal the tool and its strict root-owned immutable plan before use:

```text
PLAN --plan-sha256 SHA --self-sha256 SHA --check-only|--capture|--terminal
```

Plan schema `jetstreamer-exact144-publication-owner-plan-v1` contains only
`publisher_plan` and `capability` path/SHA-256 bindings in addition to `schema`.
The former must bind the separately sealed v2 publication plan and its qualified
four-producer envelope. The latter must prove the exact v4 publisher's actual
filesystem/UID/GID/Landlock capability. Check-only validates inputs without
querying a live owner or writing a receipt; it is not admission or launch proof.

The fixed service is `horizon-publish-144-v4-20261022-v1.service`.
Capture authenticates its complete command, current invocation and zero restarts,
live oneshot state, root configuration, six-hour start timeout, resource limits,
minimal capabilities, read-only home/system, private network, and writable mounts.
The common `/home/sol` writable mount preserves rename identity; the publisher's
own Landlock policy independently confines mutations to its exact stage, public
directory, and receipt root. Capture also binds the publisher's already-fsynced
admission intent and repeats the owner query before writing a no-clobber,
fsynced, mode0400 `launch.json` beneath the precreated root-private
`/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1` directory.

Terminal mode requires the same invocation, command and limits with no main PID.
It preserves success or failure as `terminal.json`; even success explicitly does
not prove archive verification or an R2 ready pair. Preserve failed copies and
transaction receipts. Do not restart a failed no-clobber publication in place.

## Fleet and routine adoption

The source routine helper accepts `--prepare-next-publication144 SPEC
--handoff-sha256 SHA`. The immutable spec has schema
`jetstreamer-exact144-publication-monitor-handoff-v1` and one `launch` binding.
It consumes only a genuine captured launch, retains all prior private/native
and scanner histories, and switches only to the pinned superset fleet reader.
The routine generation gets a distinct namespace; ordinary replay claims,
observer scope, ETA formulae, and cadence remain unchanged. Stop/prove the old
pending timer pair inactive before launching an owner it cannot census. After
capture, seal and sandbox-preflight the adopted successor before arming it.

The fleet uses the existing `local-publication` pipeline contract. A completed
diagnostic retained as active/exited is history, not a concurrent owner; running
and activating diagnostics still conflict. The revised reader has a regression
for this distinction. The routine preserves a qualified newer publication gate
while revalidating older private history; unknown gate actions still fail closed.
A failed publisher becomes failed-needs-repair, never disappears from the queue.
Clean service termination leaves a delivery action open, never remote-ready.

This addition is not permission to start an unmonitored job. Before real launch,
qualify the sealed tracker/reader/helper on-node, the fresh v2 admission, the
exact timer handoff and terminal capture, pipeline dashboard status/ETA support,
and downstream full/plugin uploader directories/hashes. The publication profile
currently records no fabricated replay ETA. Active publication requires its own
evidence-bound pipeline estimate through the normal status writer. No archive,
sidecar, retirement, runtime promotion, or R2 authority follows from monitoring.

## Delivery timing evidence

`jetstreamer-publication144-calibrate --self-sha256 SHA [--check-only]` reads
only four exact epoch198 uploader journal markers and a separately sealed copy
of its verified R2 receipt. It binds the original unit, invocation, PID, UID,
executable, message ordering, complete byte length and final verification time.
It rejects missing, duplicated or differently owned events. No resource sample,
network request or archive hash is performed.

The no-clobber private calibration receipt records measured local hash, upload,
and readback/revalidation durations. Its forecast scales each by the complete
144/198 byte ratio, keeps three hash-equivalent import passes separate from the
uploader's own hash/upload/readback work, and adds ten minutes for dispatch.
This is a forecast, not a publication gate, capacity claim, guaranteed bound or
permission to start. Consume it through a separately bound live pipeline model;
do not invent a launch timestamp or silently reset an overdue deadline.

The status writer's UID1001 receipt-directory exception is separately scoped to
epoch144's exact captured canonical-artifact publisher origin and its fixed
publication/upload service names. The original198 exception remains unchanged.
An arbitrary144 job, another origin receipt, another epoch, or a generic launch
cannot borrow either exception. Elapsed execution still comes from the actual
root systemd manager start event. This source support alone neither publishes
an ETA nor qualifies a downstream uploader.
