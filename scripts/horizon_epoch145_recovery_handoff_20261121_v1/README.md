# Original epoch 145 recovery handoff

Build the standalone `follow145` crate with the checked-in lockfile. Before
deployment, run its tests, Clippy, release build and the ignored native events
test as root with a private `HANDOFF_PRIVATE_FIXTURE` directory. The native
test consumes an already completed PID 1 invocation and exercises Linux
inotify and pidfd on a short-lived process.

The root metadata supervisor runs `follow145 inspect FLEET SHA PARENT SEAL`
to verify the original recovery and the current status publisher. The
`follow` subcommand takes the same arguments and the existing status
registration credentials. Provision its dedicated root-owned 0700 state
directory on the HOME-backed runtime. It obtains an exclusive lock, waits on
PID 1 for the original recovery generation, verifies the completed private
extraction and submits the sealed post-full verifier. Once its own guarded
start receipt exists, it follows the current fleet and existing epoch 136
admission and registration paths. Each launch intent is persisted before
submission. Reconcile an unanswered intent with the actual unit, journal and
receipts when recovering an interrupted handoff.

The qualified original path accepts only the five original peer identities
bound by the closed 168 trace. A failed recovery or a changed roster requires
the corresponding continuity provider. A successful fixture does not start the
post verifier, the 136 writer or a producer.

The two original terminal paths activate a single `route-outcome` oneshot.
`inspect-outcome` authenticates the current publisher, the original unit state
and the nineteen conditional status readbacks. The selector follows the
uninterrupted chain from the accepted 10:19 UTC fleet.

On an original success, the five-owner route uses the already sealed handoff.
After the accepted original 166 closure, the continuity provider can run
post-full with the completed archive. On an original failure, the selector
requires the same boot's PID 1 exit status, the failure marker and the accepted
166 terminal. It then submits the fixed-name v3 recovery and records its
protected start. The existing 168 admission session requires its own evidence
of the verifier child and leases before it can admit a producer. The controlling
operator handles the successful post-full to publisher transition using the
verified post invocation and a fresh accepted fleet.

Provision the two dedicated root-owned 0700 directories `state` and
`outcome-state` under the handoff runtime. Install the sealed unit files and
start the path unit. Both markers belong to the original invocation. A persistent
marker produces one dispatch. An existing submission without positively matching
native work requires operator reconciliation. A machine reboot requires a fresh
qualification of the previous-boot evidence. For the native negative/positive
cases, run both ignored tests individually with a root-owned private fixture.
