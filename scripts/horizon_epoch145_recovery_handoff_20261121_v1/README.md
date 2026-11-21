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
