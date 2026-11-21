# Normal 168 status registration

Start from the 44-member status publisher whose seal begins `76283826`.
Apply the post-trace 166 update from
`scripts/horizon_epoch166_terminal_20261121_v1/observer/RACE166.md`, then
apply `cadence.patch` at the package root with zero fuzz. Add `cadence168.py`,
`status168.py` and its classification fixture `status168_controls.py`.
In the composed `closed166.py`, select the normally sealed `cadence-tools-v3`
selector (ELF SHA-256
`43c67cdd9b7265d29ea806675a0a7aad5a2ef6384471452061b46d7465a00997`,
seal `e845cf376b7e55730cbfc4f3a4b89bf56fb8eac7398093bd3fcc7f62c04628ab`).
Test the assembled package against a completed native sample with both
`qualify_race166.py` and `qualify_cadence168.py`. Their positional inputs are
the assembled package, the preceding and succeeding accepted fleet paths and
a private HOME fixture directory.

The producer start intent and any held gate remain unadmitted. The first
guarded admission adds one ordinary bootstrap. A verified worker adds its
normal observer configuration to the next sample. Only a genuine positive
native log window advances the rate or transaction-progress count. The old
private diagnostic's terminal evidence and reserved space remain distinct.
Each cadence window freezes its first normal observation, including absence,
so the next-config, conditional status writes and fleet completion share a
single view if a new producer starts mid-cycle.

Before starting the replacement, verify the sealed 136 parent against this
same publisher. The sole status consumer must hold the original kernel
`consumer.lock` and the new `consume` inode. The registration helper reads
both seals and the private joint qualification and asks the parent to follow
the actual running consumer's seed to its current fleet. Under the existing
root publisher cutover, run `status_registration.py inspect` or `record` with
the publisher seal SHA-256, parent seal SHA-256 and joint qualification SHA-256.
The resulting registration binds the live status publisher invocation and its
start ticks. The independent 168 admission supplies the eventual producer
and worker identities after its guard and capacity checks.
