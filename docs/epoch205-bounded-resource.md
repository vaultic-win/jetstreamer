# Dormant epoch-205 resource measurement

The opt-in `epoch205-bounded-resource` feature builds
`jetstreamer-epoch205-bounded-resource` using the existing reviewed bounded
runner. It pins parent `025757b9…`, v1.6.16 store 8 worker `3f5e8efe…`, the
generation-bound 88,559,361 bootstrap and the exact 88,991,050 checkpoint.
The private target is 88,584,000, well before that checkpoint and the canonical
epoch end. Reaching it is resource evidence only: it is neither complete-prefix
qualification nor a full cold-epoch peak measurement.

The profile has a 256-GiB scratch ceiling, six-hour execution bound, explicit
16-thread setting and a separate 416-GiB experimental envelope (256 scratch,
128 archive, 32 buffer). Its startup lower bound is only a rejection baseline:
the six-sample century floor plus that experiment. Fresh admission must
recompute the century floor, charge every older remaining-growth claim and
prove memory, CPU, VMA, I/O and filesystem safety. Never replace the old
4.8-TB optimistic complete-span projection with this smaller trial envelope.

The standalone guard recognizes only the epoch-205 target-stop schema at
88,584,000. Wrong-epoch, stale, pre-target, external-signal and extended-drain
evidence remains fatal. The shared runner freezes its own child group and
captures the live AccountsDb before controlled stopping, retains the actual
return code, and accepts code 1 only for its authenticated post-target stop.
No existing guard is upgraded or rearmed merely because this source exists.

Keep the candidate dormant until exact-package attestation/capability, fresh
complete admission, a separately supported fleet launch contract, invocation-
bound guard and its first real sandboxed fire are qualified. An impossible
free-space threshold may be used for a capability-only plan; it is not a launch
budget. Never install a timer or launch a fifth replay from this preparation.
Diagnosis and qualified recovery of any failed epoch-203 producer takes
priority over discretionary cold work.

The later full prefix would still leave 949 slots before epoch 205 ends.
Neither this bounded measurement nor an independently checked prefix supplies
an epoch-205 checkpoint-restart/suffix/assembly route. Those semantics require
separate qualification; the build-bound epoch-213 diagnostic is not reusable
under another epoch label. Keep every new artifact private and sidecar-free.
