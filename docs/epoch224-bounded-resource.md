# Private epoch-224 repair measurement

Build `jetstreamer-epoch224-bounded-resource` from `jetstreamer-utils` with
`--features epoch224-bounded-resource`. This is preparation for a separately
admitted diagnostic, not an ordinary replay, root qualification, or upload path.
Do not change an already-running replay to use it.

The profile pins the existing, content-attested epoch-224 v1.6.25 parent
`bcb76f90515465ee3b19486a18da907d15d4a3fbe310d66e0c3912a5daa4e257`,
worker `f26fb8598aef4091356be31a0ee322c2e428609f201390cce26ec60df9c62c45`,
and generation-bound snapshot at slot 96,767,522. It retains all three exact
checkpoint filenames from that package, including the intermediate root at
97,199,617. The parent's supported terminal remains 97,631,459; the runner
observes progress and deliberately stops its own private process group at
96,800,000, before any epoch or root qualification can be completed.

The fixed measurement uses 16 Rayon threads, a 72-hour maximum execution time,
and a 448-GiB terminal scratch-capture ceiling. Its proposed incremental budget
is 640 GiB (448 GiB scratch, 128 GiB archive, and 64 GiB guard margin). This is an
enforced experiment envelope, not a prediction that a full cold epoch fits.
The compiled minimum-free lower bound protects the five-sample century floor
of 234,739,760,267 bytes plus that budget. A launch plan must raise it to protect
**all** older invocation-bound remaining-growth claims using fresh coordinated
evidence and the current recomputed century floor. The compiled lower bound
alone is never sufficient admission.

Before execution, separately seal the runner and its owner-only plan, prove the
exact packaged parent accepts the intended arguments without replay, and admit
CPU, memory, I/O, VMAs, and disk. Only a fresh phase-admission generation may
release an older replay reservation after its terminal/delivery transition is
positively established; do not edit active guards or assume an upload is free.
Use a persistent non-restarting unit with isolated private output and scratch.
Immediately bind its actual invocation to the reviewed standalone reserve/VMA
guard, including the copied worker path and target-drainage handoff, and require
the first real sandboxed guard fire to succeed before leaving it unattended.

For the exact private command probe, the reviewed
`jetstreamer-focused-capability-probe` plan accepts
`"epoch224_bounded_measurement": true` only for this epoch and parent digest.
It uses the runner's `ledger` and `output/epoch-224-canary.jet` layout while
retaining the complete-span route, three checkpoints, deliberately absent
snapshot, full package hashing, no-artifact checks, and process-reference scan.
Older plans omit the field and retain their original layout. This capability
receipt does not test snapshot restoration or authorize replay.

The shared runner freezes its child group to preserve live AccountsDb resource
measurements before controlled shutdown. Its no-clobber receipts distinguish a
target stop from pre-target failure, timeout, or external stop. Neither a target
marker nor a bounded success grants canonical checkpoint, full-epoch peak,
current-plugin, publication, sidecar, retirement, or R2 authority. Preserve the
failure evidence and keep epoch 224 in the open-repair backlog until a qualified
recovery reaches a verified R2 ready pair.

Use the existing 30-minute coordinated observer for useful-work and growth
windows; do not introduce another replay polling loop or public countdown for
this private diagnostic. Compare restore baseline and settled incremental
scratch/VMAs against transactions and account updates. A short success must not
be extrapolated into a full-span peak without evidence of nonlinear growth.
