# Native191 verification dispatcher candidate

Source-only companion to the exact191 custody/pipeline profile. Nothing has
been compiled, tested, sealed or launched from this candidate. Rustfmt and
whitespace checks are the only completed checks.

`jetstreamer-r2 dispatch-verification-191 PLAN --plan-sha256 SHA --self-sha256 SHA
[--check-only]` dispatches one epoch/stage from191–194 after the real committed
source/public batches and native controller attestation pass the shared custody
checker. It compares the requested archive digest with the actual imported
member. Pending import still needs its real controller; post-import must support
that controller's independently proven natural completion, not demand that it
remain alive forever. The custody profile's terminal-lifecycle repair is still
being completed in its separate source worktree.

The separately sealed verification spec uses
`horizon-verify-canonical-pair-dev-samjohnson191-v1`. Its path is fixed beneath
`/usr/local/lib/jetstreamer/horizon-cohort191-verification-plans-20261023-v1`,
named `epoch-N-full.json` or `epoch-N-plugin.json`. The wrapper path is fixed at
`/usr/local/lib/jetstreamer/horizon-cohort191-delivery-tools-20261023-v1/`
`jetstreamer-horizon-verify-pair`; its SHA is separately bound. Qualified198
full/plugin reader hashes remain unchanged. The native wrapper independently
checks its spec, executable, exact service identity, archive/sidecar digest,
pre/post hashing and actual full/plugin success before mirroring a real gate
receipt. No existing failed range watcher is restarted or adopted.

Create the fixed dispatcher root and canonical-verification state root as
root0700 on the OS volume, plus an existing root0600 singly linked
`dispatch.lock` under the dispatcher root. Those preparations confer no launch
authority. Each task's output/state leaf must be absent. The dispatcher uses
an inode-bound exclusive lease, checks all eight exact native191 service names
for active/queued work, fsyncs a no-clobber intent, repeats custody/admission and
the service census, then invokes PID1 once. It captures the real new IID/PID,
executable, cgroup and process start ticks. A manager timeout or unobserved
start preserves intent and requires reconciliation; it never causes a restart.
The lease serializes only these native191 dispatchers. It does not claim to
mediate unrelated host allocations or old launchers.

Only one of these full/plugin services runs at a time. Each is Restart=no,
Type=exec, RemainAfterExit=yes, RuntimeMaxSec43200, CPU400%, memory high48GiB/
max64GiB, swap0,512tasks, UMask0077, PrivateNetwork, source/home read-only and
no R2 credentials. Writable paths are the exact OS state leaf and the matching
existing gate-receipt directory. Two full-check logs are individually limited
to16MiB by the kernel. Home writes are small genuine verification receipts;
archives, sidecars and replay scratch remain read-only. Record the ordinary
pipeline metadata allowance independently; no live growth claim is reduced.

Admission binds a fresh, same-sample v2 observer and actual routine completion.
The memory condition is current host RSS planning plus its complete memory
reservation ceiling, one64GiB verifier, a possible16GiB modern compiler and the
1GiB dispatcher. It uses the independently computed memory target; an invalid
capped186 replay budget must not be substituted or weakened. It retains the
exact old228833779142-byte OS budget and reserves520MiB for all eight bounded
verification tasks/dispatcher evidence. The coordinator must explicitly include
every additional outstanding OS claim in `other_pending_os_growth_bytes` and
review that census before sealing the plan. This scalar is an operator-owned
allocation declaration, not a claim that the tool discovers all host promises.
Fresh statfs must fit the full sum. No compiler, fixture, floor or claim is
released by the dispatcher.

Run the dispatcher itself in a separate nonrestarting root sandbox: CPU100%,
memory high512MiB/max1GiB, swap0,512tasks, UMask0077, PrivateNetwork,
TOKIO_WORKER_THREADS=2, TimeoutStartSec600, LimitFSIZE16MiB, source/home read-only,
minimal DAC/ptrace capabilities, and only the dispatcher/state roots and exact
gate receipt directories writable. Manager-client temporary files stay under
the dispatcher root. Its child services get their own declared limits above.

Before launch, run meaningful dispatcher tests, full R2/observer tests and
strict Clippy/fmt; reconcile the natural-terminal controller proof; build/seal
all tools/specs; qualify equivalent denied/check-only sandbox paths; and bind
fresh native import and resource evidence. Then dispatch the first admitted
stage. A waiting plan is not a live verifier. Subsequent stages need fresh
admission and actual predecessor completion; neither service-exit alone nor
the dispatch receipt is a full/plugin receipt. The forecast must represent
this serial queue explicitly, using genuine current owners and measured stage
progress. Real queued-manager coverage, source-revalidation-tail estimates,
delivery and boundary dispatch remain separate integration work.

Five source tests cover foreign scope/program/spec, competing/reused manager
states, growth-preserving memory/freshness bindings, the exact nonrestarting
network-isolated argv, and canonical clocks. They have not run. No result here
qualifies an archive, creates a sidecar, signals replay, retires local work or
mutates R2.
