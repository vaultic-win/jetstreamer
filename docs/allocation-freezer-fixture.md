# Disposable allocation/freezer fixture

`jetstreamer-allocation-freeze-fixture` qualifies one small local fixture. It
cannot target a replay: the writer unit, cgroup and private data path are fixed
constants. Its output grants no admission, allocation credit or live-freeze
authority. A complete invocation is independently sealed and separately admitted.

The Ubuntu writer creates a fresh 8 MiB mmap file and readiness marker, then
updates an atomic counter for at most 150 seconds. The Root driver binds the
writer's actual systemd invocation, PID/start ticks and cgroup device/inode,
checks a separately armed rescue timer's typed monotonic deadline and its real
rescue executable/argv, ignore-errors policy and finite service limits, and fsyncs a
no-clobber freeze intent before freezing. Its normal mode confirms the counter
stops, checks ext4 FIEMAP data extents, thaws the fixture and confirms progress
resumes. The killed mode deliberately SIGKILLs only its own fixture driver after
freezing, to exercise independent recovery. A destructor provides an additional
thaw attempt for ordinary errors; it is not the SIGKILL recovery mechanism.

The independent rescue verifies the same sealed plan, original writer and
freeze lease, writes thaw only through the exact fixture cgroup descriptor, and
confirms the counter resumes. Caller-owned Root state directories must already
exist with mode 0700. Plans and executable digests are explicit. The writer's
directory must be fresh, Ubuntu-owned and mode 0700. No invocation can overwrite
an earlier data file, lease or completion receipt.

Qualification requires both actual native normal and killed-driver outcomes,
their full PID1/payload journals, unchanged writer identity, real rescue timer
execution, and negative controls. Pure tests alone do not establish freezer or
recovery support. FIEMAP in this fixture covers one fixed data file; it does not
qualify traversal of a live replay tree, external-writer closure, host memory
accounting or a resource reservation reduction. Those remain separate work.

Generation929 used a fresh namespace; existing sealed925
artifacts and their original files remain unchanged. Three rejection modes
exercise a wrong writer invocation, a wrong cgroup inode and a missing rescue
timer against a real disposable writer. Each must fail at its specific binding
or rescue gate while the same writer continues advancing. Even an earlier gate
regression cannot freeze in a rejection mode: a final mode guard permits only
`normal` and `kill` to construct the freezer. These are additional native
qualification controls, not proof of handling a genuinely recreated cgroup,
partial freeze or a deactivating original owner.

Generation930 gives each genuine writer invocation its own no-clobber directory
under the fixed fixture root. A controlled stop and fresh invocation can therefore
exercise a genuinely recreated cgroup while preserving the original generation.
The bounded writer has 32 CPU-only threads to make a pending freeze observable;
its SIGTERM handler records a signal-safe flag and allows 20 seconds of fixture
shutdown. The external service must retain a longer stop timeout for this case.

The `pending-kill` driver requires an actual pending transition, records it and
kills itself before waiting for freeze completion. Rescue cancels the original
request even when `frozen=0`. Failure to observe a pending transition is an
unqualified control, never a passing partial-freeze test. The `deactivating`
driver requests stop of only the fixed writer, authenticates the original
shutdown identity, then freezes and kills itself. Rescue accepts that same
original PID/IID/cgroup during its narrowly supported shutdown states. An already
terminal original with an absent cgroup produces a nonacting closure receipt;
a replaced invocation or extant replacement cgroup cannot use that path.

These source routes still need their actual native controls before qualification.
They remain confined to disposable fixture generations and grant zero live freeze,
resource credit, replay, publication or retirement authority.
