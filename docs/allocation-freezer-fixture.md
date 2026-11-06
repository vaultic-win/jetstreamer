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

The current source uses a fresh generation929 namespace; existing sealed925
artifacts and their original files remain unchanged. Three rejection modes
exercise a wrong writer invocation, a wrong cgroup inode and a missing rescue
timer against a real disposable writer. Each must fail at its specific binding
or rescue gate while the same writer continues advancing. Even an earlier gate
regression cannot freeze in a rejection mode: a final mode guard permits only
`normal` and `kill` to construct the freezer. These are additional native
qualification controls, not proof of handling a genuinely recreated cgroup,
partial freeze or a deactivating original owner.
