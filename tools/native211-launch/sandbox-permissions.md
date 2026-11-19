# Native211 launcher permission qualification

This new binary qualifies the launcher permission envelope with disjoint native
fixture units. It never starts the epoch211 harness, uses its unit names, reads
snapshot bytes or creates a production guard token. The intended launcher is the
already sealed `248c9b49` artifact, SHA
`de4d986c624bc462f687923efd99d8d5846b6ab1c2f969fd46993ebaadb00821`.
This source preparation has not been built or executed.

Main builds/tests/Clippy-checks **`--bin sandbox-permissions`** in the existing
bounded serial build envelope, publishes its source, and seals the binary as:
`/var/lib/jetstreamer/horizon-native211-permission-fixture-20261119-v1/sandbox-permissions`.
The default launcher source and accounting are unchanged by this additional bin.
Main replaces the deliberately invalid fixture hash in
`sandbox-permissions.plan.example.json` with that actual artifact hash, reviews
its pinned launcher and evidence, and seals the plan at:
`/var/lib/jetstreamer/horizon-native211-permission-fixture-plan-20261119-v1/plan.json`.
No permission acceptance is present in the example.

Before running, Main accounts the **256 MiB supervisor plus 16 MiB reader and
16 MiB timer service** (288 MiB total hard cap, swap zero) in the current complete
control booking. Main creates only the disjoint empty directory
`/home/ubuntu/.jetstreamer-private/native211-permission-20261119-v1`, uid/gid1000,
mode0700. Every fixture output directory and unit name must be unused. On a
failed attempt use a new reviewed attempt suffix; do not overwrite evidence.

The exact candidate command is below; replace `PLAN_SHA256` with the sealed
plan's actual SHA. The fixture checks its own mapped image against the plan.
This is for Main execution only after source/build and capacity review:

```sh
sudo /usr/bin/systemd-run \
  --unit=horizon-native211-permission-20261119-v1 \
  --service-type=exec \
  --property=User=root --property=Restart=no \
  --property=KillMode=control-group --property=Delegate=no \
  --property=MemoryMax=268435456 --property=MemorySwapMax=0 \
  --property=TasksMax=64 --property=CPUQuota=100% \
  --property=AllowedCPUs=48-55 --property=CPUAffinity=48-55 \
  --property=RuntimeMaxSec=180 --property=TimeoutStopSec=15 \
  --property=ProtectHome=read-only --property=ProtectSystem=strict \
  --property=PrivateNetwork=yes --property=PrivateTmp=yes \
  --property=NoNewPrivileges=yes \
  '--property=CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' \
  '--property=AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_SYS_PTRACE' \
  '--property=ReadWritePaths=/var/lib/jetstreamer /etc/systemd/system' \
  --property=UMask=0077 \
  /var/lib/jetstreamer/horizon-native211-permission-fixture-20261119-v1/sandbox-permissions \
  qualify \
  /var/lib/jetstreamer/horizon-native211-permission-fixture-plan-20261119-v1/plan.json \
  PLAN_SHA256
```

Writable publication/unit **parents** are intentional: the unchanged launcher
creates absent child destinations, the actual sealer creates hidden sibling
staging directories before rename, and unit installation creates absent links.
A mount allowlist of absent final leaves cannot do this. This broader parent
mount envelope must be explicitly reviewed by Main; the fixture does not claim
that filesystem permissions restrict writes to its own names. Its own code
restricts mutation to deterministic disjoint fixture names.

What it actually proves:

- Same effective supervisor filesystem/capability/memory/task settings; actual
  kernel limits, read-only home/system and writable required parents; retained
  mountinfo, sealed evidence and the old launcher's committed Git source read.
- Actual local PID1 bus access in a private network namespace.
- Exact sealed Rust sealer creates, fsyncs and atomically publishes immutable
  packages; repeated publication fails without modifying the first receipt.
- Four no-clobber persistent unit links and daemon reload; ordering-only target
  activation does not start the ubuntu reader. The reader has 16 MiB/8 tasks,
  swap zero and a 60-second service bound (45-second internal token wait).
- Root supervisor reads the other-user reader's executable, maps, status and
  cgroup while the producer is live, with exact image and kernel limits.
- A genuine disjoint timer fires `/usr/bin/true`, produces PID1 start/end events,
  and has a typed future monotonic next deadline. This exercises permission and
  manager paths; it does not qualify the actual protective guard's behavior.
- Root token namespace creation, actual IID subdirectory publication with
  `guard-admission.json` and a digest sidecar; uid1000 reader traverses/reads it
  and writes its own allowed scratch. The token has a deliberately unrelated
  fixture schema and never enters the production namespace.
- Original reader terminal IID/success and process drainage survive target
  restart; exact fixture links are removed and manager reloaded. Cleanup also
  runs on failure, and refuses changed links/fragments or a replaced reader IID.

Evidence is retained in
`/var/lib/jetstreamer/horizon-native211-permission-20261119-v1-execution/`.
Require both `qualification.json` **and** `cleanup.json`, successful actual
supervisor terminal status, and no `failure.json`/`cleanup-failure.json` before
Main accepts permission qualification. Every subprocess is bounded to ten
seconds, with a 110-second work deadline and separate 30-second cleanup budget.
Main must inspect and retire only exact fixture units if the supervisor is
externally killed before cleanup; the reader still has its independent runtime
bound. Immutable fixture outputs and scratch remain available for audit.

After acceptance, the actual launcher must use the same reviewed permission
properties and its separately booked cap, with exact expected ExecStart in the
fresh control census. Source publication, prestart capability acceptance, fresh
fleet/ledger admission and the actual native guard first-fire/token checks remain
mandatory. Permission success never sets native startup/input/replay/publication
qualification or grants R2 mutation.
