"""Recognize the single bounded 142 node seen during the failed V5e census."""
import hashlib
import os
from pathlib import Path
import resource
import subprocess

R = Path("/var/lib/jetstreamer/horizon_runtime_data")
Q = R / "epoch142-full-local-20261122-v1"
INCIDENT = R / "incident-replay-fit-20261121-v1/QUALIFICATION142_CENSUS_INCIDENT.json"
INCIDENT_SHA = "631041d26e076071eed0cc4423d62d97ad661ac388f1aa64af6ab29c43b0e9bd"
ROUTE_SHA = "178c49f3c0deedbbeb2dd614515f88cb1259cb5900ba9a3e433078b4e850fe1a"
BOOT = "763ea84ca81f4dddad364b1ea2ba36dd"
UNIT = "horizon-142-full-local-qualification-20261122-v1.service"
IID = "42466cf599e7429889a778a68376c5ed"
PID = 227497
GROUP = "/horizonaudit.slice/" + UNIT
MEMORY = 192 << 20
SCRATCH = 8 << 20
STATIC = ("Id InvocationID ExecMainPID ExecMainStartTimestampMonotonic Slice NRestarts ControlPID Job "
          "User Group NoExecPaths ExecPaths LimitFSIZE LimitFSIZESoft MemoryMax MemorySwapMax TasksMax "
          "NoNewPrivileges PrivateNetwork ProtectSystem ProtectHome PrivateDevices ProtectControlGroups "
          "RuntimeMaxUSec CPUQuotaPerSecUSec CapabilityBoundingSet BindPaths BindReadOnlyPaths").split()


def contract(s):
    incident, _ = s.read(INCIDENT, INCIDENT_SHA)
    route, _ = s.read(Q / "ROUTE.json", ROUTE_SHA)
    native = incident["managers"]["qualification"]
    settings = {key: native[key] for key in STATIC}
    settings.update(ActiveState="active", SubState="running", ControlGroup=GROUP, MainPID=str(PID))
    s.need(native["InvocationID"] == IID and native["Id"] == UNIT and incident["boot"] == BOOT,
           "foreign 142 qualification authority")
    expected = dict(manager=settings, pid=PID, boot=BOOT, cgroup="0::" + GROUP, members=[PID],
                    comm="jetstreamer-nod", argv=route["argv"], exe=route["node"]["path"],
                    image=[2304, 6161086, 47753136], image_digest=route["node"]["sha256"],
                    uid=[1001]*4, gid=[1003]*4, fs_limit=[2 << 20]*2, worker_noexec=True,
                    private_network=True, snapshot=[1795, 524756, 4297291805], inputs_readonly=True,
                    inputs_match=True, scratch_bytes=SCRATCH, scratch_tmpfs=True)
    return route, expected


def check(s, actual, expected):
    s.need(actual == expected, "unregistered replay process " + str(actual["pid"]))


def observe(s, pid, comm, start, group):
    if (pid, comm, group) != (PID, "jetstreamer-nod", "0::" + GROUP):
        return None
    route, expected = contract(s)
    proc = Path("/proc") / str(pid)
    cgroup = Path("/sys/fs/cgroup") / GROUP.lstrip("/")
    def manager():
        raw = subprocess.check_output(["/usr/bin/systemctl", "show", "-p",
              ",".join(expected["manager"]), UNIT], text=True, timeout=10)
        return dict(line.split("=", 1) for line in raw.splitlines())
    def members():
        return sorted(map(int, (cgroup / "cgroup.procs").read_text().split()))
    def identity(p):
        m = p.stat()
        return [m.st_dev, m.st_ino, m.st_size]
    def view(p):
        return proc / "root" / str(p).lstrip("/")
    before = manager()
    s.need(before == expected["manager"] and members() == [pid], "foreign bounded 142 manager or members")
    binds = [b.split(":") for b in route["read_only_file_binds"]]
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    scratch = os.statvfs(view(route["run_parent"]))
    mounts = [l.split() for l in (proc / "mountinfo").read_text().splitlines()]
    mount_types = [r[r.index("-")+1] for r in mounts if r[4] == route["run_parent"]]
    with (proc / "exe").open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    actual = dict(manager=before, pid=pid, boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", ""),
                  cgroup=group, members=members(), comm=comm, argv=[os.fsdecode(a) for a in
                  (proc / "cmdline").read_bytes().removesuffix(b"\0").split(b"\0")], exe=os.readlink(proc / "exe"),
                  image=identity(proc / "exe"), image_digest=digest, uid=list(map(int,status["Uid"].split())),
                  gid=list(map(int,status["Gid"].split())), fs_limit=list(resource.prlimit(pid, resource.RLIMIT_FSIZE)),
                  worker_noexec=bool(os.statvfs(view(route["worker"]["path"])).f_flag & os.ST_NOEXEC),
                  private_network=os.readlink(proc / "ns/net") != os.readlink("/proc/1/ns/net"),
                  snapshot=identity(view(route["snapshot"]["target"])),
                  inputs_readonly=all(os.statvfs(view(b)).f_flag & os.ST_RDONLY for _,b in binds),
                  inputs_match=all(s.same_file(Path(a),view(b)) for a,b in binds),
                  scratch_bytes=scratch.f_frsize*scratch.f_blocks, scratch_tmpfs=mount_types == ["tmpfs"])
    check(s, actual, expected)
    s.need(s.process(pid)[1:] == (start, group) and manager() == before and members() == [pid],
           "bounded 142 generation changed during census")
    return dict(unit=UNIT, invocation_id=IID, pid=pid, start_ticks=start, memory_bytes=MEMORY,
                scratch_bytes=SCRATCH, additional_cpu_quota_micros=0)
