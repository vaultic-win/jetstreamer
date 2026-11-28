"""Observe the sealed epoch 169 replacement alongside its retained hourly result."""
from functools import lru_cache
import os
from pathlib import Path
import runpy
import stat
import sys

from evidence import bound, checked, need
import split_status169
import split_wire

CONTROL = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v1")
SCOPE = {"path": str(CONTROL / "SCOPE.json"), "sha256": "eb589f4c2c51dcf75314d50d7074a9411d034e6bd3f6a8bd826705ca4a1feb3a"}
CADENCE = {"path": str(CONTROL / "operator-v1/cadence.py"), "sha256": "933ee622bf9c272db5edeeca355f56000939e46c96c8b87f24f09a5f1c2c7717"}
FIELD = "current_private169_retry"
KEY = "private169_retry_start"
UNIT = "horizon-qualify-169-hourly-retry-20261128-v1.service"


@lru_cache(maxsize=1)
def receiver():
    scope = checked(SCOPE)
    directory = Path(CADENCE["path"]).parent
    package = checked(scope["operator"])
    need(scope["producer_unit"] == UNIT and scope["cadence_source"] == CADENCE
         and package["destination"] == str(directory) and bound(directory / "cadence.py") == CADENCE,
         "different epoch 169 retry scope")
    for member in package["members"]:
        path = directory / member["name"]
        need(path.parent == directory and not path.lstat().st_mode & 0o222
             and bound(path)["sha256"] == member["sha256"], "unsealed retry receiver dependency")

    # The provider uses local imports with common names. Keep the incumbent
    # writer's imports and search path intact after loading the immutable API.
    names = ("contract", "namespace", "quote", "observe")
    saved = {name: sys.modules.pop(name) for name in names if name in sys.modules}
    search = sys.path[:]
    try:
        api = runpy.run_path(CADENCE["path"])
        need(all(Path(sys.modules[name].__file__) == directory / (name + ".py") for name in names),
             "retry receiver imported a different provider")
    finally:
        sys.path[:] = search
        for name in names:
            sys.modules.pop(name, None)
        sys.modules.update(saved)
    return api


def accept_assignment(row):
    if row["producer_unit"] != UNIT:
        return split_status169.accept_assignment(row)
    scope = checked(SCOPE)
    ref = bound(CONTROL / "START_INTENT.json")
    seed = checked(ref)
    grant = checked(bound(CONTROL / "GRANT.json"))
    iid = seed["producer_invocation_id"]
    need(seed["scope"] == SCOPE and seed["unit"] == UNIT and row["range"] == "169"
         and row["controller_unit"] == UNIT and row["expected_producer_invocation_id"] == iid
         and row["expected_controller_invocation_id"] == grant["invocation_id"] == iid
         and row["scratch_path"] == seed["private_scratch_mount"]["path"]
         and row["worker_executable_basename"] == "historical-worker"
         and row["append_log"] == dict(path=scope["log"], device=grant["log_device"], inode=grant["log_inode"]),
         "unregistered epoch 169 replacement observation")
    return row


def observe(c, observed_lane):
    api = receiver()
    row = api["observe_retry"](c, observed_lane)
    before = api["predecessor_context"](c, row)
    prior = split_status169.observe(before, observed_lane)
    return row, prior, before


def recheck(c):
    current = receiver()["observe"].current(c.fleet)
    row = c.retry169
    if not current or not row:
        need(current is row, "169 replacement crossed enrollment during census")
    else:
        keys = ("phase", "invocation_id", "processes", "guard_plan", "release", "worker", "intent", "terminal")
        need(all(current.get(key) == row.get(key) for key in keys), "169 replacement changed during census")


def output(row):
    # The node opens the original literal path inside its mount namespace.
    # Compare both names to its live descriptor and record the actual HOME file.
    scope = checked(SCOPE)
    host = Path(scope["output"])
    visible = split_wire.PATHS[169]
    proc = Path("/proc") / str(row["actor"]["producer_pid"])
    view = proc / "root" / visible.relative_to("/")
    try:
        meta = view.lstat()
    except FileNotFoundError:
        need(proc.is_dir() and not host.exists(), "169 projected output disappeared")
        return None
    need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 1001 and meta.st_nlink == 1
         and os.path.samestat(meta, host.lstat()), "169 output is outside the charged retry tree")
    descriptors = []
    for fd in (proc / "fd").iterdir():
        try:
            if fd.readlink() in (visible, host) and os.path.samestat(meta, fd.stat()):
                descriptors.append(fd.name)
        except FileNotFoundError:
            continue
    need(descriptors, "169 replacement output detached from producer")
    return dict(path=str(host), namespace_path=str(visible), producer_pid=row["actor"]["producer_pid"],
                device=meta.st_dev, inode=meta.st_ino, size=meta.st_size, bound_producer_fds=descriptors)


def forecast(c, row, prior, old, original, delivery):
    iid = row["invocation_id"]
    closed = row["phase"] == "terminal"
    start = row.get("intent")
    if closed:
        path = CONTROL / "START_INTENT.json"
        start = bound(path) if path.exists() else row["held"]
    evidence = checked(start)
    owner = evidence.get("producer_invocation_id") or evidence.get("invocation_id")
    need(owner == iid and evidence["unit"] == UNIT, "different retry start")
    adapted = dict(row, hourly169_start_intent=start)
    report, fields = split_wire.forecast(c, adapted, prior, old, original, delivery,
                                       status_key=KEY, archive_reader=output)
    return report, fields


def install(fleet, row):
    receiver()["install"](fleet, row)
    if row is not None:
        active = row["phase"] != "terminal"
        target, = (entry for entry in fleet["epochs"] if entry["epoch"] == 169)
        target.update(state="executing" if row["phase"] == "worker" else "verification",
                      current_repair_owner="/root", no_live_producer_claimed=not active, repair_open=True)
