"""Remove the interrupted original 169 writer's future growth after its inode is frozen."""
import fcntl
import os
from pathlib import Path
import signal
import stat


G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
PRIV = Path("/home/sol/.jetstreamer-private")
ROOT = RT / "epoch169-hourly-retry-20261128-v4"
SCOPE = dict(path=str(ROOT / "SCOPE.json"), sha256="f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5")
CUSTODY = dict(path=str(RT / "epoch169-hourly-retry-20261128-v1/PREDECESSOR_CUSTODY.json"),
               sha256="31a30e9eb09e11514c64b9c7102871aeefa58a543c77dff576588b07b0327b0b")
UNIT = "horizon-qualify-169-focused-hourly-20261123-v1.service"
IID = "b01da82c3091478f920ddcc71f4d9191"
PART = PRIV / "epoch169-hourly-source-20261123-v1/v158/epoch-169-through-73245218.jet"


def frozen_inode(path, prior, need):
    # Linux grants a read lease only when the inode has no open writer. A
    # writable shared mapping retains its write-capable file description.
    # Closing this fd releases the lease before the price returns.
    handler = signal.getsignal(signal.SIGIO)
    signal.signal(signal.SIGIO, signal.SIG_IGN)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
            current = os.fstat(fd)
            identity = dict(device=current.st_dev, inode=current.st_ino, size=current.st_size,
                            blocks=current.st_blocks, mtime_ns=current.st_mtime_ns, ctime_ns=current.st_ctime_ns,
                            owner=current.st_uid, group=current.st_gid, mode=stat.S_IMODE(current.st_mode), links=current.st_nlink)
            need(path.resolve(strict=True) == path and stat.S_ISREG(current.st_mode) and current.st_nlink == 1
                 and all(prior[key] == value for key, value in identity.items())
                 and os.path.samestat(current, path.lstat()) and fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK,
                 "original 169 inode changed or its read lease was broken")
            return identity
        finally:
            os.close(fd)
    finally:
        signal.signal(signal.SIGIO, handler)


def reconcile(core, native, first, later, amounts):
    need = core.need
    custody = core.bound(CUSTODY)
    scope = core.bound(SCOPE)
    start = core.bound(custody["grant"])
    end = core.bound(custody["terminal"])
    ceiling = native["stopped_169_compute_handoff"]
    booked = native["planned_169_retry"]
    need("frozen_original_169" not in native and first["phase"] == later["phase"] == "terminal"
         and first["invocation_id"] == later["invocation_id"] == custody["producer_invocation"] == end["invocation_id"] == IID
         and custody["producer_unit"] == start["unit"] == end["unit"] == UNIT and first["terminal"] == later["terminal"] == custody["terminal"]
         and ceiling["terminal"] == custody["terminal"] and ceiling["grant"] == custody["grant"]
         and end["grant_sha256"] == custody["grant"]["sha256"] and end["archive"] is None and not end["private_span"]
         and custody["disposition"] == "guard-stop-filesystem-floor" and not custody["complete_private_span"]
         and not custody["manifest_present"] and not os.path.lexists(custody["manifest_path"])
         and not custody["canonical_publication_authorized"] and not custody["resource_credit_bytes"]
         and ceiling["retained_169_output_bytes"] == amounts["remaining_output"] == 8 * G
         and booked["fourth_scope"] == SCOPE and scope["predecessor"] == CUSTODY
         and scope["quota"]["home_output"] == 4 * G and scope["quota"]["home_control"] == 64 * M
         and booked["additional_home"] == scope["quota"]["home_output"] + scope["quota"]["home_control"],
         "different original 169 closure, future reservation or successor")
    unit = core.state(UNIT, "Id,ActiveState,ControlPID,MainPID,ControlGroup,Job,TriggeredBy,Restart")
    need(unit["ActiveState"] == "inactive" and unit["MainPID"] == unit["ControlPID"] == "0"
         and not unit["ControlGroup"] and not unit["Job"] and not unit["TriggeredBy"] and unit["Restart"] == "no"
         and not (Path("/sys/fs/cgroup/system.slice") / UNIT / "cgroup.procs").exists(), "original 169 can still write")
    prior = custody["retained_incomplete_archive"]
    dest = Path(scope["output"])
    need(Path(prior["path"]) == PART and prior["inode"] == 107553266 and prior["size"] == 1_304_621_799
         and dest == PRIV / "epoch169-hourly-retry-20261128-v4/v158" / PART.name, "different 169 archive paths")
    fixed = frozen_inode(PART, prior, need)
    fixture = core.bound(scope["namespace_fixture"])
    physical = dest.parent.stat()
    projection = fixture["host"]["mounts"]["v158"]
    need(projection == fixture["readback"]["mounts"]["v158"] and projection["path"] == str(PART.parent)
         and projection["writable"] and (projection["device"], projection["inode"]) == (physical.st_dev, physical.st_ino)
         and not os.path.samestat(physical, PART.parent.stat()) and physical.st_dev == fixed["device"],
         "fourth 169 output tree is not disjoint from the frozen partial")
    candidate = native["independent_retry169"]
    if candidate:
        live = core.bound(candidate["intent"])["namespace"]["v158"]
        need(all(live[k] == projection[k] for k in ("path", "device", "inode", "writable")),
             "live fourth 169 projection changed")
    floor = amounts["guard_floor"]
    previous = amounts["required_home"]
    available = native["available_home"]
    need(previous == floor + 8 * G and amounts["protected_home"] + 64 * M == floor
         and amounts["available_home"] == available and amounts["home_margin"] == available - previous,
         "original 169 future output is no longer a discrete charge")
    amounts.update(remaining_output=0, required_home=floor, home_margin=available - floor)
    native["frozen_original_169"] = dict(custody=CUSTODY, scope=SCOPE, retained_partial=prior,
        occupied_home_bytes=fixed["blocks"] * 512, previous_required_home=previous, required_home=floor,
        original_protected_floor=floor, original_control_bytes=64 * M, removed_future_output=8 * G,
        successor_future_output=4 * G, successor_control=64 * M, materialization_required=False,
        nonwriting_lease_observed=True, resource_credit_bytes=0)
