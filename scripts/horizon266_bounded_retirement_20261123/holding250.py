"""Observe the original park and its independent readback under the same serial booking."""
import os
import sys
from pathlib import Path

sys.path[:0] = ["/run/horizon292-300-finite-v205-a1", "/run/horizon268-holding-build-v178-a1"]
import funds
import partition
from owners import CG, D, bound, props, ref

BASE = "horizon250-private-holding-v203-a1"
PARK = BASE + "-park.service"
VERIFY = BASE + "-verify.service"
PARK_IID = "179e129e82aa4f4db14b97c80ac5bd63"
PARK_SHA = "1404721cf236c2849a607d6c175789c713c26503c128ff9d4b7ea0bc51400342"
LIMIT = 512 << 20


def record(unit, name):
    return ref(D / unit.removesuffix(".service") / name)


def validate_source(source):
    p = Path(source["path"])
    st = p.lstat()
    identity = source["identity"]
    assert p.resolve() == p
    assert (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_uid, st.st_gid, st.st_nlink) == tuple(
        identity[k] for k in ("device", "inode", "mode", "length", "uid", "gid", "link_count"))
    for actual, prefix in ((st.st_mtime_ns, "modified"), (st.st_ctime_ns, "changed")):
        assert actual == identity[prefix + "_seconds"] * 10**9 + identity[prefix + "_nanoseconds"]


def inactive(unit):
    assert not (CG / unit).exists()
    assert props(unit, ["ActiveState", "SubState", "MainPID", "ControlPID", "Job"]) == dict(
        ActiveState="inactive", SubState="dead", MainPID="0", ControlPID="0", Job="")


def completed(unit, receipt, booking):
    result = bound(receipt)
    assert result["booking"] == record(unit, "booking.json") and booking == bound(result["booking"])
    assert result["process"] == record(unit, "process.json") and bound(result["process"])["exit"] == 0
    assert result["original"] == booking["original"] and result["source_retained"]
    assert result["resource_credit"] == 0 and result["archive_ready"] is False
    assert result["result"] == dict(
        bytes=185599540324, canonical_publication=False, capacity_credit=0, epoch=250,
        kind="closed-archive", manifest_sha256="867111b464fa2b18964b3621438150b04755f115e624d6318c4b9161af02de53",
        operation=booking["operation"], parts=5532, sha256=booking["original"]["sha256"])
    assert result["manager"] == record(unit, "pid1.json")
    events = bound(result["manager"])
    finish, = [r for r in events if r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448"]
    assert (finish["_PID"], finish["_UID"], finish["_BOOT_ID"], finish["UNIT"], finish["INVOCATION_ID"],
            finish.get("UNIT_RESULT", "success")) == (
                "1", "0", booking["boot"].replace("-", ""), unit, result["invocation_id"], "success")
    inactive(unit)


def state():
    park_ref = record(PARK, "completion.json")
    assert park_ref["sha256"] == PARK_SHA
    park = bound(park_ref)
    assert park["invocation_id"] == PARK_IID
    booking = bound(park["booking"])
    completed(PARK, park_ref, booking)
    assert booking["boot"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    validate_source(booking["original"])
    result = dict(park=park_ref, verify=None, complete=None)
    directory = D / VERIFY.removesuffix(".service")
    if not directory.exists():
        inactive(VERIFY)
        return result, {}
    vb = record(VERIFY, "booking.json")
    v = bound(vb)
    result["verify"] = vb
    for key in ("original", "actor", "image", "build", "boot", "lock", "endpoint_sha256", "service_bytes", "handoff"):
        assert v[key] == booking[key]
    expected = [p for p in booking["properties"] if not p.startswith("TemporaryFileSystem=")]
    timeout = 2 * bound(booking["timing"])["model_seconds"]["independent_readback"] + 900
    assert v["properties"] == [f"RuntimeMaxSec={timeout}" if p.startswith("RuntimeMaxSec=") else p for p in expected]
    assert v["operation"] == "verify" and v["unit"] == VERIFY and v["prior"] == park_ref and not v["retirement"]
    if (directory / "completion.json").exists():
        result["complete"] = record(VERIFY, "completion.json")
        completed(VERIFY, result["complete"], v)
        return result, {}
    pid = v["controller_pid"]
    assert partition.locked(funds.LOCK, pid) and Path("/proc", str(pid), "stat").read_text().rsplit(")", 1)[1].split()[19] == v["controller_ticks"]
    manager = props(VERIFY, ["InvocationID", "MainPID", "AllowedCPUs", "ActiveState", "SubState", "NRestarts"])
    worker = int(manager["MainPID"])
    assert (manager["ActiveState"], manager["SubState"], manager["NRestarts"], manager["AllowedCPUs"]) == ("active", "running", "0", "56")
    assert worker > 1 and len(bytes.fromhex(manager["InvocationID"])) == 16
    assert os.path.samefile(f"/proc/{worker}/exe", v["image"]["path"]) and os.sched_getaffinity(worker) == {56}
    assert Path(f"/proc/{worker}/cmdline").read_bytes().split(b"\0") == [os.fsencode(v["image"]["path"]), b"verify", b""]
    return result, {VERIFY: (manager["InvocationID"], worker, LIMIT, {56})}


def issue(unit, service, controller, outside):
    """Use the separately locked original slot, with fresh whole-host pricing."""
    from funding import price
    assert partition.locked(funds.LOCK, os.getpid()) and partition.locked(partition.LOCK, os.getpid())
    assert (unit, service, controller, outside) == (VERIFY, 512, 64, 0)
    witness, live = state()
    assert not live and not witness["verify"]
    old = bound(bound(witness["park"])["booking"])["resource_booking"]
    assert (old["service_MiB"], old["controller_MiB"], old["outside_MiB"]) == (512, 64, 40)
    # The old serial slot remains in the hard ledger. Check enough current
    # headroom for the whole verifier as well, without claiming disk savings.
    fit = price((service + controller) << 20, 1 << 20, 1 << 20, closed_disk=True)
    assert fit["total_hard"] == old["hard"]
    return dict(fleet=fit["fleet"], prior_serial=old["prior_serial"], current_fit=fit, predecessor=witness["park"],
                service_MiB=service, controller_MiB=controller, outside_MiB=outside, replay_credit=0)
