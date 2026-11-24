"""Cover the genuine, drained 159 donor before and after a full 145 native price."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RUNTIME / "epoch159-bounded-reference-20261123-v1"
ATTEMPT = ROOT / "attempt-v1"
HOME = Path("/home/sol")
UNIT = "horizon-epoch159-bounded-vote-trace-20261123-v1.service"
IID = "fd406b11e15040cb9039dd9fdc48f63d"
GRANT = "18569b972847956811d0dddd546b93acadcb21112672d963e1f2765b27d27ccc"
PRICE = "0341586ebc5fd04e0f354fc3081774fdc1d952558dc456542cb79599f4ff6b62"
EXIT = "31055f49783e564588f662448abde35e150035a0275ece6a80dab142cacd6909"
FAIL = "3306fecc2732e2804d058e5b3c328870881ca79f8abe5e2351d097c06a90d093"
CURSOR = "s=7f76387dd96140468b39dcf01e726fea;i=392ee68;b=763ea84ca81f4dddad364b1ea2ba36dd;m=371cee5228c;t=660f19bb87fc4;x=48734cd4d901dc22"
CG = Path("/sys/fs/cgroup/system.slice") / UNIT
WRITER136 = "horizon-admit-136-actual-20261120-g1.service"
PAYLOAD136 = "horizon-qualify-136-actual-20261120-g1.service"
MIB = 1 << 20
GIB = 1 << 30


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def bound(path, expected=None):
    p = Path(path)
    need(p.resolve(strict=True) == p and p.is_relative_to(RUNTIME), "foreign root receipt")
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        st = os.fstat(f.fileno())
        need(stat.S_ISREG(st.st_mode) and (st.st_uid, st.st_gid, st.st_nlink) == (0, 0, 1)
             and not st.st_mode & 0o022 and 0 < st.st_size <= 32 * MIB, "unsafe receipt")
        data = f.read(st.st_size + 1)
        def identity(s):
            return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
        need(len(data) == st.st_size and identity(st) == identity(os.fstat(f.fileno())) == identity(p.lstat()),
             "changed receipt during read")
    h = hashlib.sha256(data).hexdigest()
    need(expected in (None, h), "changed bound receipt: " + str(path))
    return json.loads(data), h


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10).strip()


def image(name, size, ino, terminal):
    p = ATTEMPT / (name + ".ext4")
    key, _ = bound(ATTEMPT / (name + "-identity.json"))
    need(key == dict(dev=HOME.stat().st_dev, ino=ino, size=size), "changed diagnostic image binding")
    if not p.exists() and name == "scratch":
        value, digest = bound(ATTEMPT / "scratch-retired.json")
        need(value["iid"] == IID and value["ino"] == ino and value["dev"] == key["dev"] and
             value["utc"] >= terminal["utc"], "unreconciled scratch removal")
        return {"retired": digest, "original": key}
    st = p.lstat()
    need((st.st_dev, st.st_ino, st.st_size) == (key["dev"], ino, size)
         and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
         and (st.st_uid, st.st_gid, st.st_nlink) == (0, 0, 1) and st.st_blocks * 512 >= size,
         "lost diagnostic physical allocation")
    need(not command("/usr/sbin/losetup", "-j", str(p)), "diagnostic image remains attached")
    return {"original": key, "retained": True}


def donor_users(exclusive136, token, rows):
    locks = [row.split()[1:] for row in rows if token in row.split()]
    if exclusive136 is None:
        need(not locks, "another actor holds the donor; requires its own enrollment")
        return {}
    writer = exclusive136["writer"]
    pid = writer["pid"]
    need(pid > 1 and writer["start_ticks"] > 0 and re.fullmatch(r"[a-f0-9]{32}", writer["invocation_id"])
         and locks == [["FLOCK", "ADVISORY", "WRITE", str(pid), token, "0", "EOF"]],
         "136 writer does not own the original donor lock")
    allowed = {WRITER136: [pid]}
    if exclusive136["occupied"]:
        actor = exclusive136["identity"]
        processes = actor["processes"]
        need(actor["unit"] == PAYLOAD136 and len(processes) == 1 and processes[0][0] > 1,
             "unqualified 136 donor payload")
        allowed[PAYLOAD136] = [processes[0][0]]
    return allowed


def snapshot(exclusive136=None):
    g, _ = bound(ROOT / "ADMISSION.json", GRANT)
    price, _ = bound(g["price"]["path"], PRICE)
    need(g["price"]["sha256"] == PRICE and price["fleet"] == g["fleet"] and g["actual_grant"] is True,
         "different donor grant")
    start, _ = bound(ATTEMPT / "start.json", "ddafa1ae35d5c889ab7a03f6940930a7c3b8da691089b60a8a98f1069288a211")
    terminal, _ = bound(ATTEMPT / "driver-exit.json", EXIT)
    failed, _ = bound(ATTEMPT / "service-failure.json", FAIL)
    hello, _ = bound(ROOT / "ACTUAL-HELLO-fd406b11.json",
                     "df4364e5f79eeb733ec8cfa254e92f3df107172e23abf20c94dd1fa16a9c40a7")
    need(start["iid"] == terminal["iid"] == failed["iid"] == hello["proc_tuples"]["invocation_id"] == IID
         and start["unit"] == g["unit"] == UNIT and start["grant"] == failed["grant"] == GRANT
         and terminal["code"] == 1 and terminal["retained"]["hello.json"] == hello["original_sha256"]
         and hello["live_comparison_passed"], "foreign terminal")
    for name, sha in terminal["retained"].items():
        need(re.fullmatch(r"[a-z0-9-]+\.json", name), "invalid retained evidence name")
        bound(ATTEMPT / "retained" / name, sha)
    row = json.loads(command("/usr/bin/journalctl", "--cursor=" + CURSOR, "-n", "1",
                             "--no-pager", "-o", "json", "_PID=1", "UNIT=" + UNIT,
                             "INVOCATION_ID=" + IID, "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15"))
    need(row["__CURSOR"] == CURSOR and row["COMMAND"] == "ExecStart" and row["EXIT_CODE"] == "exited"
         and row["EXIT_STATUS"] == "1" and row["INVOCATION_ID"] == IID and row["_PID"] == "1", "wrong PID1 exit")
    props = dict(v.split("=", 1) for v in command("/usr/bin/systemctl", "show", "-p",
                 "Id,ActiveState,SubState,InvocationID,MainPID,ControlPID,Job,NRestarts", UNIT).splitlines())
    need(props["Id"] == UNIT and props["ActiveState"] in ("inactive", "failed")
         and props["SubState"] in ("dead", "failed") and props["InvocationID"] in (IID, "")
         and props["MainPID"] == props["ControlPID"] == props["NRestarts"] == "0" and not props["Job"]
         and (not CG.exists() or not (CG / "cgroup.procs").read_text().strip()), "undrained original diagnostic")
    lock = g["donor_lock"]
    ls = Path(lock["path"]).lstat()
    need((ls.st_dev, ls.st_ino) == (lock["dev"], lock["ino"]) and stat.S_ISREG(ls.st_mode), "donor lock replaced")
    token = f"{os.major(ls.st_dev):02x}:{os.minor(ls.st_dev):02x}:{ls.st_ino}"
    permitted = donor_users(exclusive136, token, Path("/proc/locks").read_text().splitlines())
    need(permitted.keys() <= set(g["donor_idle_units"]), "original donor does not name 136 users")
    for unit in g["donor_idle_units"]:
        grp = CG.parent / unit / "cgroup.procs"
        members = sorted(map(int, grp.read_text().split())) if grp.exists() else []
        need(members == permitted.get(unit, []), "donor successor already enrolled")
    proof = dict(invocation_id=IID, grant_sha256=GRANT, original_price_sha256=PRICE, driver_exit=EXIT,
                service_failure=FAIL, pid1_exit=CURSOR, retained=terminal["retained"],
                scratch=image("scratch", 24 * GIB, 101263643, terminal),
                evidence=image("evidence", 8 * MIB, 101263647, terminal), donor_lock=lock)
    if exclusive136 is not None:
        proof["exclusive136"] = exclusive136
    return proof


def cover(before, native, after, build_bytes=0, build_ram=0, *, exclusive136=None):
    need(before == after and before["invocation_id"] == IID and before["grant_sha256"] == GRANT and
         before["driver_exit"] == EXIT and 0 <= build_bytes <= 104 * MIB and 0 <= build_ram <= 768 * MIB,
         "transition during pricing or unqualified build bound")
    need(native["fits"] and native["schema"] == "horizon-incident-replay-fit-v1" and
         native["resource_credit_bytes"] == 0 and not native["replay_launch_authorized"]
         and native["complete_cpu_quota_micros"] == 64_000_000
         and native["complete_memory_plus_reserve_bytes"] == 810_658_050_048,
         "incomplete native system price")
    ref = native["fleet"]
    fleet, _ = bound(ref["path"], ref["sha256"])
    candidate = native["candidate136"]
    if exclusive136 is None:
        need(not candidate["occupied"] and not candidate["loan_micros"], "changed 136 donor")
    else:
        need(exclusive136 == before["exclusive136"] == candidate and candidate["cap"] == candidate["remaining"] == 72 * GIB
             and candidate["loan_micros"] in (0, 4_250_000) and not build_bytes and not build_ram,
             "unqualified 136 donor or reduced reservation")
    failed170 = native.get("failed_cold170")
    if failed170:
        booking = native["bookings"]["170"]
        need(exclusive136 is None and failed170 == fleet["cold170_retry13_execution_failure"]
             and failed170["reservation_ending_bytes"] == 0
             and fleet["canonical_producer_count"] == len(fleet["actual_executing_replays"]) == 4
             and {row["epoch"] for row in fleet["actual_executing_replays"]} == {166, 167, 168, 172}
             and set(native["replacements"]) == {"166", "167", "168"}
             and set(native["survivors"]) == {"172"}
             and booking["cap_bytes"] == 384 * GIB
             and booking["cap_bytes"] == booking["physical_bytes"] + booking["remaining_bytes"]
             and booking["measurement"] == "two complete stopped-tree walks",
             "changed failed epoch 170 booking or producer topology")
    else:
        need(fleet["canonical_producer_count"] == len(fleet["actual_executing_replays"]) == 5
             and set(native["replacements"]) == {"166", "167", "168", "170"} and set(native["survivors"]) == {"172"},
             "changed donor or producer topology")
    orig, _ = bound(ROOT / "HEAD131757-132005-donor.json", PRICE)
    old = orig["reserved_hourly"]
    need(old["guard_cpu_micros"] == 1_000_000 and old["guard_memory"] == GIB and
         old["producer_cpu_micros"] == 3_000_000 and old["producer_memory"] == 68 * GIB and
         old["future_staging"] == 6_589_353_984 and old["private_workspace"] == 68_117_473_606 and
         orig["charged_reference"] == {"cpu_cores": 2, "memory_bytes": 48 * GIB, "other_home_bytes": 32 * MIB,
                                     "scratch_bytes": 24 * GIB, "swap_bytes": 0},
         "changed original 169 or 159 resources")
    ob = native["recovery_obligations"]
    need(len({(w["pid"], w["start_ticks"]) for w in ob["public_workers"]}) == len(ob["public_workers"]) and
         sum(m["required_bytes"] for m in ob["mirror_inputs"]) == ob["missing_mirror_bytes"], "incomplete public audit")
    extra = max(ob["public_storage"]["remaining_DATA_growth_bytes"],
                fleet["active_ready_range_audit_obligation"]["current_storage"]["remaining_DATA_growth_bytes"])
    vfs = os.statvfs(HOME)
    free = min(vfs.f_bavail * vfs.f_frsize, native["available_HOME_bytes"],
               fleet["complete_cycle_conservative_available_DATA_bytes"])
    required = native["complete_required_HOME_bytes"] + extra + old["future_staging"] + old["private_workspace"]
    # Reprice actual free blocks. The fully allocated 24 GiB image was already charged there.
    # Keep the complete external allowance and take no scratch-retirement credit on the reference budget.
    required += 32 * MIB + build_bytes
    margin = min(free - required, orig["remaining_home_bytes"] - build_bytes)
    memory_margin = native["available_memory_bytes"] - native["required_available_memory_bytes"] - build_ram
    if margin < 0 or memory_margin < 0:
        print(f"epoch145 donor capacity: home_shortfall_bytes={max(0, -margin)} "
              f"memory_shortfall_bytes={max(0, -memory_margin)}", file=sys.stderr, flush=True)
        raise ValueError("insufficient HOME or general-slot memory")
    return dict(schema="horizon-145-drained-159-donor-cover-v1", diagnostic=after, fleet=ref,
                native_recorded_unix_seconds=native["recorded_unix_seconds"], original_donor_price_sha256=PRICE,
                build_HOME_bytes=build_bytes, build_RAM_bytes=build_ram, remaining_home_bytes=margin,
                native_home_required=required, general_slot_cpu_micros=1_000_000, general_slot_memory_bytes=2 * GIB,
                original_guard_memory_bytes=GIB, original_guard_cpu_micros=1_000_000,
                original_producer_cpu_micros=3_000_000, original_producer_memory_bytes=68 * GIB,
                credited_retirement_bytes=0, replay_launch_authorized=False)


if __name__ == "__main__":
    action, *args = sys.argv[1:]
    if action == "snapshot" and not args:
        print(json.dumps(snapshot(), sort_keys=True))
    elif action == "build" and len(args) == 2:
        before, _ = bound(args[0])
        native, _ = bound(args[1])
        need(0 <= time.time() - native["recorded_unix_seconds"] <= 120, "stale physical build price")
        print(json.dumps(cover(before, native, snapshot(), 104 * MIB, 768 * MIB), sort_keys=True))
    else:
        raise SystemExit("expected snapshot or build PRIOR_SNAPSHOT NATIVE")
