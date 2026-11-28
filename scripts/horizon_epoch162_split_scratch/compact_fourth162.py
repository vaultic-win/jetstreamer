"""Qualify a smaller fourth producer under the unused 162/166 booking."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from fourth_interval import BASE, PRIOR_SHA, bind, digest, exact, need, reference, second
from fourth162_writer import contract, published

GIB = 1 << 30
CAP = 54 * GIB
HIGH = 51 * GIB
ORIGINAL = BASE / "operator-v1"
PACKAGE = BASE / "operator-54-v1"
SCOPE = BASE / "SCOPE_54.json"
INTERFACE = BASE / "INTERFACE_54.json"
ORIGINAL_SHA = "6102a47dd71ee77c34cd7992cf268cad14c8f4f8c829699bd14d28582df6572b"
PEAKS = dict(path=str(BASE / "FOURTH_KERNEL_PEAK_CAP_PROPOSAL.json"),
             sha256="e6a86f23904a9317bb5dafd1e93ae23ea8131fa34161b81f5ec96e14faa78c47")
REFUSAL = dict(path=str(BASE / "FOURTH_NATIVE_PRICE_1795869017178595629.json"),
               sha256="e99ff3042397fe5ae702fb186134be70876b54474d7f3b38544c1ce0f3e14207")
EARLIER_FIXTURE = dict(path="/home/sol/.jetstreamer-private/epoch162-split-scratch-20261127.zRrpyFl4/"
                       "test-1795820954042930568/ACCEPTED.json",
                       sha256="dbba452fef9ec498a363f7b025935684e6c137f8ed2a81957a6e551f4e013354")
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")


def original():
    interface, info = contract(ORIGINAL_SHA)
    seal = bind(info["provider"])
    need(seal["destination"] == str(ORIGINAL), "wrong original operator")
    members = {}
    for entry in seal["members"]:
        path = ORIGINAL / entry["name"]
        metadata = path.lstat()
        need(path.parent == ORIGINAL and path.resolve(strict=True) == path and stat.S_ISREG(metadata.st_mode)
             and metadata.st_uid == 0 and metadata.st_nlink == 1 and not metadata.st_mode & 0o222
             and digest(path) == entry["sha256"], "changed original operator member " + path.name)
        if path.suffix == ".py":
            members[path.name] = path.read_text()
    layout = runpy.run_path(str(ORIGINAL / "layout.py"))
    packet = layout["scope"]()
    need(packet["producer_ram"] == 62 * GIB and packet["tmpfs_bytes"] == 36 * GIB
         and packet["previous"]["sha256"] == PRIOR_SHA and packet["first_slot"] == 70_004_938
         and packet["last_slot"] == 70_011_988 and packet["position_count"] == 7051,
         "different source contract or previous geometry")
    return interface, info, layout, packet, members


def historical(layout):
    peak = bind(PEAKS)
    rows = peak["completed"]
    for item in rows:
        expected = item["manager"]
        records = subprocess.check_output(["/usr/bin/journalctl", "--no-pager", "-q", "-o", "json",
            "_PID=1", "_UID=0", "UNIT=" + expected["UNIT"], "INVOCATION_ID=" + expected["INVOCATION_ID"],
            "MESSAGE_ID=ae8f7b866b0347b9af31fe1c80b127c0"])
        row, = map(json.loads, records.splitlines())
        end = layout["bound"](item["terminal"])
        grant = layout["bound"](end["grant"])
        held = layout["bound"](end["held"])
        need(all(row[k] == value for k, value in expected.items()) and expected["MEMORY_SWAP_PEAK"] == "0"
             and grant["held"] == end["held"] and grant["iid"] == held["producer_invocation_id"] == expected["INVOCATION_ID"]
             and held["producer_unit"] == expected["UNIT"] and grant["profile"] == layout["profile"](36)
             and held["mounts"]["scratch_bytes"] == 36 * GIB and end["private_checkpoint_matched"]
             and end["archive"]["typed_manifest"]["output_slot_count"] == item["positions"], "unmatched prior kernel peak")
    observed = [int(item["manager"]["MEMORY_PEAK"]) for item in rows]
    need(observed == [42_699_456_512, 36_638_605_312] and CAP - max(observed) == 15_282_601_984,
         "unrecognized completed interval high-water records")
    previous = bind(EARLIER_FIXTURE)
    for size in (32, 36):
        run = bind(previous["runs"][f"native{size}"])["native_result"]
        need(run["scratch_capacity"] == size * GIB and run["scratch_inodes"] == 1 << 20
             and "noswap" in run["scratch"]["options"].split(",") and (run["uid"], run["gid"]) == (1001, 1003)
             and len(run["actual_accounts"]) == 4 and not run["initialized_real_bank"]
             and run["production_slots_replayed"] == 0, "wrong native scratch fixture")
    return dict(completed=rows, peak_bytes=max(observed), headroom_bytes=CAP-max(observed),
                native_mount_fixtures=previous["runs"], tmpfs_peak_measured=False)


def derivation(members, old_pin, scope_pin):
    result = members.copy()
    layout = result["layout.py"]
    for before, after in (
        ('PKG = BASE / "operator-v1"', 'PKG = BASE / "operator-54-v1"'),
        ('HANDOFF = BASE / "SCOPE.json"', 'HANDOFF = BASE / "SCOPE_54.json"'),
        (old_pin, scope_pin), ("scratch_gib in (32, 36)", "scratch_gib == 36"),
        ("worker_anonymous_allowance=26 * G", "worker_anonymous_allowance=18 * G"),
        ("(scratch_gib + 26) * G", "(scratch_gib + 18) * G"),
        ("(scratch_gib + 27) * G", "(scratch_gib + 19) * G"),
        ('plan["scratch_bytes"] + 24696061952', 'plan["producer_memory_max"] - 3 * G'),
    ):
        layout = exact(layout, before, after)
    result["layout.py"] = layout
    result["status162.py"] = exact(result["status162.py"], str(ORIGINAL), str(PACKAGE))
    result["close.py"] = exact(result["close.py"], "62-GiB/2-CPU", "54-GiB/2-CPU")
    for name, body in result.items():
        compile(body, name, "exec")
    return result


def check_profile(old, new, packet):
    profile = new["profile"](36)
    need(profile == dict(old["profile"](36), producer_memory_max=CAP, combined_ram=CAP+GIB,
                         worker_anonymous_allowance=18*GIB) and new["HANDOFF"] == SCOPE and new["PKG"] == PACKAGE,
         "unexpected change outside the producer RAM envelope")
    bindings = old["sources"]()
    before = old["producer_argv"](36, packet, bindings)
    after = new["producer_argv"](36, packet, bindings)
    changes = {f"--property=MemoryMax={62*GIB}": f"--property=MemoryMax={CAP}",
               f"--property=MemoryHigh={59*GIB}": f"--property=MemoryHigh={HIGH}"}
    need(set(changes).issubset(before) and after == [changes.get(arg, arg) for arg in before]
         and new["guard_plan"]("1"*32, new["MIN_FLOOR"]) == old["guard_plan"]("1"*32, old["MIN_FLOOR"]),
         "changed execution arguments, mounts or guard")
    return profile


def unoccupied(layout, refused):
    whole = refused["whole_roster"]
    seal = layout["bound"](whole["package"])
    directory = Path(seal["destination"])
    need(whole["package"]["sha256"] == "7da7fe2d6e75ac6ebab4f6eec7d5a9b191c0704557beea1404716bbe0683a3a2",
         "unexpected frozen shared provider")
    entry, = [row for row in seal["members"] if row["name"] == "capacity.py"]
    census = directory / "capacity.py"
    need(digest(census) == entry["sha256"], "changed shared census")
    price = runpy.run_path(str(census))
    peer_path = price["DIRECTORY169"] / "peer162.py"
    price["immutable"](peer_path, price["PEER_DIGEST"])
    donor = price["donor_observation"](runpy.run_path(str(peer_path)), layout["bound"](refused["donor"]))
    for unit in (layout["UNIT"], layout["TIMER"], layout["TIMER"].replace(".timer", ".service")):
        state = layout["manager"](unit)
        need(state["ActiveState"] in ("inactive", "failed") and not state["Job"] and not state.get("ControlGroup")
             and state.get("MainPID", "0") == state.get("ControlPID", "0") == "0", "occupied fourth producer or guard")
    processes = subprocess.check_output(["/usr/bin/systemctl", "list-units", "--plain", "--no-legend", "--type=service",
        "--state=running,activating,deactivating", "horizon-qualify-162-*", "horizon-162-54g-geometry-*"])
    need(not processes.strip() and not any(os.path.lexists(path) for path in (
        BASE / "SPLIT162_ENROLLMENT.json", layout["DATA"], layout["RUN"], layout["GUARDS"], layout["ALLOW"].parent,
        layout["CGROUP"])), "162 geometry or production reservation occupied")
    return donor


# The inner process only reads its own kernel namespaces. The tiny address space and
# single task bound how much of the existing donor the geometry fixture can consume.
READ_KERNEL = """
import json, os
def read(path):
    with open(path) as source:
        return source.read().strip()
group = read("/proc/self/cgroup").removeprefix("0::")
base = "/sys/fs/cgroup" + group + "/"
names = ["memory.max", "memory.high", "memory.swap.max", "cpu.max", "pids.max"]
mount, = [line for line in read("/proc/self/mountinfo").splitlines() if line.split()[4] == "/tmp"]
geometry = os.statvfs("/tmp")
root = os.stat("/tmp")
print(json.dumps(dict(cgroup=group, properties={name: read(base+name) for name in names},
    mount=mount, bytes=geometry.f_frsize*geometry.f_blocks, inodes=geometry.f_files,
    uid=os.geteuid(), gid=os.getegid(), owner=[root.st_uid, root.st_gid, root.st_mode & 0o777])))
"""


def kernel(size):
    unit = f"horizon-162-54g-geometry-{size}-{time.time_ns()}.service"
    cgroup = "/system.slice/" + unit
    props = ["Type=exec", "User=sol", "Group=horizon", "CPUQuota=200%", f"MemoryMax={CAP}", f"MemoryHigh={HIGH}",
             "MemorySwapMax=0", "TasksMax=1", "LimitAS=32M", "RuntimeMaxSec=15", "ProtectSystem=strict",
             "ProtectHome=yes", "PrivateNetwork=yes", "NoNewPrivileges=yes", "PrivateDevices=yes",
             f"TemporaryFileSystem=/tmp:rw,noswap,size={size*GIB},nr_inodes=1048576,uid=1001,gid=1003,mode=0700"]
    argv = ["/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect", "--unit="+unit,
            *("--property="+value for value in props), "--", "/usr/bin/python3", "-I", "-S", "-B", "-c", READ_KERNEL]
    output = subprocess.run(argv, capture_output=True, text=True, timeout=25)
    need(output.returncode == 0, "kernel geometry fixture: "+output.stderr[-1200:])
    observed = json.loads(output.stdout)
    parts = observed["mount"].split(" - ")
    options = set(parts[0].split()[5].split(",")) | set(parts[1].split()[2].split(","))
    need(observed["cgroup"] == cgroup and observed["properties"] == {
        "memory.max": str(CAP), "memory.high": str(HIGH), "memory.swap.max": "0",
        "cpu.max": "200000 100000", "pids.max": "1"} and observed["bytes"] == size*GIB
        and observed["inodes"] == 1 << 20 and observed["owner"] == [1001, 1003, 0o700]
        and (observed["uid"], observed["gid"]) == (1001, 1003) and parts[1].split()[0] == "tmpfs"
        and {"rw", "noswap"}.issubset(options) and "noexec" not in options
        and not Path("/sys/fs/cgroup"+cgroup).exists(), "kernel cgroup, mount or drain differed")
    return dict(unit=unit, properties=props, kernel=observed, exit=output.returncode, cgroup_drained=True)


def prepare(revision):
    paths = [Path(__file__).resolve(), HERE/"fourth162_writer.py", HERE/"fourth_interval.py",
             HERE/"derive_third162_writer.py", HERE/"second_interval.py"]
    published(revision, paths)
    original_ref, info, old, packet, members = original()
    old["need"](os.geteuid() == 0 and __debug__, "use the private operator identity")
    evidence = historical(old)
    test_body = derivation(members, info["scope"]["sha256"], "0"*64)
    candidate = {"__name__": "fourth_geometry_fixture"}
    exec(compile(test_body["layout.py"], "layout.py", "exec"), candidate)
    profile = check_profile(old, candidate, packet)
    refused = old["bound"](REFUSAL)
    need(not refused["fits"] and refused["phase"] == "prestart" and refused["held_invocation"] is None
         and refused["profile"] == old["profile"](36) and refused["home_margin"] == -21_514_105_644
         and refused["ram_margin"] == 855_908_352 and refused["fourth_162_predecessor"] == info["previous"],
         "different full-size refusal")
    proof_path = BASE / "FOURTH_54_KERNEL_QUALIFICATION.json"
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        donor = unoccupied(old, refused)
        if proof_path.exists():
            existing, proof = old["pinned"](proof_path)
            need(existing["source_commit"] == revision and existing["profile"] == profile and existing["history"] == evidence
                 and existing["refusal"] == REFUSAL and existing["old_interface"] == original_ref, "different existing proof")
        else:
            tested = {str(size): kernel(size) for size in (32, 36)}
            need(unoccupied(old, refused) == donor, "donor changed across fixture")
            proof = old["save"](proof_path, dict(source_commit=revision, profile=profile, old_interface=original_ref,
                history=evidence, refusal=REFUSAL, kernel=tested, original_kernel_peaks=PEAKS,
                predecessor_fixture=EARLIER_FIXTURE, donor=refused["donor"], source_sha256={p.name:digest(p) for p in paths},
                production_slots_replayed=0, enrolled=False), 0o400)
        scope = old["save"](SCOPE, dict(packet, source_commit=revision, producer_ram=CAP,
            full_size_interface=original_ref, kernel_qualification=proof), 0o400)
        staging = BASE/"operator-54-source"
        staging.mkdir(mode=0o700, exist_ok=True)
        st = staging.lstat()
        need(staging.resolve(strict=True) == staging and st.st_uid == 0 and not st.st_mode & 0o077, "unsafe staging")
        files = {}
        for name, contents in derivation(members, info["scope"]["sha256"], scope["sha256"]).items():
            old["save"](staging/name, contents.encode())
            files[name] = staging/name, 0o444
        origin = staging/"ORIGIN.json"
        old["save"](origin, dict(previous=info["provider"], scope=scope, proof=proof, revision=revision))
        files[origin.name] = origin, 0o444
        seal = second.seal(files, PACKAGE, old["save"], plan_root=BASE)
        sealed = runpy.run_path(str(PACKAGE/"layout.py"))
        check_profile(old, sealed, sealed["scope"]())
        reader = runpy.run_path(str(PACKAGE/"status162.py"))
        need(reader["api"]().PKG == PACKAGE and reader["FIELD"] == info["field"], "inconsistent sealed status reader")
        interface = old["save"](INTERFACE, dict(info, provider=seal, scope=scope, reader=reference(PACKAGE/"status162.py"),
                                    full_size_interface=original_ref, kernel_qualification=proof), 0o400)
        return dict(interface=interface, qualification=proof, scope=scope, predecessor_peaks=evidence["peak_bytes"],
                    headroom=evidence["headroom_bytes"], profile=profile)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("published_revision")
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.published_revision), sort_keys=True))
