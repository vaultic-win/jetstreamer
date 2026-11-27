"""Price the issued Anza 168 and 170 owners against their remaining spend.

Caller must hold the actual campaign operation lock. This is a read-only module.
The result excludes any new job, fixed build image or non-fleet overhead.
"""
from hashlib import file_digest
from pathlib import Path
import json
import os
import runpy
import stat
import sys

sys.dont_write_bytecode = True
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
ATTEMPT = RT / "epoch170-from-73746882-20261127-v1/attempt-2"
OP = ATTEMPT / "operator-v3"
CURRENT_PRICE = ATTEMPT / "issued-price-v47"
FOCUSED169_PRICE = RT / "epoch169-hourly-admission-20261123-v1/issued-split-v1"
AS = Path("/home/sol/.jetstreamer-private/epoch168-assembly-operator-20261127-v1/launch-acmxqat0")
OP_SEAL = "0dd508ca75585705f8a01805518f9b1792be31943548f9829421bef858d5be56"
PROGRESS = "51aaa67e0eeb7bd1da0ed85e718ade911a6ae425e21be20383cb0f715c834d02"
INTENT = "e33354cdeb51c747f9f821416b740c23223649102603f588b34267b7b92dd2c3"
NATIVE = "3da3b3af56ae50a30787e0f924f0cf61d7a55fba76067298b19195fa678fcf28"
AID = "f097aed2a8f647398854fa6139f02d32"
RID = "c3ab30cfeb05428bb8f5c48a5a44822c"
G = 1 << 30

def need(value, reason):
    if not value:
        raise ValueError(reason)

def digest(path):
    with path.open("rb") as f:
        return file_digest(f, "sha256").hexdigest()

def pinned(path, expected):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and not st.st_mode & 0o222 and st.st_nlink == 1 and digest(path) == expected,
         "sealed input changed: " + str(path))
    return json.loads(path.read_bytes())

def proc_info(pid):
    proc = Path("/proc") / str(pid)
    ticks = int((proc / "stat").read_text().rsplit(") ", 1)[1].split()[19])
    exe = (proc / "exe").stat()
    return [pid, ticks, exe.st_dev, exe.st_ino]

def assembly_roster(old, native, intent):
    unit = native["Id"]
    row = old.state(unit)
    need(row["InvocationID"] == native["InvocationID"] == AID and row["MainPID"] == native["MainPID"],
         "foreign epoch 168")
    args = intent["argv"][intent["argv"].index("--") + 1:]
    shell, image, plan, plan_sha = args[0], args[-3], args[-2], args[-1]
    want = [[shell, *args[1:]], [image, "--assemble-private", plan, plan_sha], ["/usr/bin/head", "-c", "33554432"]]
    main = int(native["MainPID"])
    cgroup = Path("/sys/fs/cgroup" + row["ControlGroup"])
    evidence = []
    for pid in sorted(map(int, (cgroup / "cgroup.procs").read_text().split())):
        proc = Path("/proc") / str(pid)
        command = [os.fsdecode(s) for s in (proc / "cmdline").read_bytes().split(b"\0")[:-1]]
        need(command in want and (proc / "exe").samefile(command[0]), "unexpected assembly command")
        need((command[0] == shell and pid == main) or (command[0] != shell and
             int((proc / "stat").read_text().rsplit(") ", 1)[1].split()[1]) == main), "assembly child changed")
        want.remove(command)
        evidence.append(proc_info(pid))
    need(not want, "incomplete assembly cgroup")
    return evidence

def live_price(*, separate_169=False):
    seal = pinned(OP / "deployment-seal-receipt.json", OP_SEAL)
    for entry in seal["members"]:
        member = OP / entry["name"]
        st = member.lstat()
        need(member.resolve(strict=True) == member and st.st_uid == 0 and not st.st_mode & 0o222
             and st.st_size == entry["bytes"] and digest(member) == entry["sha256"], "operator seal changed")
    directory = Path(__file__).resolve().parent
    need(not separate_169 or directory == FOCUSED169_PRICE, "separate accounting outside the enrolled 169 provider")
    source = directory if directory in (CURRENT_PRICE, FOCUSED169_PRICE) else OP
    base = runpy.run_path(str(source / "continuation_price.py"))
    old = base["prior"]
    progress, pref = old.read(ATTEMPT / "FIRST_PROTECTED_PROGRESS.json", PROGRESS)
    actor = old.bound(progress["actor"])
    release = old.bound(progress["release"])
    plan = old.bound(release["guard_plan"])
    profile = old.bound(progress["scope"])["profile"]
    worker = progress["worker"]
    need(actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
         and actor["producer_invocation_id"] == progress["producer_invocation_id"] == release["producer_invocation_id"] == RID
         and actor["unit"] == profile["host_unit"] == plan["unit"] == base["UNIT"]
         and actor["producer_pid"] == progress["producer_pid"] and actor["interface"] == progress["scope"] == release["interface"]
         and release["actor"] == progress["actor"] and release["guard_timer_invocation_id"] == progress["guard_timer_invocation_id"]
         and (ATTEMPT.parent / "barrier/allow").read_text() == RID and plan["invocation_id"] == RID
         and plan["worker_root"] == str(old.TREE) and plan["filesystem"] == "/home/sol"
         and plan["maximum_root_physical_bytes"] == 349442555904 and plan["minimum_free_bytes"] == 9635346274380
         and profile["producer_memory_bytes"] == 48*G and profile["guard_memory_bytes"] == G
         and profile["worker"] == worker["sha256"] and worker["pid"] != actor["producer_pid"],
         "replay release, cap or guard identity changed")
    need((Path("/proc")/str(actor["producer_pid"])/"exe").samefile(profile["node"]["path"])
         and (Path("/proc")/str(worker["pid"])/"exe").samefile(worker["exe"])
         and digest(Path("/proc")/str(worker["pid"])/"exe") == worker["sha256"], "different 170 executables")
    assembly_intent = pinned(AS / "LAUNCH_INTENT.json", INTENT)
    assembly_native = pinned(AS / "LAUNCH_NATIVE.json", NATIVE)
    def observe():
        replay = [proc_info(actor["producer_pid"]), proc_info(worker["pid"])]
        need(replay[0][1] == actor["start_ticks"] and replay[1][1] == worker["start_ticks"], "different replay processes")
        anchor, lower, _ = old.protected(actor["unit"], replay, progress["guard_timer_invocation_id"],
                                         progress["native_guard"], 48*G, "6s", False)
        sample = old.bound(anchor)
        need(sample["plan_sha256"] == release["guard_plan"]["sha256"]
             and sample["root_physical_observation"]["maximum_physical_bytes"] == plan["maximum_root_physical_bytes"]
             and sample["minimum_free_bytes"] == plan["minimum_free_bytes"], "foreign guard sample")
        assembly = assembly_roster(old, assembly_native, assembly_intent)
        anon = base["anonymous"]
        a = anon(assembly_native["Id"], AID, [p[:2] for p in assembly], 8*G)
        r = anon(actor["unit"], RID, [p[:2] for p in replay], 48*G)
        return dict(sample=anchor, lower170=lower, replay=replay, assembly=assembly, anon170=r, anon168=a,
                    available=old.availability())
    focused = None
    row169 = None
    fleet169 = None
    if directory == FOCUSED169_PRICE:
        focused = runpy.run_path(str(directory / "split_actor.py"))
        fleet169, _ = old.current_fleet()
        row169 = focused["current"](fleet169)
    before = observe()
    q = base["price"]("held", native169=row169) if focused else base["price"]("held")
    after = observe()
    if focused:
        focused["recheck"](fleet169, row169)
    need(before["replay"] == after["replay"] and before["assembly"] == after["assembly"]
         and q["phase170_first"] and q["priced_170_invocation"] == RID and q["assembly168"]["native"]["InvocationID"] == AID
         and q["assembly168"]["state"] == "live" and q["assembly168"]["plan"] == assembly_intent["plan"]
         and q["assembly168"]["incremental_ram"] == 2*G and q["assembly168"]["native"]["MemoryMax"] == str(8*G)
         and q["guarded_hourly_remaining"] == 64*G and q["concurrent_143_growth_bytes"] == 0 and not q["replacement143"]
         and q["phase"] == "held" and q["joint"]["producer_allowance"] == 48*G and q["joint"]["guard_sibling_allowance"] == G
         and q["candidate_170_growth_bytes"] == 36*G and q["resource_credit_bytes"] == 0
         and q["required_home"] == q["guard_floor"] + q["assembly168_remaining_bytes"] + 36*G
         and q["guard_floor"] >= q["ordinary_170_guard_floor"] and q["guard_floor"] >= q["assembly168"]["floor"]
         and old.current_fleet()[1] == q["fleet"], "unsupported fleet or phase change")
    cap = plan["maximum_root_physical_bytes"]
    low, high = q["terminal_tree_bounds"]
    need(0 < low <= high <= cap <= 384*G, "170 tree outside the issued cap")
    # Charge the actual floor and the unrealized part of the already issued tree cap.
    # The independent historical screen stays at its original 36 GiB assumption.
    remaining = cap - min(before["lower170"], after["lower170"], low)
    required_home = max(q["guard_floor"], plan["minimum_free_bytes"]) + q["assembly168_remaining_bytes"] + remaining
    available_home = min(before["available"][0], after["available"][0], q["available_home"])
    available_ram = min(before["available"][1], after["available"][1], q["available_ram"])
    # Both are anonymous bytes already absent from the kernel's MemAvailable reading.
    # Cap 168 at its incremental funding. The older 6 GiB of carried funding remains charged.
    observed_170 = min(before["anon170"], after["anon170"])
    observed_168 = min(before["anon168"], after["anon168"], q["assembly168"]["incremental_ram"])
    required_ram = q["required_ram"] - observed_170 - observed_168
    disk_margin = min(q["historical_home_margin"], available_home - required_home)
    result = dict(schema="horizon-live-168-170-remaining-fleet-v1", raw=q, before=before, after=after,
                actor=progress["actor"], release=progress["release"], progress=pref, guard_plan=release["guard_plan"],
                assembly_native=dict(path=str(AS/"LAUNCH_NATIVE.json"), sha256=NATIVE),
                assembly_intent=dict(path=str(AS/"LAUNCH_INTENT.json"), sha256=INTENT),
                actual_170_floor=plan["minimum_free_bytes"], actual_170_tree_cap=cap, remaining_170_bytes=remaining,
                realized_170_anon=observed_170, realized_168_incremental_anon=observed_168,
                available_home=available_home, required_home=required_home, available_ram=available_ram,
                required_ram=required_ram, home_margin=disk_margin, ram_margin=available_ram-required_ram,
                historical_home_margin=q["historical_home_margin"], resource_credit_bytes=0)
    if separate_169:
        return result, row169
    if focused:
        return focused["charge"](result, row169)
    return result
