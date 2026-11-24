"""Bind and price the private epoch 170 diagnostic inside its retained booking."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = ROOT / "epoch170-metered-hourly-20261124-v1"
SEALED = BASE / "sealed"
READY = BASE / "INPUTS_READY.json"
READY_SHA = "ebe80a6c299948168cf6e7453f0e45560e4fe61b772f4fa5ee851cb06c0d9c0c"
OLD = ROOT / "epoch170-retry13-rebook-20261122-v1"
STATE = ROOT / "epoch145-guarded-export-20261121-v1/state"
I145 = "8452dba9df42437b9874b35cb44d059f"
IMAGE145 = "18f46b23edd8061eb7ed9ae1566134bc7ea2cbaa6fa7b85cdd1745488366dca4"
U145 = "horizon-holding-export145-20261121-v1.service"
P145 = ROOT / "incident-replay-fit-20261121-v1/tools-homefloor-145-v5t-guard-recovery-v1/post-stop-fit"
I145START = STATE / I145 / "recovery-started.json"
UNIT = "horizon-qualify-170-metered-hourly-20261124-v1.service"
CGROUP = "/system.slice/" + UNIT
TIMER = "horizon-guard-170-metered-hourly-20261124-v1.timer"
GUARD_SERVICE = TIMER.replace(".timer", ".service")
ALIAS = Path("/run/horizon-170-metered-hourly-v1")
INTENT = BASE / "START_INTENT.json"
PLAN = BASE / "guard-plan/guard-plan.json"
GRANT = BASE / "barrier/allow.json"
POST = BASE / "POST_GUARD_CAPACITY.json"
LANE = Path("/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1")
RUN = LANE / "replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/metered-hourly-20261124-v1"
G = 1 << 30
CAP = 384 * G
GROWTH = 96 * G
CPU_MAX = 64_000_000
MEM_MAX = 810_658_050_048
ACTOR = {"cpu_micros": 3_000_000, "memory_max": 68 * G, "memory_high": 64 * G,
         "memory_swap_max": 0, "tasks_max": 1024}
GUARD = {"cpu_micros": 1_000_000, "memory_max": G, "memory_swap_max": 0, "tasks_max": 256}
FIELD = "epoch170_hourly_start_intent"
SUCCESS = "7ad2d189f7e94e70a38c781354912448"
FAILURE = "d9b373ed55a64feb8242e02dbe79a49c"
EXIT = "98e322203f7a4ed290d09fe03c09fe15"
STOP = "de5b426a63be47a7b6ac3eaac82e2f6f"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value, width=64):
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{width}}}", value) and int(value, 16)


def file_id(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def sealed(path, expect=None, *, read=True, limit=2 << 20):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o022 and (not read or st.st_size <= limit),
         f"unsafe evidence {path}")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        raw = stream.read(limit + 1) if read else None
        sha = hashlib.sha256(raw).hexdigest() if read else hashlib.file_digest(stream, "sha256").hexdigest()
        need(file_id(os.fstat(stream.fileno())) == file_id(st) == file_id(path.lstat()),
             f"evidence changed {path}")
    need(expect is None or expect == sha, f"wrong SHA-256 {path}")
    return (json.loads(raw) if read else None), dict(path=str(path), sha256=sha)


def binding(ref, expected, **kwargs):
    need(ref["path"] == str(expected) and digest(ref["sha256"]), f"foreign receipt {expected}")
    return sealed(expected, ref["sha256"], **kwargs)[0]


def properties(unit, *fields):
    pairs = subprocess.check_output(
        ["/usr/bin/systemctl", "show", unit, "-p", ",".join(fields)], text=True, timeout=8)
    result = dict(line.split("=", 1) for line in pairs.splitlines())
    need(set(result) == set(fields), f"incomplete native scope {unit}")
    return result


def pid1(unit, iid, boot, message_ids):
    args = ["/usr/bin/journalctl", "--no-pager", "-o", "json", "_PID=1",
            f"_BOOT_ID={boot.replace('-', '')}", f"UNIT={unit}", f"INVOCATION_ID={iid}"]
    args += ["MESSAGE_ID=" + code for code in message_ids]
    return [json.loads(raw) for raw in subprocess.check_output(args, timeout=12).splitlines()]


def ready_contract():
    ready, ready_ref = sealed(READY, READY_SHA)
    inputs = binding(ready["inputs"], SEALED / "inputs.json")
    bootstrap = binding(ready["bootstrap"], BASE / "BOOTSTRAP_STAGED.json")
    seal = binding(ready["sealed"], SEALED / "deployment-seal-receipt.json")
    binding(ready["service"], BASE / UNIT, read=False)
    need(seal["destination"] == str(SEALED) and not ready["worker_launched"]
         and ready["reservation_ending_bytes"] == 0
         and inputs["retained_booking_bytes"] == CAP and inputs["private_growth_bytes"] == GROWTH
         and inputs["canonical_publication_authorized"] is False
         and inputs["case"]["slot"] == 73_711_515 and inputs["case"]["status"] is None,
         "different staged diagnostic")
    membership = {row["name"]: row for row in seal["members"]}
    need(set(membership) == {"diagnostic170.py", "inputs.json", "canonical-hashes.txt"}
         and membership["inputs.json"]["sha256"] == ready["inputs"]["sha256"], "different input seal")
    for name in ("diagnostic170.py", "canonical-hashes.txt"):
        binding(dict(path=str(SEALED / name), sha256=membership[name]["sha256"]), SEALED / name, read=False)
    snap = Path(inputs["snapshot"]["path"])
    need(snap.is_relative_to(RUN / "inputs") and snap.resolve(strict=True) == snap
         and file_id(snap.lstat()) == inputs["snapshot"]["identity"]
         and bootstrap["bytes"] == inputs["bootstrap"]["size"] == snap.stat().st_size
         and bootstrap["generation"] == inputs["bootstrap"]["generation"] == "1634787456399441"
         and bootstrap["snapshot"] == {k: inputs["snapshot"][k] for k in ("path", "sha256")}
         and bootstrap["replay_launched"] is False, "staged snapshot identity changed")
    # Check both historical CPU/memory ceilings. The 170 price also binds the paid epoch cap.
    prepared = binding(inputs["predecessor"][str(OLD / "PREPARED.json")], OLD / "PREPARED.json")
    old_guard, old_guard_ref = sealed(OLD / "GUARD_ARGV.json",
                                      "03602cc48ce0d49c11c1de7d1ef9a7d3906e4035e76357456c36b13d518fad81")
    need(set(("--property=CPUQuota=900%", "--property=MemoryMax=73014444032", "--property=MemorySwapMax=0"))
         <= set(prepared["baseline"]["profile"]["producer_argv"])
         and {"--property=CPUQuota=100%", "--property=MemoryMax=1G", "--property=MemorySwapMax=0"} <= set(old_guard),
         "retained 170 CPU or memory booking differs")
    return dict(ready=ready_ref, inputs=ready["inputs"], snapshot=inputs["snapshot"],
                node=inputs["node"], worker=inputs["worker"], guard=inputs["guard"], service=ready["service"],
                old_guard_argv=old_guard_ref, bootstrap=ready["bootstrap"])


def process_argv(pid):
    return [os.fsdecode(a) for a in (Path("/proc") / str(pid) / "cmdline").read_bytes().split(b"\0") if a]


def epoch145_members(s, fit):
    members = fit.members(U145)
    if len(members) != 3:
        return members
    # An independent read-only quote may overlap the exact old V5u price.
    # Its already paid Python child is part of the same non-replay cgroup.
    parent = int(s.show(U145)["MainPID"])
    known = []
    for pid in members:
        if pid == parent:
            continue
        a = process_argv(pid)
        proc = Path("/proc") / str(pid)
        if (len(a) == 6 and a[2:4] == [str(P145), "145"] and
                Path(a[0]).resolve() == Path("/usr/bin/python3").resolve() and
                a[1] in ("-IB", "-BI") and digest(a[5]) and
                Path(a[4]).parent.parent == ROOT and Path(a[4]).name == "ROOT_COMPLETE_OPERATIONAL_FLEET.json" and
                s.process(pid)[0::2] == (parent, "0::/system.slice/" + U145) and
                s.same_file(proc / "exe", Path("/usr/bin/python3"))):
            known.append(pid)
    need(len(known) == 1, "foreign concurrent V5u price process")
    return tuple(pid for pid in members if pid not in known)


def drained145(s, fit):
    m = s.show(U145)
    need(not fit.members(U145) and not m["Job"] and m["MainPID"] == m["ControlPID"] == "0"
         and m["ActiveState"] in ("inactive", "failed") and not m["ControlGroup"],
         "epoch 145 is not drained")
    started, start_ref = sealed(I145START, "85dede3d71e27414b28369d1686fe4d7e9ee207bcf6ac4a2c083836961149549")
    need(started["iid"] == I145 and started["image"] == IMAGE145 and not started["r2_mutations"]
         and started["fresh_fit"]["phase145"]["stage"] == "controller"
         and started["fresh_fit"]["phase145"]["invocation_id"] == I145, "unbound V5u start")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    events = pid1(U145, I145, boot, (SUCCESS, FAILURE, EXIT, STOP))
    end = [row for row in events if row["MESSAGE_ID"] in (SUCCESS, FAILURE)]
    need(len(end) == 1 and end[0] == events[-1], "missing exact V5u PID1 terminal")
    terminal = end[0]
    good = terminal["MESSAGE_ID"] == SUCCESS
    need(not any(r["MESSAGE_ID"] == STOP for r in events) and m["InvocationID"] in ("", I145)
         and (good or (terminal["UNIT_RESULT"] == "exit-code" and
                       any(r["MESSAGE_ID"] == EXIT and r.get("EXIT_STATUS") == "1" for r in events))),
         "different V5u outcome")
    v, vref = sealed(I145START.with_name("complete.json" if good else "failed.json"))
    need(v["iid"] == I145 and not v["r2_mutations"], "V5u terminal receipt differs")
    if good:
        leaf = binding(v["receipt"], I145START.with_name("extraction-complete.json"))
        need(leaf["actor_iid"] == I145 and leaf["recovery_evidence"] == start_ref
             and not leaf["archive_publication_authorized"] and not leaf["r2_mutations"],
             "different completed 145 candidate")
        binding(leaf["verified_frozen"], I145START.with_name("verified-frozen.json"))
    need(s.show(U145) == m and not fit.members(U145), "V5u name changed during terminal capture")
    return dict(stage="v5u-drained", native=m, terminal=terminal, result=vref)


def empty_actor(s, fit):
    m = s.show(UNIT)
    timer = s.show(TIMER)
    need(not fit.members(UNIT) and m["MainPID"] == m["ControlPID"] == "0"
         and m["ActiveState"] == timer["ActiveState"] == "inactive" and not m["Job"] and not timer["Job"]
         and not Path("/sys/fs/cgroup" + CGROUP).exists() and not GRANT.exists() and not INTENT.exists(),
         "170 diagnostic already staged or claimed")


def owner(s, fit, contract, fleet, fleet_ref, row, stage):
    src, ref = sealed(INTENT)
    iid, pid, ticks = src["invocation_id"], src["pid"], src["start_ticks"]
    need(src["schema"] == "horizon-epoch170-hourly-held-intent-v1" and src["unit"] == UNIT
         and src["inputs_ready"] == contract["ready"] and src["inputs"] == contract["inputs"]
         and src["service"] == contract["service"] and digest(iid, 32)
         and src["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
         and src["diagnostic_only"] is True and src["reservation_ending_bytes"] == 0,
         "foreign diagnostic start intent")
    before = binding(src["prestart"], BASE / "PRESTART.json")
    proposal = before["hourly170_diagnostic"]
    need(proposal["stage"] == "prestart" and proposal["inputs_ready"] == contract["ready"]
         and before["fits"] and proposal["launch_compatible"] and not before["replay_launch_authorized"]
         and proposal["private_growth_bytes"] == GROWTH and before["bookings"]["170"]["cap_bytes"] == CAP,
         "unfunded diagnostic prestart")
    if stage == "post-guard":
        need(src["fleet"] == before["fleet"] == fleet_ref,
             "post-guard quote crossed the accepted prestart fleet; recapture before starting")
        need(not GRANT.exists() and not row and 0 <= time.time() - before["recorded_unix_seconds"] <= 180,
             "released, stale or duplicate held diagnostic")
    plan = binding(src["guard_plan"], PLAN)
    need(plan == dict(schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=UNIT, invocation_id=iid,
                      filesystem="/home/sol", minimum_free_bytes=proposal["protected_raw_floor_bytes"],
                      worker_root=str(LANE), maximum_worker_vmas=3_500_000,
                      maximum_root_physical_bytes=proposal["whole_tree_guard_cap_bytes"],
                      receipt_directory=str(BASE / "guard-receipts")), "different paid diagnostic guard plan")
    fields = ("Id", "MainPID", "ActiveState", "SubState", "ControlPID", "Job", "InvocationID", "ControlGroup",
              "NRestarts", "User", "Group", "CPUQuotaPerSecUSec", "MemoryMax", "MemoryHigh",
              "MemorySwapMax", "TasksMax", "FragmentPath")
    m = properties(UNIT, *fields)
    need(m["Id"] == UNIT and m["MainPID"] == str(pid) and m["InvocationID"] == iid
         and m["ControlGroup"] == CGROUP and m["ActiveState"] == "active" and m["SubState"] == "running"
         and not m["Job"] and m["NRestarts"] == m["ControlPID"] == "0"
         and m["User"] == "sol" and m["Group"] == "horizon" and m["CPUQuotaPerSecUSec"] == "3s"
         and int(m["MemoryMax"]) == ACTOR["memory_max"] and int(m["MemoryHigh"]) == ACTOR["memory_high"]
         and m["MemorySwapMax"] == "0" and int(m["TasksMax"]) == ACTOR["tasks_max"], "changed actual diagnostic unit")
    sealed(Path(m["FragmentPath"]), contract["service"]["sha256"], read=False)
    group = Path("/sys/fs/cgroup" + CGROUP)
    need((group / "cpu.max").read_text().split() == ["300000", "100000"] and
         int((group / "memory.max").read_text()) == ACTOR["memory_max"] and
         int((group / "memory.high").read_text()) == ACTOR["memory_high"] and
         int((group / "memory.swap.max").read_text()) == 0 and int((group / "pids.max").read_text()) == 1024,
         "different diagnostic kernel limits")
    t = properties(TIMER, "Id", "ActiveState", "InvocationID", "Triggers", "Job",
                   "Requisite", "After", "StopPropagatedFrom")
    g = properties(GUARD_SERVICE, "Id", "CPUQuotaPerSecUSec", "MemoryMax", "MemorySwapMax", "TasksMax", "TriggeredBy")
    relation = ("Requisite", "After", "StopPropagatedFrom")
    need({key: value for key, value in t.items() if key not in relation} ==
         dict(Id=TIMER, ActiveState="active", InvocationID=src["timer_iid"], Triggers=GUARD_SERVICE, Job="")
         and all(UNIT in t[key].split() for key in relation)
         and g == dict(Id=GUARD_SERVICE, CPUQuotaPerSecUSec="1s", MemoryMax=str(G), MemorySwapMax="0",
                       TasksMax="256", TriggeredBy=TIMER), "different diagnostic timer or guard limits")
    proc = Path("/proc") / str(pid)
    exe = proc / "exe"
    members = fit.members(UNIT)
    need(s.process(pid)[1:] == (ticks, "0::" + CGROUP) and pid in members, "foreign diagnostic PID or start")
    paths = proc / "root" / ALIAS.relative_to("/")
    for name, expected in (("diagnostic170.py", SEALED / "diagnostic170.py"), ("inputs.json", SEALED / "inputs.json"),
                           ("jetstreamer-node", Path(contract["node"]["path"])),
                           ("historical-worker-v1-5-6", Path(contract["worker"]["path"])),
                           ("canonical-hashes.txt", SEALED / "canonical-hashes.txt"), ("barrier", GRANT.parent)):
        link = paths / name
        need(os.path.samefile(link, expected) and os.statvfs(link).f_flag & os.ST_RDONLY,
             f"changed mounted diagnostic input {name}")
    log = (RUN / "producer.log").stat()
    need(src["log_device_inode"] == [log.st_dev, log.st_ino] and
         all(os.path.samefile(proc / "fd" / fd, RUN / "producer.log") for fd in ("1", "2")),
         "foreign append log")
    expected_gate = ["/usr/bin/python3", "-IB", str(ALIAS / "diagnostic170.py"), "run", contract["inputs"]["sha256"]]
    a = process_argv(pid)
    held = a == expected_gate and os.path.samefile(exe, "/usr/bin/python3")
    processes = [[pid, ticks, exe.stat().st_dev, exe.stat().st_ino]]
    if stage == "post-guard":
        need(held and members == (pid,), "producer escaped post-guard hold")
    else:
        grant, _ = sealed(GRANT)
        post = binding(dict(path=str(POST), sha256=grant["native_post_guard_fit_sha256"]), POST)
        need(grant["schema"] == "horizon-epoch170-metered-hourly-postguard-release-v1" and grant["unit"] == UNIT
             and grant["invocation_id"] == iid and grant["pid"] == pid and grant["start_ticks"] == ticks
             and grant["inputs_sha256"] == contract["inputs"]["sha256"] and grant["guard_plan_sha256"] == src["guard_plan"]["sha256"]
             and grant["first_guard_sha256"] == src["first_guard"]["sha256"]
             and post["fits"] and post["hourly170_diagnostic"]["intent"] == ref
             and post["hourly170_diagnostic"]["stage"] == "post-guard"
             and post["hourly170_diagnostic"]["receipt"] == src["first_guard"]
             and post["fleet"] == src["fleet"] and grant["boot_id"] == src["boot_id"]
             and 0 <= grant["issued_unix_seconds"] - post["recorded_unix_seconds"] <= 90
             and (row is not None or fleet["recorded_unix_seconds"] < grant["issued_unix_seconds"])
             and src["log_device_inode"] == grant["log_device_inode"] and not grant["archive_publication_authorized"],
             "different live release or post-guard quote")
        args = [str(ALIAS / "jetstreamer-node"), "170", str(RUN / "ledger"), "--verify",
                f"--epoch-hashes={ALIAS}/canonical-hashes.txt", f"--snapshot-archive={contract['snapshot']['path']}",
                f"--horizon-output={RUN}/ledger/epoch-170.diagnostic.jet", f"--replay-scratch={RUN}/scratch",
                "--qualification-end-slot=73713261"]
        need(a == args and os.path.samefile(exe, contract["node"]["path"]) and len(members) in (1, 2),
             "different released node")
        if len(members) == 2:
            child = next(p for p in members if p != pid)
            pp, ct, cg = s.process(child)
            ce = Path("/proc") / str(child) / "exe"
            child_path = ce.readlink()
            ce_stat = ce.stat()
            with ce.open("rb") as worker:
                sha = hashlib.file_digest(worker, "sha256").hexdigest()
            need(pp == pid and cg == "0::" + CGROUP and child_path.is_relative_to(RUN / "scratch")
                 and child_path.name == "historical-worker" and sha == contract["worker"]["sha256"],
                 "foreign metered worker ownership")
            processes.append([child, ct, ce_stat.st_dev, ce_stat.st_ino])
    if row is not None:
        need(row[FIELD] == ref and row["unit"]["Id"] == UNIT and row["unit"]["InvocationID"] == iid
             and int(row["unit"]["MainPID"]) == pid, "unjoined private cadence row")
    need(fit.members(UNIT) == members and properties(UNIT, *fields) == m, "diagnostic native owner changed")
    return dict(unit=UNIT, processes=processes, iid=iid, timer_iid=t["InvocationID"],
                plan=src["guard_plan"], first=src["first_guard"], intent=ref,
                gate_prestart=src["prestart"], baseline=proposal["baseline_physical_bytes"], native_plan=plan)


def roster(fleet, stage):
    ordinary = fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"]
    private = fleet["actual_active_private_diagnostics"]
    selected = [v for v in private if v["epoch"] == 170]
    need(len(selected) <= 1 and not any(v["epoch"] == 170 for v in ordinary)
         and (stage == "active" or not selected), "overlapping epoch 170 registration")
    return ordinary + [v for v in private if v["epoch"] != 170], (selected[0] if selected else None)


def sample(contract, actor, stage):
    directory = BASE / "guard-receipts"
    if stage == "post-guard":
        ref = actor["first"]
        path = Path(ref["path"])
        need(path.parent == directory, "foreign first guard path")
    else:
        paths = [p for p in directory.glob("sample-*.json") if re.fullmatch(r"sample-[0-9a-f]{32}\.json", p.name)]
        need(paths, "missing live guard receipts")
        path = max(paths, key=lambda p: p.stat().st_mtime_ns)
        _, ref = sealed(path)
    g = binding(ref, path)
    p = actor["native_plan"]
    r = g["root_physical_observation"]
    cap = p["maximum_root_physical_bytes"]
    need(g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
         and path.name == f"sample-{g['guard_invocation_id']}.json" and digest(g["guard_invocation_id"], 32)
         and g["producer_invocation_id"] == actor["iid"] == g["producer"]["invocation_id"]
         and g["producer"]["pid"] == actor["processes"][0][0] and g["producer"]["cgroup"] == CGROUP
         and g["guard_sha256"] == contract["guard"]["sha256"] and g["plan_sha256"] == actor["plan"]["sha256"]
         and g["plan"] == actor["plan"]["path"] and g["maximum_worker_vmas"] == 3_500_000
         and g["minimum_free_bytes"] == p["minimum_free_bytes"] <= g["available_bytes"]
         and g["maximum_root_physical_bytes"] == r["maximum_physical_bytes"] == cap
         and 0 <= time.time() - g["recorded_unix_seconds"] <= 90 and g["producer_stop_enabled"]
         and not r["exceeds_budget"] and not g["trip_reason"] and not g["worker_observation_error"]
         and not g["root_physical_observation_error"] and not g["r2_mutations"] and not g["remote_mutations"]
         and not g["bounded_measurement"] and g["bounded_canary"] is None and g["native_main"] is None
         and g.get("DATA_fulfillment") is None,
         "different or stale 170 guard sample")
    if stage == "post-guard":
        need(not g["workers"], "first guard observed released replay")
        rows = pid1(GUARD_SERVICE, g["guard_invocation_id"],
                    Path("/proc/sys/kernel/random/boot_id").read_text().strip(), (SUCCESS, FAILURE, EXIT))
        need(len(rows) == 1 and rows[0]["MESSAGE_ID"] == SUCCESS, "first timer guard lacks PID1 success")
    else:
        need(g["workers"] == [p[:2] for p in actor["processes"][1:]], "live worker has no exact completed guard sample")
    walks = [r[key] for key in ("first", "second")]
    need(all(actor["baseline"] <= t["physical_bytes"] <= cap for t in walks), "out-of-scope whole-tree growth")
    physical = min(t["physical_bytes"] for t in walks) if not any(t["vanished_entries"] for t in walks) else actor["baseline"]
    return dict(receipt=ref, measured_bytes=physical, available_bytes=g["available_bytes"])


def price(native, contract, actor, guard, stage):
    book = native["bookings"]["170"]
    need(native["complete_cpu_quota_micros"] == CPU_MAX and
         native["complete_memory_plus_reserve_bytes"] == MEM_MAX and
         native["resource_credit_bytes"] == 0 and native["replay_launch_authorized"] is False
         and native["failed_cold170"]["reservation_ending_bytes"] == 0
         and not native["candidate136"]["occupied"] and not native["bounded_qualification"]
         and "170" not in native["replacements"] and book["root"] == str(LANE)
         and book["cap_bytes"] == book["physical_bytes"] + book["remaining_bytes"] == CAP,
         "diagnostic is outside the original 170 or aggregate fleet booking")
    unchanged_required = native["complete_required_HOME_bytes"]
    absolute = max(8_297_502_499_408, native["active168_guard_floor"],
                   *(v["guard"]["floor"] for v in native["survivors"].values()),
                   *(v["floor"] for v in native["replacements"].values()))
    if actor is None:
        baseline = book["physical_bytes"]
        whole_cap = baseline + GROWTH
        need(whole_cap <= CAP, "96 GiB diagnostic exceeds the retained 384 GiB tree")
        floor = max(unchanged_required - GROWTH, absolute)
        remaining = GROWTH
        available = native["available_HOME_bytes"]
    else:
        baseline = actor["baseline"]
        whole_cap = actor["native_plan"]["maximum_root_physical_bytes"]
        need(whole_cap == baseline + GROWTH <= CAP and
             book["physical_bytes"] == guard["measured_bytes"],
             "different retained tree or actual guard measurement")
        floor = max(actor["native_plan"]["minimum_free_bytes"], absolute)
        remaining = whole_cap - guard["measured_bytes"]
        available = min(native["available_HOME_bytes"], guard["available_bytes"])
    # The entire 170 entitlement remains in the native quote. Its diagnostic
    # is a scoped suballocation. Preserve the higher of the two live floors.
    required = max(unchanged_required, floor + remaining)
    context = dict(stage=stage, inputs_ready=contract["ready"], inputs=contract["inputs"],
                   baseline_physical_bytes=baseline, private_growth_bytes=GROWTH,
                   whole_tree_guard_cap_bytes=whole_cap, retained_booking_bytes=CAP,
                   diagnostic_remaining_bytes=remaining, protected_raw_floor_bytes=floor,
                   actor_limits=ACTOR, guard_limits=GUARD, launch_compatible=(native["phase145"]["stage"] == "v5u-drained"),
                   additive_charge_bytes=0, additive_cpu_quota_micros=0, additive_memory_bytes=0,
                   intent=actor["intent"] if actor else None, receipt=guard["receipt"] if guard else None,
                   resource_fit=bool(native["fits"] and available >= required))
    if stage != "prestart":
        need(context["launch_compatible"], "live sealed V5u provider cannot recognize the 170 diagnostic")
    return dict(native, complete_required_HOME_bytes=required, available_HOME_bytes=available,
                fits=context["resource_fit"] and context["launch_compatible"],
                hourly170_diagnostic=context)
