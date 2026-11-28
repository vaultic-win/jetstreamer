"""Launch the guarded second private epoch 143 interval on the ordinary writer roster."""

import ctypes
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time


RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
BASE = RT / "epoch143-second-hourly-20261128-v2"
RUN = Path("/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1")
ALIAS = Path("/run/horizon143-second-hourly-v2")
UNIT = "horizon-qualify-143-second-hourly-20261128-v2.service"
GUARD = "horizon-guard-143-second-hourly-20261128-v2"
LOCK = Path("/run/horizon-epoch171-to136-g1.operation.lock")
TREE = 64 << 30
MEMORY = 40 << 30
EVIDENCE = 64 << 20
GIB = 1 << 30
GUARD_PLAN = BASE / "ACTUAL_GUARD_PLAN.json"
HELD = BASE / "HELD_OWNER.json"
BARRIER = BASE / "barrier"
RECEIPTS = BASE / "guard-receipts"


def need(value, why):
    if not value:
        raise ValueError(why)


def run(*args):
    return subprocess.check_output(args, text=True, timeout=150).strip()


def props(unit, *keys):
    return dict(line.split("=", 1) for line in run("systemctl", "show", unit, "-p", ",".join(keys)).splitlines())


def ref(path):
    with path.open("rb") as source:
        return dict(path=str(path), sha256=hashlib.file_digest(source, "sha256").hexdigest())


def read(reference, *, writable_state=False):
    path = Path(reference["path"])
    meta = path.lstat()
    need(path.resolve() == path and stat.S_ISREG(meta.st_mode) and meta.st_uid == 0
         and not meta.st_mode & (0o022 if writable_state else 0o222) and meta.st_nlink == 1, "unsealed receipt " + str(path))
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == reference["sha256"], "changed receipt " + str(path))
    return json.loads(raw)


def member(package, name, seal):
    receipt = read(seal)
    rows = [row for row in receipt["members"] if row["name"] == name]
    path = package / name
    st = path.lstat()
    need(receipt["destination"] == str(package) and len(rows) == 1 and path.resolve() == path
         and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o222,
         "unsealed deployment member " + str(path))
    actual = ref(path)
    need(actual["sha256"] == rows[0]["sha256"], "changed deployment member " + str(path))
    return actual


def durable(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    candidate = path.with_name("." + path.name + ".pending")
    with candidate.open("xb") as output:
        output.write(raw)
        os.fchmod(output.fileno(), 0o444)
        output.flush()
        os.fsync(output.fileno())
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(candidate), -100, os.fsencode(path), 1) != 0:
        code = ctypes.get_errno()
        candidate.unlink()
        raise OSError(code, os.strerror(code), path)
    directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return ref(path)


def checked_roster(booking, *, held=None):
    quote = json.loads(run("/usr/bin/python3", "-IB", "-c",
                           "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['whole_roster']()))",
                           booking["price"]["path"]))
    stages = "HELD" if held else "PRESTART"
    if not quote["fits"] or quote["home_margin"] <= 0 or quote["ram_margin"] <= 0:
        refused = durable(BASE / f"{stages}_REFUSED_{time.time_ns()}.json", quote)
        raise ValueError(f"ordinary {stages} quote refused at {refused['path']}, "
                         f"HOME {quote['home_margin']}, RAM {quote['ram_margin']} bytes")
    closed = quote["closed_143"]
    observed = quote["base_169"]["native"]["raw"]["replacement143"]
    need(quote["fleet"] == booking["fleet"] and quote["writer"] == booking["writer"] and quote["fits"]
         and not quote["resource_credit_bytes"] and not quote["preparation_only"]
         and closed["acceptance"] == booking["closure"] and closed["retained_home"] == TREE + EVIDENCE
         and closed["retained_ram"] == MEMORY + GIB and closed["cpu_quota_micros"] == 3_000_000,
         "ordinary quote rejected the second interval or changed the host roster")
    if held:
        need(observed["iid"] == held["producer_invocation_id"] and observed["actor"] == ref(HELD)
             and observed["mode"] == "gate" and observed["cap"] == TREE
             and observed["booking"] == held["booking"], "ordinary held quote identified another producer")
    else:
        need(observed is None, "second interval already has a live producer")
    return quote


def enrollment(booking):
    fleet = read(booking["fleet"], writable_state=True)
    writer = read(booking["writer"], writable_state=True)
    ready = read(writer["ready"])
    native = writer["new"]
    manager = props(native["unit"], "ActiveState", "MainPID", "InvocationID", "Job")
    timer = props(booking["timer"]["unit"], "ActiveState", "SubState", "InvocationID", "Job")
    need(manager == dict(ActiveState="active", MainPID=str(native["pid"]), InvocationID=native["invocation_id"], Job="")
         and timer == dict(ActiveState="active", SubState="waiting", InvocationID=booking["timer"]["invocation_id"], Job="")
         and fleet["sole_next_timer"] == booking["timer"]["unit"] and ready["second_hourly143_retry_contract"] == booking["contract"]
         and ready["second_hourly143_prefix"] == booking["closure"], "writer or observer enrollment changed")
    return fleet


def native_args(contract, plan, digest, booking):
    bindings = dict(contract["read_only_bind_map"])
    bindings[str(plan)] = str(ALIAS / "plan.json")
    bindings[str(BARRIER)] = str(ALIAS / "barrier")
    pairs = [f"{source}:{target}" for source, target in bindings.items()]
    settings = [f"--setenv={key}={value}" for key, value in contract["producer_env"].items()]
    options = [
        "Type=exec", "User=sol", "Group=horizon", "Restart=no", "KillMode=control-group",
        "TimeoutStopSec=20s", f"RuntimeMaxSec={booking['runtime_max_seconds']}", "Delegate=no",
        "TasksMax=512", "CPUQuota=200%", f"MemoryHigh={36 * GIB}", f"MemoryMax={MEMORY}",
        "MemorySwapMax=0", "LimitCORE=0", "ProtectHome=read-only", "ProtectSystem=strict",
        "PrivateTmp=yes", "PrivateDevices=yes", "ProtectControlGroups=yes", "NoNewPrivileges=yes",
        "CapabilityBoundingSet=", f"WorkingDirectory={RUN}", f"ReadWritePaths={RUN}",
        "BindReadOnlyPaths=" + " ".join(pairs), "StandardOutput=journal", "StandardError=journal",
    ]
    args = ["systemd-run", f"--unit={UNIT}", *[f"--property={p}" for p in options], *settings,
            "--", "/usr/bin/env", str(ALIAS / "hold-143"), digest]
    return args, bindings


def make_booking(contract_ref, contract, writer_ref, price_seal):
    writer = read(writer_ref, writable_state=True)
    ready = read(writer["ready"])
    head = max(RT.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    fleet_ref = ref(head)
    timer = read(fleet_ref, writable_state=True)["sole_next_timer"]
    tprops = props(timer, "InvocationID", "NextElapseUSecRealtime")
    due = int(run("date", "-u", "-d", tprops["NextElapseUSecRealtime"], "+%s"))
    now = int(time.time())
    need(now + 120 < due, "the armed observer is due inside admission")
    need(due - now <= 1800 and (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromtimestamp(
         head.stat().st_mtime, tz=dt.timezone.utc)).total_seconds() < 1800, "old observer roster")
    need(ready["second_hourly143_retry_contract"] == contract_ref, "V63 did not register the exact contract")
    price = member(Path(price_seal["path"]).parent, "capacity.py", price_seal)
    return dict(
        schema="horizon-143-second-hourly-booking-v1", unit=UNIT, tree=str(RUN),
        fleet=fleet_ref, writer=writer_ref, timer=dict(unit=timer, invocation_id=tprops["InvocationID"]),
        price=price, price_seal=price_seal, contract=contract_ref, closure=contract["prefix_acceptance"],
        operator=ref(Path(__file__).resolve()), HOME_bytes=TREE + EVIDENCE, RAM_bytes=MEMORY + GIB,
        cpu_quota_micros=3_000_000, record_at=now, runtime_max_seconds=28_800,
        native_census_enrolled=True, recording_authorized=True, archive_publication_authorized=False,
    )


def launch(contract_ref, writer_ref, price_seal, guard_seal):
    contract = read(contract_ref)
    need(contract["unit"] == UNIT and contract["guarded_HOME_bytes"] == TREE
         and contract["producer_RAM_bytes"] == MEMORY and contract["separate_evidence_HOME_bytes"] == EVIDENCE
         and contract["guard_RAM_bytes"] == GIB, "unexpected 143 contract resource scope")
    tools = contract["tools_seal"]
    gate = member(BASE / "tools-v1", "hold-143", tools)
    guard = member(BASE / "guard-v2", "guard", guard_seal)
    need(contract["node"] == member(BASE / "node-v1", "jetstreamer-node", contract["node_seal"]),
         "native node was not sealed")
    custody = read(contract["snapshot_custody"])
    need(ref(Path(custody["snapshot"]["path"])) == custody["snapshot"], "bootstrap payload changed")
    for item in ("prefix_acceptance", "native_terminal"):
        read(contract[item])
    need(RUN.stat().st_dev == Path("/home/sol").stat().st_dev, "private replay tree must use HOME")
    need(not (RUN / "build").exists(), "guarded build scratch must leave the replay tree after sealing")
    for name in ("ledger", "private", "scratch"):
        path = RUN / name
        info = path.stat()
        need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == 1001 and info.st_gid == 1003
             and stat.S_IMODE(info.st_mode) == 0o700, "unexpected staged private tree " + str(path))
    need(ref(RUN / "ledger/genesis.tar.bz2")["sha256"] == contract["genesis"]["sha256"], "genesis changed")
    need(not Path(contract["prepared_output_file"]).exists(), "private interval output already exists")
    for unit in (UNIT, GUARD + ".service", GUARD + ".timer"):
        need(props(unit, "LoadState")["LoadState"] == "not-found", "native unit already exists " + unit)
    booking = make_booking(contract_ref, contract, writer_ref, price_seal)
    booking["guard_seal"] = guard_seal
    enrollment(booking)
    quote = checked_roster(booking)
    need(0 < quote["guard_floor"] <= quote["required_home"] < quote["available_home"],
         "invalid native prestart floor")
    floor_buffer = min(GIB, quote["home_margin"] // 4)
    floor = quote["guard_floor"] + floor_buffer
    need(floor_buffer < quote["available_home"] - quote["required_home"], "guard floor buffer does not fit")
    booking_ref = durable(BASE / f"BOOKING_{time.time_ns()}.json", booking)
    durable(BASE / "PRESTART_SCREEN.json", quote)
    plan = BASE / "NATIVE_PLAN.json"
    plan_ref = durable(plan, dict(schema="horizon-143-private-second-hourly-native-plan-v1",
                                 prefix_acceptance=dict(contract["prefix_acceptance"], path=str(ALIAS / "prefix.json")),
                                 snapshot_custody=dict(contract["snapshot_custody"], path=str(ALIAS / "custody.json")),
                                 minimum_free_bytes=floor))
    args, binds = native_args(contract, plan, plan_ref["sha256"], booking)
    BARRIER.mkdir(mode=0o755)
    BARRIER.chmod(0o755)
    RECEIPTS.mkdir(mode=0o700)
    enrollment(booking)
    started = guarded = released = False
    try:
        run(*args)
        started = True
        owner = props(UNIT, "InvocationID", "MainPID", "ControlGroup", "CPUQuotaPerSecUSec", "MemoryMax", "MemorySwapMax")
        iid, pid = owner["InvocationID"], int(owner["MainPID"])
        need(len(iid) == 32 and pid > 1 and owner["ControlGroup"] == f"/system.slice/{UNIT}"
             and owner["CPUQuotaPerSecUSec"] == "2s" and owner["MemoryMax"] == str(MEMORY)
             and owner["MemorySwapMax"] == "0", "unexpected native producer scope")
        process = Path(f"/proc/{pid}")
        for _ in range(30):
            if (process / "exe").samefile(gate["path"]):
                break
            time.sleep(0.1)
        need((process / "exe").samefile(gate["path"]), "hold gate did not stay bound")
        visible = {fields[4]: fields[5].split(",") for fields in (
            line.split() for line in (process / "mountinfo").read_text().splitlines())}
        for source, target in binds.items():
            projected = process / "root" / target.lstrip("/")
            need(projected.samefile(source) and "ro" in visible[target], "different read-only bind " + target)

        guard_plan = durable(GUARD_PLAN, dict(
            schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=UNIT, invocation_id=iid,
            filesystem="/home/sol", minimum_free_bytes=floor, worker_root=str(RUN),
            maximum_worker_vmas=3_500_000, maximum_root_physical_bytes=TREE, receipt_directory=str(RECEIPTS)))
        guard_args = [guard["path"], guard_plan["path"], "--plan-sha256", guard_plan["sha256"],
                      "--self-sha256", guard["sha256"]]
        run(*guard_args, "--validate-plan-only")
        run("systemd-run", f"--unit={GUARD}", "--on-active=1s", "--timer-property=AccuracySec=1s",
            "--timer-property=OnUnitActiveSec=10s", f"--timer-property=BindsTo={UNIT}",
            f"--timer-property=After={UNIT}", "--property=CPUQuota=100%", f"--property=MemoryMax={GIB}",
            "--property=MemorySwapMax=0", "--property=TasksMax=64", "--property=TimeoutStopSec=10s",
            "--property=Restart=no", "--property=ProtectHome=read-only", "--property=ProtectSystem=strict",
            "--property=PrivateNetwork=yes", f"--property=ReadWritePaths={RECEIPTS}", "--", *guard_args)
        guarded = True
        for _ in range(80):
            samples = sorted(RECEIPTS.glob("sample-*.json"))
            if samples:
                break
            time.sleep(0.15)
        need(samples, "no invocation-bound first guard sample")
        sample_ref = ref(samples[0])
        sample = json.loads(samples[0].read_bytes())
        need(sample["producer_invocation_id"] == iid and sample["producer"]["pid"] == pid
             and sample["plan_sha256"] == guard_plan["sha256"] and sample["minimum_free_bytes"] == floor
             and sample["producer_stop_enabled"] and not sample["workers"]
             and sample["trip_reason"] is sample["root_physical_observation_error"] is sample["worker_observation_error"] is None
             and not sample["root_physical_observation"]["exceeds_budget"], "protected held gate check failed")
        timer = props(GUARD + ".timer", "Id", "ActiveState", "InvocationID", "BindsTo", "Job")
        need(timer["ActiveState"] == "active" and timer["BindsTo"] == UNIT and not timer["Job"],
             "guard timer did not bind the producer")
        actor = dict(schema="horizon-epoch143-second-hourly-held-owner-v1", unit=UNIT,
                     producer_invocation_id=iid, producer_pid=pid, closure=booking["closure"],
                     start_ticks=int((process / "stat").read_text().rsplit(") ", 1)[1].split()[19]),
                     boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                     guard_timer_invocation_id=timer["InvocationID"], guard_plan=guard_plan,
                     first_guard=sample_ref, booking=booking_ref, contract=contract_ref,
                     recorded_unix_seconds=int(time.time()), archive_publication_authorized=False)
        actor_ref = durable(HELD, actor)
        held = checked_roster(booking, held=actor)
        durable(BASE / "POST_GUARD_SCREEN.json", held)
        enrollment(booking)
        need(held["epoch143_installed_guard_floor"] == floor and held["guard_floor"] <= floor and held["required_home"] + floor - held["guard_floor"] <= held["available_home"]
             and props(UNIT, *owner) == owner and props(GUARD + ".timer", *timer) == timer
             and (process / "exe").samefile(gate["path"]) and not (RECEIPTS / "stop-intent.json").exists(),
             "held quote, producer or guard advanced before permission")
        permit = durable(BARRIER / "allow", iid.encode())
        released = True
        return dict(actor=actor_ref, permit=permit, invocation_id=iid, producer_pid=pid, replaced_first_interval=True)
    finally:
        if not released:
            if started:
                subprocess.run(["systemctl", "stop", UNIT], check=False, timeout=30)
            if guarded:
                subprocess.run(["systemctl", "stop", GUARD + ".timer", GUARD + ".service"], check=False, timeout=30)


if __name__ == "__main__":
    need(os.geteuid() == 0 and len(sys.argv) == 9, "supply the sealed contract, writer, quote and guard references")
    values = [dict(path=path, sha256=digest) for path, digest in zip(sys.argv[1::2], sys.argv[2::2])]
    with LOCK.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(launch(*values), indent=2))
