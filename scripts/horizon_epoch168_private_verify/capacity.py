"""Price the serial private reader against the 143 and 170 reservations."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import stat
import subprocess

G = 1 << 30
M = 1 << 20
RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
HOME_FS = Path("/home/sol")
READER = HOME_FS / ".jetstreamer-private/epoch168-anza-reader-build-20261127.jMydZnTw"
CURRENT = RT / "epoch170-from-73746882-20261127-v1/attempt-2"
FOLLOWING = RT / "epoch170-from-73766969-20261127-v1"
CURRENT_SEAL = "3fd92f9c66b9a42f9159886355e842764244fb3685d4bf03e36cf700e550a7f3"
FOLLOWING_SEAL = "0388c77e3eb1af9df0d592bc09e86c13c9b23ea2f2b5b589b9a104c02dbf8759"
OPERATION = Path("/run/horizon-epoch171-to136-g1.operation.lock")
SERIAL = Path("/run/lock/horizon-epoch140-suffix-compiler.lock")
CURRENT_IID = "c3ab30cfeb05428bb8f5c48a5a44822c"
PACKAGE_BYTES = 738197504 + 283820032 + 353947648
BOOK = READER / "v2-20261127/campaign-price.py"
PAIR = READER / "admit-pair.py"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def check_file(path, expected, immutable=True):
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_nlink == 1
         and (not immutable or (st.st_uid == 0 and not st.st_mode & 0o222))
         and digest(path) == expected, "changed source " + str(path))


def sealed(directory, expected):
    receipt = directory / "deployment-seal-receipt.json"
    check_file(receipt, expected)
    seal = json.loads(receipt.read_bytes())
    need(seal["destination"] == str(directory), "foreign pricing module")
    for member in seal["members"]:
        path = directory / member["name"]
        need(path.parent == directory and path.stat().st_size == member["bytes"], "changed member")
        check_file(path, member["sha256"])
    return directory


def load_helpers():
    check_file(BOOK, "5bb2552e1bbe3fa52826be1c2c5b630ae8a243974d4a6ed11f9a52eacc4ce832")
    check_file(PAIR, "c5904b02fbad6443fd1e6ed97dbadfd25ca102eff40293bdf922e2d6c4f177e2")
    return runpy.run_path(str(BOOK)), runpy.run_path(str(PAIR))


def guarded(provider):
    core = provider["prior"]
    actor_dir = provider["DEP"]
    progress, ref = core.read(actor_dir / "FIRST_PROTECTED_PROGRESS.json")
    release = core.bound(progress["release"])
    actor = core.bound(progress["actor"])
    plan = core.bound(release["guard_plan"])
    profile = core.bound(progress["scope"])["profile"]
    iid = progress["producer_invocation_id"]
    unit = provider["UNIT"]
    worker = progress["worker"]
    need(actor["producer_invocation_id"] == release["producer_invocation_id"] == plan["invocation_id"] == iid
         and (actor_dir != CURRENT or iid == CURRENT_IID)
         and progress["scope"] == actor["interface"] == release["interface"]
         and progress["actor"] == release["actor"]
         and progress["guard_timer_invocation_id"] == release["guard_timer_invocation_id"]
         and actor["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip()
         and actor["unit"] == plan["unit"] == unit == profile["host_unit"]
         and actor["producer_pid"] == progress["producer_pid"] and
         profile["producer_memory_bytes"] == 48*G and profile["guard_memory_bytes"] == G
         and profile["worker"] == worker["sha256"] and plan["worker_root"] == str(core.TREE)
         and plan["filesystem"] == str(HOME_FS), "unbound epoch 170 actor")
    rows = []
    for pid, ticks, image in [(actor["producer_pid"], actor["start_ticks"], profile["node"]["path"]),
                              (worker["pid"], worker["start_ticks"], worker["exe"])]:
        proc = Path("/proc") / str(pid)
        st = (proc/"exe").stat()
        need((proc/"exe").samefile(image), "different protected 170 program")
        rows.append([pid, ticks, st.st_dev, st.st_ino])
    sample, low, _ = core.protected(unit, rows, progress["guard_timer_invocation_id"],
                                    progress["native_guard"], 48*G, "6s", False)
    actual = core.bound(sample)
    cap, floor = plan["maximum_root_physical_bytes"], plan["minimum_free_bytes"]
    need(actual["plan_sha256"] == release["guard_plan"]["sha256"]
         and actual["minimum_free_bytes"] == floor
         and actual["root_physical_observation"]["maximum_physical_bytes"] == cap
         and 0 < low <= cap <= 384*G, "different live guarded 170 tree")
    anon = provider["anonymous"](unit, iid, [r[:2] for r in rows], 48*G)
    return dict(iid=iid, progress=ref, guard=sample, plan=release["guard_plan"], floor=floor,
                cap=cap, measured_tree=low, anonymous=anon, roster=rows)


def quote(provider, phase):
    for attempt in range(5):
        try:
            return provider["price"](phase)
        except subprocess.CalledProcessError as err:
            # A live AccountsDB can unlink an inode between directory enumeration and stat.
            # A failed traversal never supplies a byte count. Start the full quote again.
            if attempt == 4 or err.cmd[0] != "/usr/bin/du" or err.returncode != 1:
                raise


def slice_admission(api):
    pool = RT/"ready-range-audit-20261121-v1/pool/anza-149-156/jobs"
    root = api["SLICE"]
    names = {p.name for p in root.iterdir() if p.is_dir() and (p/"cgroup.procs").read_text().strip()}
    baseline = {"horizon-r2-ready-parallel-regions-20261121-v1.service":7_000_000,
                "horizon-r2-ready-ranges-101-300-20261121-v1.service":4_000_000}
    pending = {f"horizon-anza-ready-audit@{epoch}.service" for epoch in range(149,157)
               if (pool/str(epoch)/"READY").is_file()}
    if names == set(baseline) and not pending:
        return dict(api["cgroup_admission"](),additional_audit_ram=0)
    fields = {name:(root/name).read_text().strip() for name in
              ("cpu.max","memory.current","memory.high","memory.max","memory.swap.max","pids.current","pids.max")}
    need(fields["cpu.max"] == "1200000 100000" and fields["memory.swap.max"] == "0", "unknown reader slice")
    quotas = {}
    for name in names:
        cpu, period = (root/name/"cpu.max").read_text().split()
        quota = int(cpu)*1_000_000//int(period)
        need((name in baseline and quota == baseline[name]) or
             (re.fullmatch(r"horizon-anza-ready-audit@(149|15[0-6])\.service",name)
              and quota == 1_000_000 and (root/name/"memory.max").read_text().strip() == str(2*G)
              and (root/name/"memory.swap.max").read_text().strip() == "0"
              and (pool/name.split("@")[1].split(".")[0]/"current/CONSUMED").is_file()),
             "unknown audit owner " + name)
        quotas[name] = quota
    for name in set(baseline)-names:
        state = api["state"](name)
        need(state["ActiveState"] == "inactive" and not state["Job"] and not state["ControlGroup"],
             "baseline auditor in transition")
    for name in pending-names:
        quotas[name] = 1_000_000
    extra_ram = len(set(quotas)-set(baseline))*2*G
    memory = min(int(fields["memory.high"]),int(fields["memory.max"]))-int(fields["memory.current"])
    tasks = fields["pids.max"] == "max" or int(fields["pids.max"])-int(fields["pids.current"]) >= 96
    fits = sum(quotas.values())+1_000_000 <= 12_000_000 and memory >= 2*G+extra_ram and tasks
    return dict(properties=fields,child_quotas=quotas,pending=sorted(pending),ram_room=memory,
                additional_audit_ram=extra_ram,fits=fits)


def actual_budget(q, provider, phase, before, after):
    assembly = q["assembly168"]
    growth = q["joint"]["candidate_growth"]
    incremental = assembly["incremental_home"]
    need(growth == 36*G and q["joint"]["producer_allowance"] == 48*G
         and q["joint"]["guard_sibling_allowance"] == G
         and q["resource_credit_bytes"] == 0 and q["phase"] == phase, "changed replay commitments")
    floor = q["required_home"] - incremental - growth
    extra = 0
    observed_170 = 0
    if phase == "held":
        need(before["iid"] == after["iid"] == q["priced_170_invocation"]
             and before["roster"] == after["roster"] and before["plan"] == after["plan"],
             "170 changed during the quote")
        remaining = before["cap"] - min(before["measured_tree"], after["measured_tree"],
                                        q["terminal_tree_bounds"][0])
        extra = max(0, remaining-growth)
        floor = max(floor, before["floor"])
        observed_170 = min(before["anonymous"], after["anonymous"])
    required_home = floor + incremental + growth + extra
    # The provider's separate historical screen prices its original booked 36 GiB.
    # The exact issued 170 floor and remaining cap apply to the independent live screen.
    available_home, available_ram = provider["prior"].availability()
    available_home = min(available_home, q["available_home"])
    available_ram = min(available_ram, q["available_ram"])
    required_ram = q["required_ram"] - observed_170
    return dict(raw=q, available_home=available_home, required_home=required_home,
                home_margin=min(available_home-required_home, q["historical_home_margin"]),
                available_ram=available_ram, required_ram=required_ram, ram_margin=available_ram-required_ram,
                historical_home_margin=q["historical_home_margin"], realized_170_anon=observed_170,
                realized_168_incremental_anon=0, actual_170_before=before, actual_170_after=after)


def current_controls(base, book, new_pricing, core, output_bytes):
    q = base["raw"]
    n, proof = new_pricing["load_holding"](core)
    fleet = n.accepted_fleet(q["fleet"])
    funded = fleet["retry9_auxiliary_commitments"]
    serial = n.repeated_serial_slot(q, funded)
    compiler = n.compiler_reservation()
    holding = new_pricing["holding_owner"](core, n)
    intake, hist_input, in_progress, ram_input = new_pricing["incoming"](core, n, fleet, None)
    recorder = book["micro_cost"](n)
    rooms = n.margins(base, funded, compiler["image_physically_funded_bytes"], serial["repeated_serial_bytes"])
    history = base["historical_home_margin"] - rooms["build_home"] - hist_input
    live = base["available_home"] - base["required_home"] - in_progress - rooms["build_home"] + compiler["image_physically_funded_bytes"]
    need(new_pricing["holding_owner"](core, n) == holding and core.current_fleet()[1] == q["fleet"],
         "holding or fleet changed while pricing private scan")
    return dict(shared_price=rooms, funding=serial, holding=holding, input=intake, native_compiler=compiler,
                recorder=recorder, price_seal=proof,
                remaining_home=min(live, history)-32*M-output_bytes,
                remaining_ram=rooms["post_reservation_ram_margin"]-ram_input-recorder["witness_ram"]-128*M)


def price(fixture=False):
    book, api = load_helpers()
    capacity = slice_admission(api)
    current = sealed(CURRENT/"issued-price-v47", CURRENT_SEAL)
    if fixture and api["state"]("horizon-assemble-168-private-20261127-v1.service")["ActiveState"] == "active":
        sample = book["sample_funded_memory"]()
        live = runpy.run_path(str(current/"live_168_170_price.py"))
        base = live["live_price"]()
        room = book["price"](base,2*G,sample,outside=PACKAGE_BYTES+128*M)
        room["remaining_ram"] -= 128*M + capacity["additional_audit_ram"]
        return dict(fits=capacity["fits"] and room["remaining_home"] >= 0 and room["remaining_ram"] >= 0,
                    capacity=capacity,provider=str(current/"live_168_170_price.py"),base=base,room=room,
                    retained_packages=PACKAGE_BYTES,controller_ram=128*M,canonical_writes=False)
    following = sealed(FOLLOWING/"operator-v2", FOLLOWING_SEAL)
    if api["state"]("horizon-qualify-170-from-73746882-20261127-v1.service")["ActiveState"] == "active":
        directory, old = current, True
    else:
        directory, old = following, False
    provider = runpy.run_path(str(directory/"continuation_price.py"))
    phase = "held" if api["state"](provider["UNIT"])["ActiveState"] == "active" else "start"
    if old:
        need(phase == "held", "170 predecessor is between owners")
    outside = PACKAGE_BYTES + 128*M
    residency = book["sample_funded_memory"]() if old else None
    before = guarded(provider) if phase == "held" else None
    q = quote(provider, phase)
    after = guarded(provider) if phase == "held" else None
    base = actual_budget(q, provider, phase, before, after)
    need(q["replacement143"] or q["guarded_hourly_remaining"] == 64*G, "143 hourly commitment missing")
    if not fixture:
        need(q["assembly168"]["state"] == "queued-or-drained" and not q["assembly168"]["incremental_home"],
             "assembler has not released its allocation")
    core = provider["prior"]
    proposed = set(q["joint"]["guard_samples"])
    if after:
        proposed.add(provider["UNIT"])
    if q["replacement143"]:
        proposed.add(q["replacement143"]["unit"])
    future = runpy.run_path(str(following/"following_capacity.py"))
    n, _ = future["load_holding"](core)
    need(n.active_units("horizon-qualify-*") == proposed, "live replay roster changed")
    if old and not q["replacement143"]:
        room = book["price"](base,2*G,residency,outside=outside)
        room["remaining_ram"] -= 128*M
    elif old:
        room = current_controls(base,book,future,core,outside)
    else:
        need(q["sequential_read_RAM_difference"] == 0 and q["charged_control_evidence"] >= 32*M,
             "170 readback turnover cannot fund an independent verifier")
        room = dict(remaining_home=base["home_margin"]-outside,
                    remaining_ram=base["ram_margin"]-128*M, following_control_charge=q["charged_control_evidence"])
    room["remaining_ram"] -= capacity["additional_audit_ram"]
    return dict(fits=capacity["fits"] and room["remaining_home"] >= 0 and room["remaining_ram"] >= 0,
                capacity=capacity, provider=str(directory), phase=phase, base=base, room=room,
                retained_packages=PACKAGE_BYTES, miscellaneous_disk=128*M, controller_ram=128*M,
                canonical_writes=False)
