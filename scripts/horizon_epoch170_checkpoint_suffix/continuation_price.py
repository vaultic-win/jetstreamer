"""Rebind the sequential bounded slot after its exact native predecessor closes."""
import importlib.util
import json
import os
from pathlib import Path
import time

spec = importlib.util.spec_from_file_location("prior_funding", Path(__file__).with_name("successor_price.py"))
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
RT, TREE, B140 = prior.RT, prior.TREE, prior.B140
state, read, bound, inactive, need, cmd = prior.state, prior.read, prior.bound, prior.inactive, prior.need, prior.cmd
FIRST = RT / "epoch170-from-73746882-20261127-v1"
OPERATOR = Path(__file__).resolve().parent
ISSUED_PRICE = FIRST/"attempt-2/issued-price-v47"
FOCUSED169_PRICE = RT/"epoch169-hourly-admission-20261123-v1/issued-split-v1"
ISSUED_PRICES = (ISSUED_PRICE, FOCUSED169_PRICE)
RETRY = OPERATOR in ISSUED_PRICES or OPERATOR.parent == FIRST/"attempt-2" and OPERATOR.name in ("operator-v1", "operator-v2", "operator-v3")
DEP = ATTEMPT = FIRST/"attempt-2" if RETRY else FIRST
OLD = prior.DEP / "attempt-2"
BRIDGE = prior.UNIT
ORIG = "04b0750aead84a83914d18edea9c8736"
UNIT = "horizon-qualify-170-from-73746882-20261127-v1.service"
ALIAS = "/run/horizon-170-from-73746882-v1"
G, M = 1 << 30, 1 << 20
READ_UNIT = "horizon-170-73746882-closed-read-20261127-v1.service"
CHECKER = "bounded-checkpoints"
PREVIOUS_SLOTS = [73726716, 73746882]
NEXT_DIRECTORY = RT / "epoch170-from-73766969-20261127-v1"
RECONCILED = OPERATOR in (NEXT_DIRECTORY / "operator-v3", NEXT_DIRECTORY / "closed-reader-v2")
FOLLOWING = RECONCILED or OPERATOR in (NEXT_DIRECTORY / "operator-v1", NEXT_DIRECTORY / "operator-v2", NEXT_DIRECTORY / "closed-reader-v1")
if FOLLOWING:
    BRIDGE = UNIT
    ORIG = "c3ab30cfeb05428bb8f5c48a5a44822c"
    DEP = ATTEMPT = FIRST = NEXT_DIRECTORY
    UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
    ALIAS = "/run/horizon-170-from-73766969-v1"
    READ_UNIT = "horizon-170-73766969-closed-read-20261127-v1.service"
    CHECKER = "following-checkpoints"
    PREVIOUS_SLOTS = [73746882, 73753554, 73760367, 73766969]


def following_scope():
    bindings, _ = read(OPERATOR / "binding.json")
    interface, ref = read(DEP / "BOUNDED_SUCCESSOR_WRITER_INTERFACE.json")
    package = DEP / "package"
    source, packet_ref = read(package / "source-packet.json", "fd2a07ec1a136a57b7613168ff4e22931e575c6fc97a68d3c1c21921335c0e8a")
    prior_dir = RT / "epoch170-from-73746882-20261127-v1/attempt-2"
    release, release_ref = read(prior_dir / "SUCCESSOR_RELEASE.json", "a943145ddc01d4eaff76041eaf131818228e2cb484c32bc7753e84a8dc64bdef")
    actor, actor_ref = read(prior_dir / "SUCCESSOR_ACTOR.json", "1812cb4ab3972c09ec5f97d6c3a45e2f5e92b25254edff4e683ef7a6305534b0")
    handoff = bound(interface["handoff"])
    profile = interface["profile"]
    native = bound(interface["source_preflight"])
    need(bindings["interface"] == ref and bindings["source_packet"] == packet_ref
         and bindings["predecessor_capture"] == read(DEP / "PREDECESSOR_CAPTURE_ACTIVE.json", "1f84466d9ec0697cd1b2e4c367f557ec63370935af882ef5d4d5379fd5082920")[1]
         and release["actor"] == interface["old_actor"] == actor_ref and interface["old_release"] == release_ref
         and actor["unit"] == BRIDGE and actor["producer_invocation_id"] == ORIG
         and handoff["source_packet"] == packet_ref and handoff["original_release"] == release_ref
         and interface["handoff"] == interface["closed_terminal_handoff"]
         and interface["closed_comparison"] == str(DEP / "CLOSED_PREDECESSOR_COMPARISON.json")
         and interface["barrier"] == str(DEP / "barrier/allow")
         and interface["expected_producer_unit"] == profile["host_unit"] == UNIT
         and profile["bootstrap"] == interface["bootstrap"] == source["bootstrap_slot"] == 73766969
         and source["range"] == native["scope"] == [interface["first_new_slot"],interface["last"]] == [73766970,73787145]
         and profile["positions"] == 20176 and profile["first"] == 73766970 and profile["last"] == 73787145
         and native["route_accepted"] and not native["worker_executed"]
         and not interface["admission_or_release"], "unconfirmed fourth hourly route")
    return interface, ref


def scope():
    if FOLLOWING:
        return following_scope()
    original_sha = "6e7eed43d0593e9ffe6d5df59cb27f92da518af40c96fb7d09fadb63a5990255"
    expected = "f5da8a618bfb147d98d2db1ec91526d9b711df014189c4e6485503f003e63dcd" if RETRY else original_sha
    interface, ref = read(DEP/"BOUNDED_SUCCESSOR_WRITER_INTERFACE.json", expected)
    if RETRY:
        original, parent_ref = read(FIRST/"BOUNDED_SUCCESSOR_WRITER_INTERFACE.json", original_sha)
        failed = bound(interface["unreleased_failed_attempt"])
        need(parent_ref == interface["previous_interface"] and failed["no_permit"] and failed["no_worker_or_archive"]
             and failed["guard_samples"] == 0 and bound(failed["actor"])["producer_invocation_id"] == failed["terminal"]["InvocationID"]
             and interface["closed_comparison"] == original["closed_comparison"] and interface["profile"] == original["profile"]
             and interface["run"] == original["run"] and interface["log"] == str(Path(original["run"])/"producer-attempt2.log")
             and interface["barrier"] == original["barrier"] and interface["guard_receipts"] == original["guard_receipts"],
             "unconfirmed unreleased predecessor or changed retry layout")
    native = bound(interface["source_preflight"])
    need(native["route_accepted"] and not native["worker_executed"] and native["scope"] == [73746883,73766969]
         and interface["profile"]["positions"] == 20087 and interface["expected_producer_unit"] == UNIT,
         "different bounded route")
    return interface, ref


def close_interface():
    if not FOLLOWING:
        return scope()[0]
    previous = RT / "epoch170-from-73746882-20261127-v1/attempt-2"
    _, actor = read(previous / "SUCCESSOR_ACTOR.json", "1812cb4ab3972c09ec5f97d6c3a45e2f5e92b25254edff4e683ef7a6305534b0")
    _, release = read(previous / "SUCCESSOR_RELEASE.json", "a943145ddc01d4eaff76041eaf131818228e2cb484c32bc7753e84a8dc64bdef")
    return {"old_actor":actor, "old_release":release, "closed_comparison":str(DEP / "CLOSED_PREDECESSOR_COMPARISON.json")}


def predecessor_exit():
    interface = close_interface()
    release = bound(interface["old_release"])
    actor = bound(interface["old_actor"])
    terminal, ref = read(FIRST/"predecessor-exit/PID1_EXIT.json")
    prop = terminal["properties"]
    need(release["actor"] == interface["old_actor"] and terminal["actor"] == actor
         and terminal["release"] == interface["old_release"] and prop["Id"] == BRIDGE
         and prop["InvocationID"] == actor["producer_invocation_id"] == ORIG
         and prop["ExecMainPID"] == str(actor["producer_pid"])
         and prop["Result"] == "success" and prop["ExecMainCode"] == "1"
         and prop["ExecMainStatus"] == prop["MainPID"] == prop["ControlPID"] == "0",
         "predecessor did not exit cleanly")
    inactive(BRIDGE)
    return ref


def compare_predecessor():
    interface = close_interface()
    predecessor_exit()
    doc, ref = read(interface["closed_comparison"])
    e = doc["evidence"]
    need(doc["actor"] == interface["old_actor"] and doc["release"] == interface["old_release"]
         and e["comparison"] == "closed" and e["pid1_exit"]["native"]["InvocationID"] == ORIG
         and e["pid1_exit"]["native"]["Result"] == "success"
         and [p["slot"] for p in doc["checkpoints"]] == PREVIOUS_SLOTS
         and len(e["closed_segment"]["sha256"]) == 64 and not doc["canonical_publication_authorized"],
         "different closed archive")
    return ref


def anonymous(unit, invocation, roster, cap):
    row = state(unit)
    need(row["InvocationID"] == invocation and row["ActiveState"] == "active"
         and row["ControlGroup"] == "/system.slice/"+unit and int(row["MemoryMax"]) == cap
         and row["MemorySwapMax"] == "0" and not row["Job"], "memory owner changed")
    cg = Path("/sys/fs/cgroup"+row["ControlGroup"])
    expected = {p[0] for p in roster}
    def members(): return set(map(int, (cg/"cgroup.procs").read_text().split()))
    need(members() == expected and int(row["MainPID"]) in expected, "anonymous memory owner roster changed")
    total = 0
    for pid, ticks in roster:
        proc = Path("/proc")/str(pid)
        def tick(): return int((proc/"stat").read_text().rsplit(") ",1)[1].split()[19])
        need(tick() == ticks and (proc/"cgroup").read_text().strip() == "0::"+row["ControlGroup"], "replaced memory owner")
        total += next(int(s.split()[1])*1024 for s in (proc/"smaps_rollup").read_text().splitlines()
                      if s.startswith("Pss_Anon:"))
        need(tick() == ticks, "changed memory owner during measurement")
    stats = dict(line.split() for line in (cg/"memory.stat").read_text().splitlines())
    need(members() == expected and state(unit) == row, "memory owner changed during quote")
    return min(total, int(stats["anon"]), cap)


def hourly_owner():
    base = RT/"epoch141-first-hourly-20261127-v1"
    actor, ref = read(base/"HELD_OWNER.json", "f746b5dbe75d5c33749f7fc66f199431a726494e5a82934bfadc76b27ef6d3ac")
    progress, _ = read(base/"FIRST_PROTECTED_PROGRESS.json")
    need(progress["held_owner"] == ref and progress["producer_invocation_id"] == actor["producer_invocation_id"],
         "different first hourly owner")
    if state(actor["unit"])["ActiveState"] != "active":
        inactive(actor["unit"])
        guard_unit = actor["unit"].replace("-qualify-","-guard-")
        inactive(guard_unit)
        clock = state(guard_unit.replace(".service",".timer"),"Id,ActiveState,Job")
        need(clock["ActiveState"] == "inactive" and not clock["Job"], "hourly guard still booked")
        # A stopped producer may still have a retained tree and a successor obligation.
        # Keep its entire 44 GiB/30 GiB future allocation with zero residency credit.
        exits = [json.loads(line) for line in cmd("/usr/bin/journalctl","-q","--no-pager","-o","json",
                  "_PID=1","_UID=0","UNIT="+actor["unit"],"INVOCATION_ID="+actor["producer_invocation_id"],
                  "_BOOT_ID="+actor["boot_id"].replace("-","")).splitlines()]
        need(any(r.get("MESSAGE_ID") == "7ad2d189f7e94e70a38c781354912448" for r in exits)
             and not any(r.get("MESSAGE_ID") == "98e322203f7a4ed290d09fe03c09fe15" for r in exits),
             "unconfirmed hourly terminal")
        return None, 0, 44*G, 0
    roster = [(actor["producer_pid"],actor["start_ticks"]),(progress["worker_pid"],progress["worker_start_ticks"])]
    procs = []
    for pid,ticks in roster:
        exe = (Path("/proc")/str(pid)/"exe").stat()
        procs.append([pid,ticks,exe.st_dev,exe.st_ino])
    sample, lower, _ = prior.protected(actor["unit"],procs,actor["guard_timer_invocation_id"],
                                       progress["guard_after"]["receipt"],30*G,"2s",False)
    plan = bound(actor["guard_plan"])
    need(plan["invocation_id"] == actor["producer_invocation_id"] and plan["maximum_root_physical_bytes"] == 44*G
         and bound(sample)["plan_sha256"] == actor["guard_plan"]["sha256"], "different hourly reservation")
    ram = anonymous(actor["unit"], actor["producer_invocation_id"], roster, 30*G)
    return sample, plan["minimum_free_bytes"], max(0,44*G-lower), ram


def guarded_hourly143(rollover, current):
    closed = rollover.first_closed(prior)
    permit = rollover.ROOT/"barrier/allow"
    mode = "released" if os.path.lexists(permit) else "gate"
    guarded = rollover.guard(prior, rollover.ROOT, rollover.UNIT, rollover.ROOT/"guard-receipts",
                             current["InvocationID"], mode)
    if mode == "gate":
        # A retried gate has a new immutable writer booking. Select it by
        # kernel start time, so an earlier failed attempt cannot back it.
        pid, ticks = guarded["roster"][0]
        boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines()
                    if line.startswith("btime "))
        started = boot + ticks / os.sysconf("SC_CLK_TCK")
        bookings = []
        for path in rollover.ROOT.glob("WRITER_BOOKING_FIRST_HOURLY*.json"):
            booking, ref = read(path)
            if booking["recorded_unix_seconds"] - 1 <= started <= booking["latest_start_unix_seconds"] + 1:
                bookings.append((booking, ref))
        need(len(bookings) == 1, "unreleased 143 has no unique writer booking at its kernel start")
        booking, ref = bookings[0]
        need(guarded["roster"] == [(int(current["MainPID"]),ticks)] and booking["unit"] == rollover.UNIT
             and booking["schema"] == "horizon-epoch143-first-hourly-booking-v1"
             and booking["closed_141"] == closed and booking["contract"] == read(rollover.ROOT/"contract-v1/LAUNCH_PROFILE.json",rollover.SHA)[1]
             and booking["HOME_bytes"] == 64*G+64*M and booking["RAM_bytes"] == 41*G
             and booking["cpu_quota_micros"] == 3000000 and not booking["archive_publication_authorized"],
             "unfunded hourly gate")
        guarded["booking"] = ref
    guarded["mode"] = mode
    return guarded


def issued_tree_bounds(actor):
    """Use the live guard's paired scans of this exact tree and worker."""
    progress, _ = read(DEP/"FIRST_PROTECTED_PROGRESS.json", "51aaa67e0eeb7bd1da0ed85e718ade911a6ae425e21be20383cb0f715c834d02")
    release = bound(progress["release"])
    plan = bound(release["guard_plan"])
    scope = bound(release["interface"])
    worker = progress["worker"]
    need(progress["producer_invocation_id"] == actor["producer_invocation_id"] == release["producer_invocation_id"]
         == "c3ab30cfeb05428bb8f5c48a5a44822c" and actor == bound(release["actor"])
         and release["actor"] == progress["actor"] and scope["expected_producer_unit"] == plan["unit"] == UNIT
         and plan["invocation_id"] == actor["producer_invocation_id"] and plan["worker_root"] == str(TREE)
         and plan["filesystem"] == "/home/sol" and scope["profile"]["worker"] == worker["sha256"],
         "different issued 170 price or guard")
    roster = []
    for pid, ticks, expected_exe in ((actor["producer_pid"], actor["start_ticks"], scope["profile"]["node"]["path"]),
                                     (worker["pid"], worker["start_ticks"], worker["exe"])):
        exe = Path("/proc")/str(pid)/"exe"
        need(exe.samefile(expected_exe), "different issued 170 executable")
        st = exe.stat()
        roster.append([pid, ticks, st.st_dev, st.st_ino])
    sample, lower, _ = prior.protected(UNIT, roster, release["guard_timer_invocation_id"], progress["native_guard"], 48*G, "6s", False)
    census = bound(sample)
    upper = prior.peak(census)
    need(census["plan_sha256"] == release["guard_plan"]["sha256"]
         and census["minimum_free_bytes"] == plan["minimum_free_bytes"]
         and 0 < lower <= upper <= plan["maximum_root_physical_bytes"] == census["root_physical_observation"]["maximum_physical_bytes"],
         "unprotected or out-of-bounds 170 tree")
    return sample, (lower, upper)


def price(phase, *, native169=None):
    need(phase in ("read","start","held"),"unknown continuation phase")
    need(native169 is None or OPERATOR == FOCUSED169_PRICE, "169 is outside this operator")
    need(OPERATOR not in ISSUED_PRICES or phase == "held", "issued-price-v47 only prices the live 170 worker")
    prior_receipt = predecessor_exit()
    if phase != "read": compare_predecessor()
    before = prior.availability()
    held = phase == "held"
    if held:
        actor, _ = read(DEP/"SUCCESSOR_ACTOR.json")
        s = state(UNIT)
        need(actor["producer_invocation_id"] == s["InvocationID"] and s["ActiveState"] == "active"
             and actor["producer_pid"] == int(s["MainPID"]) and s["MemoryMax"] == str(48*G)
             and s["CPUQuotaPerSecUSec"] == "6s","different held successor")
    else: inactive(UNIT)
    shared = Path(__file__).with_name("rollover143.py")
    rollover = None
    replacement = None
    if shared.exists():
        shared_spec = importlib.util.spec_from_file_location("rollover143", shared)
        rollover = importlib.util.module_from_spec(shared_spec)
        shared_spec.loader.exec_module(rollover)
        rs = state(rollover.UNIT)
        if rs["ActiveState"] == "active":
            replacement = guarded_hourly143(rollover, rs)
    sample, bounds = issued_tree_bounds(actor) if OPERATOR in ISSUED_PRICES else (None, None)
    options = {"native169": native169} if native169 is not None else {}
    joint = prior.price("held" if held else "start",attempt=OLD,held_replacement=UNIT if held else None,live_tree_bounds=bounds,
                        hourly_replacement=replacement["iid"] if replacement else None, **options)
    need(joint["candidate_growth"] == 36*G and joint["producer_allowance"] == 48*G
         and joint["guard_sibling_allowance"] == G and joint["resource_credit_bytes"] == 0
         and joint["extra"]["reserved_141"]["sha256"] == "73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131",
         "changed sequential producer or hourly allowance")
    hourly_ram_delta = 0
    if replacement:
        hourly = replacement["sample"]
        hourly_floor = replacement["floor"]
        hourly_growth = max(0,64*G-replacement["low"])
        hourly_resident = anonymous(replacement["unit"],replacement["iid"],replacement["roster"],40*G)
        hourly_ram_delta = 10*G
    elif rollover and rollover.ACCEPT.exists():
        rollover.first_closed(prior)
        hourly, hourly_floor, hourly_growth, hourly_resident = None, 0, 64*G, 0
        hourly_ram_delta = 10*G
    else:
        hourly, hourly_floor, hourly_growth, hourly_resident = hourly_owner()
    tail = bound(joint["charged_167"])
    intent = bound(tail["actor"]["intent"])
    need(intent["quote"]["producer_memory_bytes"] == 42*G
         and intent["quote"]["exact_native_fit"]["reserved_new_selector_RAM_bytes"] == 4*G,
         "changed 167 producer or selector reservation")
    tail_resident = anonymous(tail["actor"]["unit"], tail["actor"]["producer_invocation_id"],
                              [p[:2] for p in tail["processes"]], 42*G)
    low, high = joint["terminal_tree_bounds"]
    old_plan = bound(bound(close_interface()["old_release"])["guard_plan"])
    need(0 < low <= high <= old_plan["maximum_root_physical_bytes"] <= 384*G,
         "original subtree exceeds admitted cap")
    if hourly is not None: need(bound(hourly)["producer_stop_enabled"],"unprotected hourly producer")
    highest = max(hourly_floor, *(bound(r)["minimum_free_bytes"] for r in joint["guard_samples"].values()))
    # During readback the predecessor's full remaining tree still belongs to 170.
    # A successor gets its new 36 GiB only after native close and whole-file readback.
    growth = old_plan["maximum_root_physical_bytes"] - low if phase=="read" else 36*G
    floor = max(joint["required_home"] - 36*G - (44*G+64*M), highest) + hourly_growth + 64*M
    # The retired compiler leaves one serial 0.5-core/512-MiB control slot.
    # It can overlap the old-slot reader or the new producer only when freshly paid.
    floor += 128*M
    aux = rollover.auxiliary(prior,joint["fleet"]) if rollover else None
    aux_home = aux["evidence_home"] if aux else 0
    aux_ram = aux["fourth_ram"]+aux["parallel_controls_ram"]+aux["watcher_ram"] if aux else 0
    floor += aux_home
    required = floor+growth
    ram_required = joint["required_ram"] - hourly_resident - tail_resident + 512*M + hourly_ram_delta + aux_ram
    after = prior.availability()
    home, ram = min(before[0],after[0]), min(before[1],after[1],joint["available_ram"])
    historical_home = joint["historical_home_limit"] + aux["incremental_185_m_after_fleet"] if aux else joint["available_home"]
    historical = historical_home - (joint["required_home"] - 36*G + growth + 128*M)
    historical -= aux_home + (20*G if hourly_ram_delta else 0)
    margin = min(historical,home-required)
    fits = margin >= 0 and ram >= ram_required and (phase=="read" or high+growth <= 384*G)
    result = dict(phase=phase,priced_170_invocation=s["InvocationID"] if held else None,fleet=joint["fleet"],joint=joint,observed=int(time.time()),fits=fits,
                old_terminal=prior_receipt,hourly_guard=hourly,hourly_ram_resident=hourly_resident,
                tail_ram_resident=tail_resident,terminal_tree_bounds=[low,high],guard_floor=floor,
                guard_cap=min(384*G,high+growth),available_home=home,available_ram=ram,required_home=required,
                required_ram=ram_required,home_margin=margin,ram_margin=ram-ram_required,
                historical_home_margin=historical,guarded_hourly_remaining=hourly_growth,
                guarded_remaining_141=0 if hourly_ram_delta else hourly_growth,
                replacement143=replacement,auxiliary=aux,
                dispatch_cpu_micros=500000,dispatch_memory_bytes=512*M,dispatch_home_bytes=128*M,
                resource_credit_bytes=0,archive_publication_authorized=False)
    if sample:
        result["issued_tree_guard_sample"] = sample

    # Historical standalone read deployments predate the assembly reservation.
    overlay_path = Path(__file__).with_name("assembly_reservation.py")
    if not FOLLOWING and (phase == "read" or (not RETRY and not overlay_path.exists())):
        return result
    overlay_spec = importlib.util.spec_from_file_location("assembly_reservation", overlay_path)
    overlay = importlib.util.module_from_spec(overlay_spec)
    overlay_spec.loader.exec_module(overlay)
    assembly = overlay.reservation()
    if FOLLOWING:
        module = Path(__file__).with_name("following_capacity.py")
        spec = importlib.util.spec_from_file_location("following_capacity", module)
        capacity = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(capacity)
        scope_for_price = None if phase == "read" else scope()[0]
        quote = capacity.charge(prior, result, assembly, scope_for_price)
        if RECONCILED:
            spec = importlib.util.spec_from_file_location("verification_reservation", OPERATOR / "verification_reservation.py")
            verification = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(verification)
            return verification.apply(prior, quote)
        return quote
    if OPERATOR in (FIRST/"attempt-2/operator-v3", *ISSUED_PRICES):
        return overlay.apply_170(result, assembly, use_phase=True)
    return overlay.apply_170(result, assembly)
