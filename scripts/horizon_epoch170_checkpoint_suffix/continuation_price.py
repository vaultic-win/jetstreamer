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
DEP = ATTEMPT = RT / "epoch170-from-73746882-20261127-v1"
OLD = prior.DEP / "attempt-2"
BRIDGE = prior.UNIT
ORIG = "04b0750aead84a83914d18edea9c8736"
UNIT = "horizon-qualify-170-from-73746882-20261127-v1.service"
ALIAS = "/run/horizon-170-from-73746882-v1"
G, M = 1 << 30, 1 << 20
READ_UNIT = "horizon-170-73746882-closed-read-20261127-v1.service"


def scope():
    interface, ref = read(DEP/"BOUNDED_SUCCESSOR_WRITER_INTERFACE.json",
                          "6e7eed43d0593e9ffe6d5df59cb27f92da518af40c96fb7d09fadb63a5990255")
    native = bound(interface["source_preflight"])
    need(native["route_accepted"] and not native["worker_executed"] and native["scope"] == [73746883,73766969]
         and interface["profile"]["positions"] == 20087 and interface["expected_producer_unit"] == UNIT,
         "different bounded route")
    return interface, ref


def predecessor_exit():
    interface, _ = scope()
    release = bound(interface["old_release"])
    actor = bound(interface["old_actor"])
    terminal, ref = read(DEP/"predecessor-exit/PID1_EXIT.json")
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
    interface, _ = scope()
    predecessor_exit()
    doc, ref = read(interface["closed_comparison"])
    e = doc["evidence"]
    need(doc["actor"] == interface["old_actor"] and doc["release"] == interface["old_release"]
         and e["comparison"] == "closed" and e["pid1_exit"]["native"]["InvocationID"] == ORIG
         and e["pid1_exit"]["native"]["Result"] == "success"
         and [p["slot"] for p in doc["checkpoints"]] == [73726716,73746882]
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


def price(phase):
    need(phase in ("read","start","held"),"unknown continuation phase")
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
    joint = prior.price("held" if held else "start",attempt=OLD,held_replacement=UNIT if held else None)
    need(joint["candidate_growth"] == 36*G and joint["producer_allowance"] == 48*G
         and joint["guard_sibling_allowance"] == G and joint["resource_credit_bytes"] == 0
         and joint["extra"]["reserved_141"]["sha256"] == "73a120db97d72a03c05c39139098a10cd6c84802f0f5472a1251f341976ce131",
         "changed sequential producer or hourly allowance")
    hourly, hourly_floor, hourly_growth, hourly_resident = hourly_owner()
    tail = bound(joint["charged_167"])
    intent = bound(tail["actor"]["intent"])
    need(intent["quote"]["producer_memory_bytes"] == 42*G
         and intent["quote"]["exact_native_fit"]["reserved_new_selector_RAM_bytes"] == 4*G,
         "changed 167 producer or selector reservation")
    tail_resident = anonymous(tail["actor"]["unit"], tail["actor"]["producer_invocation_id"],
                              [p[:2] for p in tail["processes"]], 42*G)
    low, high = joint["terminal_tree_bounds"]
    old_plan = bound(bound(scope()[0]["old_release"])["guard_plan"])
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
    required = floor+growth
    ram_required = joint["required_ram"] - hourly_resident - tail_resident + 512*M
    after = prior.availability()
    home, ram = min(before[0],after[0]), min(before[1],after[1],joint["available_ram"])
    historical = joint["available_home"] - (joint["required_home"] - 36*G + growth + 128*M)
    margin = min(historical,home-required)
    fits = margin >= 0 and ram >= ram_required and (phase=="read" or high+growth <= 384*G)
    return dict(phase=phase,fleet=joint["fleet"],joint=joint,observed=int(time.time()),fits=fits,
                old_terminal=prior_receipt,hourly_guard=hourly,hourly_ram_resident=hourly_resident,
                tail_ram_resident=tail_resident,terminal_tree_bounds=[low,high],guard_floor=floor,
                guard_cap=min(384*G,high+growth),available_home=home,available_ram=ram,required_home=required,
                required_ram=ram_required,home_margin=margin,ram_margin=ram-ram_required,
                historical_home_margin=historical,guarded_remaining_141=hourly_growth,
                dispatch_cpu_micros=500000,dispatch_memory_bytes=512*M,dispatch_home_bytes=128*M,
                resource_credit_bytes=0,archive_publication_authorized=False)
