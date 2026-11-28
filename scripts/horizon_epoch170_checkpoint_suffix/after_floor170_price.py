"""Price the shorter RAM-backed 170 recovery without spending any other epoch's runway."""
from hashlib import sha256
import importlib
import os
from pathlib import Path
import runpy
import stat
import sys

G = 1<<30
M = 1<<20
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-ram-20261128-v1")
UNIT = "horizon-qualify-170-from-73766969-ram-20261128-v1.service"
SCOPE_DIGEST = None
RECEIVER_DIGEST = None
SCOPE = dict(path=str(ROOT/"AFTER_FLOOR_WRITER_INTERFACE.json"), sha256=SCOPE_DIGEST)
RECEIVER = ROOT/"observer-modules-v1"
DRAWDOWN = dict(path=str(ROOT.parent/"epoch166-closed-compact-indexes-20261128-v1/SHARED_HOME_DRAWDOWN_0400_053730.json"),
                sha256="cb92e5a9b96960d0e2a98a7f2d9ce75d5ad221b84c4549955eea4ce05a0b87ab")
HOME, CONTROL, RAM = 8*G, 64*M, 56*G


def need(check, reason):
    if not check:
        raise ValueError(reason)


def receiver(core, directory):
    previous = runpy.run_path(str(directory/"after_ram170_admission.py"))["receiver"](core,directory)
    seal, _ = core.read(RECEIVER/"deployment-seal-receipt.json",RECEIVER_DIGEST)
    images = {entry["name"]:entry["sha256"] for entry in seal["members"]}
    need(seal["destination"] == str(RECEIVER) and set(images) == {
        "after_floor170_"+n+".py" for n in ("contract","native","status","workspace")}, "different hourly receiver")
    for name, digest in images.items():
        path = RECEIVER/name
        st = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == 0
             and not st.st_mode & 0o222 and sha256(path.read_bytes()).hexdigest() == digest, "unsealed receiver " + name)
    sys.path.insert(0,str(RECEIVER))
    try:
        module = importlib.import_module("after_floor170_status")
    finally:
        del sys.path[0]
    need(all(Path(sys.modules[Path(p).stem].__file__) == RECEIVER/p for p in images)
         and module.contract.previous is previous.contract and module.INTERFACE == SCOPE and module.UNIT == UNIT,
         "foreign input, module or ancestor")
    return module


def owner(core, fleet, directory):
    scope = core.bound(SCOPE)
    if not os.path.lexists(scope["actor_path"]):
        core.inactive(UNIT)
        need(not any(os.path.lexists(scope[k]) for k in ("release_path","barrier","plan_path","enrollment_path")),
             "hourly 170 authority exists without its actor")
        return None
    callback = receiver(core,directory)
    callback.contract.stopped_owner(fleet)
    comparison = callback.contract.checkpoint(callback.contract.interface())
    node = callback.gap
    ref, actor = node.read_actor()
    manager = node.native.props(UNIT,node.PROPS)
    release, grant = node.release(scope,ref,actor,comparison)
    plan_file = Path(scope["plan_path"])
    plan, pr = core.read(plan_file) if plan_file.exists() else (None,None)
    basic = dict(unit=UNIT,invocation=actor["producer_invocation_id"],pid=actor["producer_pid"],actor=ref,interface=SCOPE,
                 release=release,guard_plan=pr,closed_comparison=comparison,floor=plan["minimum_free_bytes"] if plan else None)
    if manager["ActiveState"] in ("inactive","failed"):
        event = node.terminal(actor)
        need(not node.CGROUP.exists(), "hourly replay cgroup still draining")
        return dict(**basic,phase="terminal",native_terminal=event)
    processes, worker, phase = node.live(scope,manager,actor,grant is not None)
    guard = None
    if grant:
        guard, seen = node.guard(scope,actor,worker,grant)
        need(guard["plan"] == pr and not (Path(scope["guard_receipts"])/"stop-intent.json").exists(),"hourly guard is stopping")
        if seen:
            phase = "worker"
    need(node.native.props(UNIT,node.PROPS) == manager and [node.process(p[0]) for p in processes] == processes,
         "hourly 170 changed during native census")
    return dict(**basic,phase=phase,processes=processes,tree_guard=guard)


def guarded_bounds(owner, tree, bound, state, cmd, directory):
    import time
    support = runpy.run_path(str(directory/"after_ram170_tree.py"))
    scope, grant, actor = (bound(owner[key]) for key in ("interface","release","actor"))
    plan = bound(owner["guard_plan"])
    guard = owner["tree_guard"]
    sample = bound(guard["sample"])
    run = Path(scope["run"])
    need(owner["unit"] == UNIT and owner["interface"] == SCOPE and actor["interface"] == SCOPE
         and grant["actor"] == owner["actor"] and grant["closed_comparison"] == scope["retained_comparison"]
         and owner["phase"] in ("bootstrap","worker") and grant["guard_plan"] == guard["plan"] == owner["guard_plan"]
         and owner["invocation"] == actor["producer_invocation_id"] == grant["producer_invocation_id"] == plan["invocation_id"]
         and sample["producer_invocation_id"] == owner["invocation"] and sample["producer"]["pid"] == owner["pid"]
         and grant["guard_timer_invocation_id"] == guard["timer_invocation_id"] and sample["guard_sha256"] == scope["guard_sha"]
         and sample["plan_sha256"] == owner["guard_plan"]["sha256"] and plan["unit"] == UNIT and plan["worker_root"] == str(tree)
         and Path(guard["sample"]["path"]) == Path(scope["guard_receipts"])/("sample-"+sample["guard_invocation_id"]+".json")
         and not os.path.lexists(Path(scope["guard_receipts"])/"stop-intent.json"), "different live hourly guard")
    mounts = state(UNIT,"Id,ProtectHome,ReadWritePaths")
    need(mounts["ProtectHome"] == "read-only" and mounts["ReadWritePaths"] == str(run), "unknown writable HOME scope")
    closed = support["closed_bytes"](cmd,tree,run)
    scans = support["native_scans"](sample,plan,time.time())
    need(min(closed) <= min(scans), "closed siblings exceed the native guard tree scan")
    return dict(actor=owner["actor"],release=owner["release"],interface=SCOPE,plan=owner["guard_plan"],guard=guard,
                tree=str(tree),excluded_writable_run=str(run),closed_du_bytes=closed,guarded_physical_bytes=scans,
                bounds=[min(closed),max(scans)],minimum_free_bytes=plan["minimum_free_bytes"],active_run_occupancy_credit_bytes=0)


def stable(owner):
    # Receipt sample names may advance while all actor, timer and plan identities stay the same.
    if not owner or not owner.get("tree_guard"):
        return owner
    guard = {k:v for k,v in owner["tree_guard"].items() if k != "sample"}
    return dict(owner,tree_guard=guard)


def booking(core, scope):
    path = ROOT/"SUCCESSOR_START_INTENT.json"
    if not os.path.lexists(path):
        return None
    intent, ref = core.read(path)
    price = core.bound(intent["price"])
    need(intent["interface"] == SCOPE and intent["producer_unit"] == UNIT and intent["guard_unit"] == scope["expected_guard_unit"]
         and intent["closed_comparison"] == scope["retained_comparison"] and price["scope"] == SCOPE
         and price["closed_comparison"] == intent["closed_comparison"] and price["phase"] == "start" and price["fits"]
         and price["candidate_170_growth_bytes"] == HOME and price["producer_memory_max"] == RAM
         and price["guard_memory_max"] == G and price["drawdown_evidence"] == DRAWDOWN
         and not intent["resource_credit_bytes"] and not intent["archive_publication_authorized"], "unfunded hourly 170 intent")
    return ref


def select(core, whole, directory, projection):
    need("after_floor170_accounting" not in whole and "after_ram170_accounting" not in whole
         and not whole["resource_credit_bytes"], "170 has already been accounted")
    scope = core.bound(SCOPE)
    native = whole["base_169"]["native"]
    past, active = native["after_ram170"], native["after_floor170"]
    intent = booking(core,scope)
    need(past and past["phase"] == "terminal" and past["invocation"] == "e589078414194de38fe902a9df0f5b0c"
         and past["actor"] == core.bound(scope["stopped_custody"])["actor"] and not native["ram_gap170"]
         and (not active or intent) and (not projection or not whole["preparation_only"]),
         "different disk predecessor or hourly ownership")
    cost = native["ram_retry_cost"]
    need(cost["original_home_growth"] == 36*G and cost["home_growth"] == HOME and cost["producer_memory_max"] == RAM
         and cost["extra_ram"] == 8*G and cost["scratch_tmpfs"] == 40*G and cost["original_guard_still_budgeted"]
         and cost["resident_ram_credit"] == native["ram170_residency"]["realized_bytes"] == 0
         and native["raw"]["joint"]["guard_sibling_allowance"] == G, "different base RAM booking")
    applied = bool(intent) or projection
    whole["after_floor170_accounting"] = dict(scope=SCOPE,actor=active,intent=intent,replacement_selected=applied,
        prospective=bool(projection and not intent),home_growth=HOME,producer_memory=RAM,guard_memory=G,
        previous_home_growth=36*G,previous_producer_memory=48*G,resident_credit=0,additional_inputs=0)
    return applied


def geometry(whole, drawdown):
    need(drawdown == 20_011_974_656 and not whole["resource_credit_bytes"], "different measured peer drawdown")
    raw = whole["base_169"]["native"]["raw"]
    remaining = whole["epoch143_remaining_replay_home"]
    installed143 = whole.get("epoch143_installed_guard_floor") or 0
    peer_floor = whole["epoch143_protected_sibling_floor"]
    low, high = raw["terminal_tree_bounds"]
    need(0 < low <= high and 0 <= remaining <= 64*G and raw["guarded_hourly_remaining"] == remaining
         and whole["epoch143_protected_runway_required_home"] == max(whole["required_home"],peer_floor+remaining),
         "unreconciled 143 runway or 170 whole-tree bounds")
    # The shared required_home and its arithmetic guard_floor already include 143's
    # full remaining growth. Preserve them in the joint test. The independent
    # minimum_free_bytes for this new guard must leave that paid growth usable.
    floor = max(raw["guard_floor"], whole["guard_floor"]-remaining, whole["required_home"]-remaining-HOME,
                peer_floor-HOME, installed143, *whole["observed_sibling_guard_floors"])
    required = max(whole["required_home"], whole["epoch143_protected_runway_required_home"],
                   floor+HOME+remaining, installed143+HOME)
    cap = min(low+HOME-CONTROL,384*G)
    margin = min(whole["home_margin"],whole["available_home"]-required) - drawdown
    return dict(guard_floor=floor,guard_cap=cap,terminal_tree_bounds=[low,high],candidate_170_growth_bytes=HOME,
                required_home=required,available_home=whole["available_home"],home_margin=margin,ram_margin=whole["ram_margin"],
                required_ram=whole["required_ram"],guard_memory_max=G,producer_memory_max=RAM,
                shared_drawdown_allowance=drawdown,drawdown_evidence=DRAWDOWN,protected_143_remaining=remaining,
                installed_143_floor=installed143,shared_required_home=whole["required_home"],joint=raw["joint"],
                assembly168=raw["assembly168"],fits=(whole["fits"] and margin>=0 and high<=cap and cap-low == HOME-CONTROL))


def candidate(core, whole, phase):
    need(phase in ("start","held") and not whole["preparation_only"], "invalid hourly price phase")
    registered = whole["after_floor170_accounting"]
    legacy = whole["after_ram170_accounting"]
    scope = core.bound(SCOPE)
    need(registered["scope"] == SCOPE and registered["replacement_selected"] and legacy["phase"] == "booked"
         and legacy["superseded_by"] == SCOPE and legacy["terminal_stop"]["reason"] == "filesystem-floor"
         and not legacy["terminal_stop"]["checkpoint_interval_completed"], "disk was not exchanged for hourly RAM")
    owner = registered["actor"]
    if phase == "start":
        need(registered["prospective"] and not registered["intent"] and not owner,"hourly 170 already booked")
    else:
        need(not registered["prospective"] and registered["intent"] and owner and owner["phase"] == "held"
             and owner["interface"] == SCOPE and not owner["release"], "different held hourly 170")
    history = core.bound(DRAWDOWN)
    need(history["worst_stop_unix"]-history["worst_start_unix"] == 83, "changed original peer fluctuation")
    return dict(**geometry(whole,history["worst_observed_90s_free_byte_decrease"]),phase=phase,scope=SCOPE,
                closed_comparison=scope["retained_comparison"],observed=int(whole["recorded_unix_seconds"]),fleet=whole["fleet"],
                writer=whole["writer"],whole_roster=whole,resource_credit_bytes=0,archive_publication_authorized=False)
