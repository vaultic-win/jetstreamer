"""Recognize the next guarded 170 owner without adding a second reservation."""
from hashlib import sha256
import importlib
import os
from pathlib import Path
import runpy
import stat
import sys
import time

G = 1 << 30
M = 1 << 20
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73773645-ram-20261128-v1")
UNIT = "horizon-qualify-170-from-73773645-ram-20261128-v1.service"
SCOPE = None
RECEIVER = None


def receiver(core):
    seal = core.bound(RECEIVER)
    directory = ROOT/"observer-modules-v1"
    names = {f"next_hourly170_{name}.py" for name in ("contract","native","status","workspace")}
    core.need(RECEIVER["path"] == str(directory/"deployment-seal-receipt.json")
              and seal["destination"] == str(directory)
              and set(row["name"] for row in seal["members"]) == names
              and len(seal["members"]) == len(names), "different next-hourly receiver seal")
    for row in seal["members"]:
        path = directory/row["name"]
        info = path.lstat()
        core.need(path.resolve(strict=True) == path and stat.S_ISREG(info.st_mode)
                  and info.st_nlink == 1 and info.st_uid == 0 and not info.st_mode & 0o222
                  and sha256(path.read_bytes()).hexdigest() == row["sha256"],
                  "unsealed observer " + path.name)
    sys.path.insert(0,str(directory))
    try:
        module = importlib.import_module("next_hourly170_status")
    finally:
        del sys.path[0]
    core.need(module.INTERFACE == SCOPE and module.UNIT == UNIT
              and all(Path(sys.modules[Path(p).stem].__file__) == directory/p for p in names),
              "foreign next-hourly receiver modules")
    return module


def owner(core, fleet):
    scope = core.bound(SCOPE)
    if not os.path.lexists(scope["actor_path"]):
        core.inactive(UNIT)
        core.need(not any(os.path.lexists(scope[k]) for k in ("release_path","barrier","plan_path","enrollment_path")),
                  "next-hourly authority exists without an actor")
        return None
    callback = receiver(core)
    callback.contract.stopped_owner(fleet)
    closed = callback.contract.checkpoint(callback.contract.interface())
    node = callback.gap
    ref, actor = node.read_actor()
    props = node.native.props(UNIT,node.PROPS)
    release, grant = node.release(scope,ref,actor,closed)
    plan_path = Path(scope["plan_path"])
    plan, pr = core.read(plan_path) if plan_path.exists() else (None,None)
    row = dict(unit=UNIT,invocation=actor["producer_invocation_id"],pid=actor["producer_pid"],
               phase="held",actor=ref,interface=SCOPE,release=release,guard_plan=pr,
               closed_comparison=closed,floor=plan["minimum_free_bytes"] if plan else None)
    if props["ActiveState"] in ("inactive","failed"):
        core.need(not node.CGROUP.exists(),"next-hourly cgroup still draining")
        return dict(row,phase="terminal",native_terminal=node.terminal(actor))
    processes, worker, phase = node.live(scope,props,actor,grant is not None)
    guard = None
    if grant:
        guard, guarded_worker = node.guard(scope,actor,worker,grant)
        core.need(guard["plan"] == pr and not (Path(scope["guard_receipts"])/"stop-intent.json").exists(),
                  "next-hourly guard is stopping")
        if guarded_worker:
            phase = "worker"
    core.need(node.native.props(UNIT,node.PROPS) == props and [node.process(p[0]) for p in processes] == processes,
              "next-hourly owner changed during census")
    return dict(row,phase=phase,processes=processes,tree_guard=guard)


def stable(row):
    if not row or not row.get("tree_guard"):
        return row
    return dict(row,tree_guard={key:value for key,value in row["tree_guard"].items() if key != "sample"})


def guarded_bounds(actor, tree, bound, state, cmd, directory):
    scope, grant, owner, plan = (bound(actor[key]) for key in ("interface","release","actor","guard_plan"))
    guard = actor["tree_guard"]
    sample = bound(guard["sample"])
    run = Path(scope["run"])
    mounts = state(UNIT,"Id,ProtectHome,ReadWritePaths")
    need = runpy.run_path(str(directory/"after_floor170_price.py"))["need"]
    need(actor["unit"] == UNIT and actor["interface"] == owner["interface"] == SCOPE
         and actor["phase"] in ("worker","bootstrap")
         and actor["invocation"] == grant["producer_invocation_id"] == owner["producer_invocation_id"] == plan["invocation_id"]
         and grant["actor"] == actor["actor"] and grant["closed_comparison"] == scope["retained_comparison"]
         and grant["guard_plan"] == guard["plan"] == actor["guard_plan"]
         and grant["guard_timer_invocation_id"] == guard["timer_invocation_id"]
         and plan["unit"] == UNIT and plan["worker_root"] == str(run)
         and plan["maximum_root_physical_bytes"] == (8*G)-(64*M)
         and mounts["Id"] == UNIT and mounts["ProtectHome"] == "read-only"
         and mounts["ReadWritePaths"] == str(run)
         and sample["producer_invocation_id"] == actor["invocation"] and sample["producer"]["pid"] == actor["pid"]
         and sample["plan_sha256"] == actor["guard_plan"]["sha256"] and sample["guard_sha256"] == scope["guard_sha"]
         and not os.path.lexists(Path(scope["guard_receipts"])/"stop-intent.json"),
         "different next-hourly guarded scope")
    support = runpy.run_path(str(directory/"after_ram170_tree.py"))
    closed = support["closed_bytes"](cmd,tree,run)
    own = support["native_scans"](sample,plan,time.time())
    return dict(actor=actor["actor"],release=actor["release"],interface=SCOPE,plan=actor["guard_plan"],guard=guard,
                tree=str(tree),excluded_writable_run=str(run),closed_du_bytes=closed,guarded_physical_bytes=own,
                bounds=[min(closed)+min(own),max(closed)+max(own)],minimum_free_bytes=plan["minimum_free_bytes"],
                active_run_occupancy_credit_bytes=0)


def apply_residency(core, native, helper, first, last):
    core.need("next_hourly170_residency" not in native
              and native["after_floor170_residency"]["realized_bytes"] == native["ram170_residency"]["realized_bytes"] == 0,
              "two 170 owners claim residency")
    probe = dict(raw=native["raw"],resource_credit_bytes=native["resource_credit_bytes"],
                 ram_gap170=native["next_hourly170"],realized_170_anon=native["realized_170_anon"],
                 required_ram=native["required_ram"],available_ram=native["available_ram"],
                 ram_retry_cost=dict(native["ram_retry_cost"]))
    helper["apply"](core,probe,first,last)
    native["next_hourly170_residency"] = probe["ram170_residency"]
    native["required_ram"] = probe["required_ram"]
    native["ram_margin"] = probe["ram_margin"]


def register(core, whole):
    path = ROOT/"SUCCESSOR_START_INTENT.json"
    intent, ref = core.read(path) if path.exists() else (None,None)
    old = whole["after_floor170_accounting"]
    native = whole["base_169"]["native"]
    current = native["next_hourly170"]
    core.need(not current or intent, "unbooked next-hourly native owner")
    if intent:
        price = core.bound(intent["price"])
        scope = core.bound(SCOPE)
        core.need(old["actor"]["phase"] == "terminal" and old["resident_credit"] == 0
                  and old["replacement_selected"] and old["home_growth"] == 8*G
                  and old["producer_memory"] == 56*G and old["guard_memory"] == G
                  and intent["interface"] == price["scope"] == SCOPE
                  and intent["closed_comparison"] == scope["retained_comparison"]
                  and price["predecessor"] == scope["predecessor"] and price["fits"]
                  and price["phase"] == "start" and intent["producer_unit"] == UNIT
                  and price["guard_cap"] == (8*G)-(64*M) and price["future_home_existing_booking"] == 8*G
                  and price["producer_memory_max"] == 56*G and price["guard_memory_max"] == G
                  and not price["resource_credit_bytes"] and not intent["archive_publication_authorized"],
                  "unfunded or overlapping next-hourly intent")
    whole["next_hourly170_accounting"] = dict(scope=SCOPE,actor=current,intent=ref,
        producer_booking_reused=bool(intent),home_growth=8*G,producer_memory=56*G,guard_memory=G,
        additional_home=0,additional_ram=0,resident_credit=native["next_hourly170_residency"]["realized_bytes"])
    return whole
