"""Recognize the held, guarded and terminal RAM-backed 170 without hiding its interrupted predecessor."""
import hashlib
from pathlib import Path
import stat
import sys

RT=Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT=RT/"epoch170-from-73760367-ram-20261128-v1"
UNIT="horizon-qualify-170-from-73760367-ram-20261128-v1.service"
SEAL="e94b0211cfa973e0ca708259c3ec7e611b5cfd6b831d27c9530167d96b3c8bee"


def receiver(core):
    folder=ROOT/"observer-modules-v1"
    seal,_=core.read(folder/"deployment-seal-receipt.json",SEAL)
    expected={name+".py" for name in ("ram170_status","ram170_contract","ram170_native","ram170_workspace")}
    core.need(seal["destination"]==str(folder) and {m["name"] for m in seal["members"]}==expected,
              "different RAM retry observer")
    for m in seal["members"]:
        path=folder/m["name"];s=path.lstat()
        core.need(path.resolve(strict=True)==path and stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
                  and not s.st_mode&0o222 and hashlib.sha256(path.read_bytes()).hexdigest()==m["sha256"],
                  "changed RAM receiver "+m["name"])
    # The V7 receiver already validated the original modules and populated these
    # entries from the sealed support paths before it checked both predecessors.
    core.need("gap170_contract" in sys.modules and "bounded167_admission" in sys.modules and "evidence" in sys.modules,
              "the first gap observer has not been checked")
    sys.path.insert(0,str(folder))
    try:
        import ram170_status as callback
    finally:
        sys.path.pop(0)
    core.need(all(Path(sys.modules[Path(name).stem].__file__)==folder/name for name in expected),
              "foreign RAM observer dependency")
    return callback


def owner(core, fleet):
    callback=receiver(core)
    callback.contract.stopped_owner(fleet)
    gap=callback.gap
    if not gap.ACTOR.exists():
        gap.native.idle(UNIT)
        gap.native.idle(gap.GUARD_UNIT)
        timer = core.state(gap.GUARD_TIMER, "Id,ActiveState,Job")
        core.need(not gap.RELEASE.exists() and not gap.ENROLLMENT.exists()
                  and not (ROOT/"SUCCESSOR_START_INTENT.json").exists()
                  and not (ROOT/"ACTUAL_GUARD_PLAN.json").exists() and not (ROOT/"barrier/allow").exists()
                  and timer["ActiveState"] == "inactive" and not timer["Job"]
                  and not any(row["epoch"] == 170 for row in fleet["actual_active_private_diagnostics"]),
                  "retry authority without its actor")
        return None
    ref,actor=gap.read_actor()
    state=gap.native.props(UNIT,gap.PROPS)
    if state["ActiveState"] in ("inactive","failed"):
        gap.terminal(actor)
        return None
    scope=callback.interface()
    permit,grant=gap.release(scope,ref,actor,callback.contract.checkpoint(scope))
    processes,worker,phase=gap.live(scope,state,actor,grant is not None)
    plan_path=Path(scope["plan_path"])
    plan,pr=core.read(plan_path) if plan_path.exists() else (None,None)
    if grant:
        guard,sighted=gap.guard(scope,actor,worker,grant)
        core.need(guard["plan"]==grant["guard_plan"]==pr and not (ROOT/"guard-receipts/stop-intent.json").exists(),
                  "RAM retry guard stopped")
        phase="worker" if sighted else phase
    core.need(gap.native.props(UNIT,gap.PROPS)==state and [gap.process(p[0]) for p in processes]==processes,
              "RAM retry identity changed during the census")
    return dict(unit=UNIT,invocation=actor["producer_invocation_id"],pid=actor["producer_pid"],actor=ref,
                processes=processes,phase=phase,release=permit,guard_plan=pr,
                floor=plan["minimum_free_bytes"] if plan else None,guard_cap=plan["maximum_root_physical_bytes"] if plan else None)
