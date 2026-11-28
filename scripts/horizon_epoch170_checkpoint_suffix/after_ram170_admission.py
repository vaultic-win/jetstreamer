"""Register the exact staged 170 owner and rotate its existing V20 fleet reservation."""
from hashlib import sha256
import importlib
import os
from pathlib import Path
import runpy
import stat
import sys

G = 1 << 30
ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1")
UNIT = "horizon-qualify-170-from-73766969-20261127-v1.service"
SCOPE = dict(path=str(ROOT / "AFTER_RAM_WRITER_INTERFACE.json"),
             sha256="1f8f41eb9e393c0c6d3238cceae5849caf6b806538a1c1f311b747cf9131749c")
RECEIVER = ROOT / "after-ram-observer-v1"
SEAL = "9d2fffc08e26af3a84e8fda30cf8e1d72fe29b905ef5b9fddc5f9cd7590c8ac2"
HISTORICAL = ROOT.parent / "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v62-entry146"
BASE_MODULES = {
    "fourth170_contract.py": "3ee0ccb0ae86cd0645aaca85ee48a348049f7c033272ab44054071d8c276407b",
    "fourth170_native.py": "0d3552abf6180eaf15f0abce075984b74102672721adc063cd5a2be3e61f77df",
    "continuation170_retry_contract.py": "0c255f7799296f0f9aebb67e38e110ca6d3207de33d8a17f45e5f40cc009e88c",
    "continuation170_contract.py": "7e39dd751026c51b2bc7da962fb279f13c3d5a34ed19dccc340a2cdf5d10e4c6",
}
REG = "after_ram170_accounting"


def need(predicate, message):
    if not predicate:
        raise ValueError(message)


def receiver(core, directory):
    # This authenticates the third RAM receiver and its support dependencies before import.
    runpy.run_path(str(directory / "ram170_live.py"))["receiver"](core)
    seal, _ = core.read(RECEIVER / "deployment-seal-receipt.json",SEAL)
    rows = {m["name"]:m["sha256"] for m in seal["members"]}
    need(seal["destination"] == str(RECEIVER) and set(rows) == {
        "after_ram170_contract.py","after_ram170_native.py","after_ram170_history.py","after_ram170_status.py"},
        "different after-RAM receiver")
    paths = {RECEIVER / k:v for k,v in rows.items()}
    paths.update({HISTORICAL / k:v for k,v in BASE_MODULES.items()})
    for path, digest in paths.items():
        st = path.lstat()
        need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
             and st.st_nlink == 1 and not st.st_mode & 0o222 and sha256(path.read_bytes()).hexdigest() == digest,
             "different receiver source " + str(path))
    sys.path[:0] = [str(RECEIVER),str(HISTORICAL)]
    try:
        callback = importlib.import_module("after_ram170_status")
    finally:
        del sys.path[:2]
    need(all(Path(sys.modules[p.stem].__file__) == p for p in paths if p.stem != "after_ram170_history")
         and callback.INTERFACE == SCOPE and callback.UNIT == UNIT, "different receiver module resolution")
    return callback


def owner(core, fleet, directory):
    scope = core.bound(SCOPE)
    if not os.path.lexists(scope["actor_path"]):
        core.inactive(UNIT)
        need(not any(os.path.lexists(scope[k]) for k in ("release_path","barrier","plan_path","enrollment_path")),
             "after-RAM authority without an actor")
        return None
    callback = receiver(core,directory)
    callback.contract.previous_owner(fleet)
    following = callback.following
    need(not any(path.exists() for path in (callback.old.ACTOR,callback.old.RELEASE,callback.old.ENROLLMENT)),
         "two fourth-window actors")
    comparison = callback.contract.closed_comparison(callback.contract.interface())
    ref, actor = following.read_actor()
    state = following.native.props(UNIT,following.PROPS)
    release, grant = following.release(scope,ref,actor,comparison)
    plan_path = Path(scope["plan_path"])
    plan, plan_ref = core.read(plan_path) if plan_path.exists() else (None,None)
    info = dict(unit=UNIT,invocation=actor["producer_invocation_id"],pid=actor["producer_pid"],
                actor=ref,interface=SCOPE,release=release,guard_plan=plan_ref,closed_comparison=comparison,
                floor=plan["minimum_free_bytes"] if plan else None,guard_cap=plan["maximum_root_physical_bytes"] if plan else None)
    if state["ActiveState"] in ("inactive","failed"):
        event = following.terminal(actor)
        need(not (Path("/sys/fs/cgroup/system.slice")/UNIT).exists(),"closed after-RAM actor still has a cgroup")
        return dict(**info,phase="terminal",native_terminal=event)
    processes, worker, phase = following.live(scope,state,actor,grant is not None)
    if grant:
        guard, seen = following.guard(scope,actor,worker,grant)
        need(guard["plan"] == grant["guard_plan"] == plan_ref and not (Path(scope["guard_receipts"])/"stop-intent.json").exists(),
             "after-RAM guard stopped or has a foreign plan")
        if seen:
            phase = "worker"
    need(following.native.props(UNIT,following.PROPS) == state and [following.process(p[0]) for p in processes] == processes,
         "after-RAM native identity changed")
    return dict(**info,phase=phase,processes=processes)


def rotated(whole):
    """Replace the fully nonresident 56 GiB/8 GiB allocation once, retaining every other booking."""
    need(REG not in whole and not whole["resource_credit_bytes"], "duplicate or unexpected 170 adjustment")
    native = whole["base_169"]["native"]
    joint = native["raw"]["joint"]
    cost = native["ram_retry_cost"]
    need(native["ram_gap170"] is None and native["ram170_residency"]["realized_bytes"] == cost["resident_ram_credit"] == 0
         and cost["producer_memory_max"] == 56*G and cost["extra_ram"] == 8*G and cost["scratch_tmpfs"] == 40*G
         and cost["home_growth"] == 8*G and cost["original_home_growth"] == joint["candidate_growth"] == 36*G
         and cost["original_guard_still_budgeted"] and joint["guard_sibling_allowance"] == G
         and joint["producer_allowance"] == 48*G and joint["producer_quota_micros"] == 6_000_000
         and joint["guard_quota_micros"] == 1_000_000 and whole["available_ram"]-whole["required_ram"] == whole["ram_margin"],
         "different prior working-set charge or live predecessor")
    home_delta = cost["original_home_growth"] - cost["home_growth"]
    ram_delta = joint["producer_allowance"] - cost["producer_memory_max"]
    required_home = whole["required_home"] + home_delta
    required_ram = whole["required_ram"] + ram_delta
    margin = min(whole["home_margin"] - home_delta,whole["available_home"] - required_home)
    ram = whole["available_ram"] - required_ram
    base = whole["base_169"]
    peer_resident = whole["second_162_accounting"]["resident_lower_bytes"]
    # These are the four independent tests in V20's 162 reconciliation. The
    # subsequent 167 allocation can only lower the final HOME margin.
    known_fit = min(base["home_margin"], base["ram_margin"] + peer_resident,
                    whole["home_margin"], whole["ram_margin"]) >= 0
    need(known_fit == whole["fits"], "an additional shared admission condition needs reconciliation")
    other_fit = base["home_margin"] >= home_delta and base["ram_margin"] + peer_resident >= ram_delta
    return dict(required_home=required_home,required_ram=required_ram,home_margin=margin,ram_margin=ram,
                fits=other_fit and min(margin,ram) >= 0,guard_floor=whole["guard_floor"])


def booking(core, directory):
    path = ROOT / "SUCCESSOR_START_INTENT.json"
    if not os.path.lexists(path):
        return None
    intent, ref = core.read(path)
    scope = core.bound(SCOPE)
    contract = receiver(core,directory).contract
    comparison = contract.closed_comparison(contract.interface())
    fit = core.bound(intent["price"])
    need(intent["interface"] == SCOPE and intent["closed_comparison"] == comparison and intent["producer_unit"] == UNIT
         and intent["guard_unit"] == scope["expected_guard_unit"] and fit["phase"] == "start" and fit["fits"]
         and fit["candidate_170_growth_bytes"] == 36*G and fit["accounted_home_delta"] == 28*G
         and fit["scope"] == SCOPE and not intent["resource_credit_bytes"] and not intent["archive_publication_authorized"],
         "different staged successor booking")
    return ref


def account(whole, core, directory):
    need(REG not in whole, "after-RAM profile was already accounted")
    actor = whole["base_169"]["native"]["after_ram170"]
    intent = booking(core,directory)
    need(actor is None or intent, "unbooked fourth-window actor")
    if intent:
        whole.update(rotated(whole))
    whole[REG] = dict(scope=SCOPE,phase="booked" if intent else "unbooked",intent=intent,actor=actor,
                      home_increment=28*G if intent else 0,ram_delta=-8*G if intent else 0,
                      producer_memory_max=48*G,guard_memory_max=G,home_growth_bytes=36*G,
                      additional_input_bytes=0,resource_credit_bytes=0)
    return whole


def candidate(whole, phase, *, scope, closed, peer_drawdown=0):
    """Return the issuer fit for the held gate, including the live whole-tree cap and existing floors."""
    need(phase in ("start","held") and scope == SCOPE and closed["path"] == str(ROOT/"THIRD_CLOSED_COMPARISON.json")
         and len(closed["sha256"]) == 64 and not whole["preparation_only"] and peer_drawdown >= 0,
         "different successor, closed comparison or shared quote")
    account = whole[REG]
    need(account["scope"] == SCOPE and account["resource_credit_bytes"] == 0, "wrong registered profile")
    actor = account["actor"]
    if phase == "start":
        need(account["phase"] == "unbooked" and account["intent"] is None and actor is None
             and account["home_increment"] == account["ram_delta"] == 0, "successor already booked")
        base = dict(whole)
        del base[REG]
        budget = rotated(base)
    else:
        need(account["phase"] == "booked" and account["intent"] and actor and actor["phase"] == "held"
             and actor["interface"] == scope and actor["closed_comparison"] == closed and not actor["release"]
             and account["home_increment"] == 28*G and account["ram_delta"] == -8*G,
             "different held successor or double charge")
        budget = {k:whole[k] for k in ("required_home","required_ram","home_margin","ram_margin","guard_floor","fits")}
    native = whole["base_169"]["native"]
    raw = native["raw"]
    low, high = raw["terminal_tree_bounds"]
    need(0 < low <= high, "missing current conservative whole-tree size")
    # Preserve all floors even when independent jobs already raised one above the arithmetic minimum.
    growth = 36*G
    floor = max(budget["guard_floor"],raw["guard_floor"],budget["required_home"]-growth,
                whole["available_home"]-budget["home_margin"]-growth)
    cap = min(low+growth,384*G)
    required = max(budget["required_home"],floor+growth)
    margin = min(budget["home_margin"],whole["available_home"]-required) - peer_drawdown
    return dict(scope=scope,closed_comparison=closed,phase=phase,observed=int(whole["recorded_unix_seconds"]),
                fleet=whole["fleet"],writer=whole["writer"],whole_roster=whole,guard_floor=floor,guard_cap=cap,
                terminal_tree_bounds=[low,high],candidate_170_growth_bytes=growth,accounted_home_delta=28*G,
                accounted_ram_delta=-8*G,producer_memory_max=48*G,guard_memory_max=G,required_ram=budget["required_ram"],
                available_home=whole["available_home"],required_home=required,shared_required_home=budget["required_home"],
                home_margin=margin,ram_margin=budget["ram_margin"],joint=raw["joint"],assembly168=raw["assembly168"],
                shared_drawdown_allowance=peer_drawdown,resource_credit_bytes=0,archive_publication_authorized=False,
                fits=budget["fits"] and margin>=0 and high<=cap and cap-low==growth)
