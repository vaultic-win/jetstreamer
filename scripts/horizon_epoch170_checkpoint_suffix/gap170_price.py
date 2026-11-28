"""Price the independently scoped 6,602-position recording against the current complete fleet."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import runpy
import time

DEP = ATTEMPT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-20261128-v1")
RT = DEP.parent
OPERATOR = DEP / "operator-v1"
ALIAS = "/run/horizon-170-from-73760367-v1"
UNIT = "horizon-qualify-170-from-73760367-20261128-v1.service"
BRIDGE = "horizon-qualify-170-from-73746882-20261127-v1.service"
ORIG = "c3ab30cfeb05428bb8f5c48a5a44822c"
WRITER = RT / "survivor172-cadence-20261122-v1"
PROVIDER = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v7"
OLD = RT / "epoch170-from-73746882-20261127-v1/attempt-2/operator-v3"
CHECKPOINT = "1031f72af7900560d972c0a4b0c50f5f42e0c548e883e0eafbe3eaa0dec1f4eb"
INTERFACE_SHA = "3f375caf9273b81cb84c5908695c27c0e4dbc6406f5ab53ebc1e1611ddf2a69f"
ACTIVE_SHA = "ede08352a67056909967fa5961c1b19987ab894a8a46a0514e5613d9cc5e086b"
G = 1 << 30
FOLLOWING = RETRY = False


def module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance


# The SHA-pinned common reader enforces root ownership, integral receipt digests
# and canonical paths before it exposes any dynamic host evidence.
core_path = OLD / "successor_price.py"
if hashlib.sha256((OLD / "deployment-seal-receipt.json").read_bytes()).hexdigest() != "0dd508ca75585705f8a01805518f9b1792be31943548f9829421bef858d5be56":
    raise ValueError("unregistered historical runtime")
historical = json.loads((OLD / "deployment-seal-receipt.json").read_bytes())
expected, = [m for m in historical["members"] if m["name"] == core_path.name]
if hashlib.sha256(core_path.read_bytes()).hexdigest() != expected["sha256"]:
    raise ValueError("changed historical pricing primitives")
prior = module(core_path)
TREE, need, cmd, state, inactive, read, bound = (prior.TREE, prior.need, prior.cmd, prior.state, prior.inactive, prior.read, prior.bound)


def scope():
    result, ref = read(DEP / "GAP170_WRITER_INTERFACE.json", INTERFACE_SHA)
    entry = bound(result["source_preflight"])
    need(result["expected_producer_unit"] == UNIT and entry["scope"] == [73760368, 73766969]
         and entry["route_accepted"] and not entry["worker_executed"]
         and result["profile"]["positions"] == 6602 and not result["publication_authorized"],
         "different independent gap scope")
    return result, ref


def compare_predecessor():
    source, ref = read(DEP / "INDEPENDENT_CHECKPOINT.json", CHECKPOINT)
    i, _ = scope()
    packet = bound(source["source_packet"])
    custody = bound(source["bootstrap_payload"])
    terminal = bound(source["verified_original_stop"])
    need(source["closed_segment"] is False and source["original_actor"] == i["old_actor"]
         and source["original_release"] == i["old_release"] and source["native_preflight"] == i["source_preflight"]
         and ref == i["independent_checkpoint"] and source["source_packet"] == i["source_packet"]
         and terminal["properties"]["InvocationID"] == ORIG and terminal["properties"]["ExecMainStatus"] == "15"
         and packet["bootstrap_snapshot_sha256"] == custody["sha256"] and packet["positions"] == 6602
         and not packet["predecessor_closed_segment_claimed"], "different gap checkpoint")
    return ref


def writer():
    active, ref = read(WRITER / "FAILED166_CADENCE_V52_ACTIVE.json", ACTIVE_SHA)
    ready = bound(active["ready"])
    package = bound(ready["package"])
    owner = active["new"]
    source = Path(owner["program"])
    directory = source.parent
    need(ready["gap170_interface"] == scope()[1] and ready["successor170_interface"]["sha256"] == "6b0e1674cb45059761c95b312fbbb478a80ed1a0ab22dcee22a55cbfc03efb40"
         and package["destination"] == str(directory) and source.name == "status_cycle.py"
         and directory == WRITER / "tools-cold168-retry5-failed166-v52-entry146", "writer lacks the independent gap route")
    for filename in ("status_cycle.py", "gap170_contract.py", "gap170_native.py", "gap170_status.py"):
        member, = (item for item in package["members"] if item["name"] == filename)
        need(hashlib.sha256((directory/filename).read_bytes()).hexdigest() == member["sha256"], "writer source binding changed")
    s = state(owner["unit"]); p = Path("/proc") / str(owner["pid"])
    lock = (p / "fd" / str(owner["lock"]["fd"])).stat()
    need(s["InvocationID"] == owner["invocation_id"] and s["ActiveState"] == "active"
         and s["MainPID"] == str(owner["pid"]) and os.fsencode(source) in (p/"cmdline").read_bytes().split(b"\0")
         and int((p/"stat").read_text().rsplit(") ",1)[1].split()[19]) == owner["start_ticks"]
         and (lock.st_dev,lock.st_ino) == (owner["lock"]["device"],owner["lock"]["inode"]),
         "writer lost its existing cadence lock")
    return ref, source


def retained_guard(timer, original):
    need(timer["InvocationID"] == original["timer_invocation_id"]
         and timer["Id"] == BRIDGE.replace("-qualify-", "-guard-").replace(".service", ".timer")
         and timer["ActiveState"] == "active" and not timer["Job"], "old guard changed")
    inactive(BRIDGE)


def price(phase):
    need(phase in ("start","held") and Path(__file__).resolve().parent == OPERATOR,
         "use the sealed gap operator")
    details, _ = read(OPERATOR / "binding.json")
    ref = details["provider"]
    seal = bound(ref)
    need(Path(ref["path"]) == PROVIDER / "deployment-seal-receipt.json"
         and seal["destination"] == str(PROVIDER) and details["gap170_interface"] == scope()[1],
         "different complete fleet price")
    for member in seal["members"]:
        path = PROVIDER/member["name"]
        need(path.parent == PROVIDER and path.resolve(strict=True) == path
             and path.stat().st_uid == 0 and not path.stat().st_mode & 0o222
             and hashlib.sha256(path.read_bytes()).hexdigest() == member["sha256"], "provider changed")
    active, _ = writer()
    quote = runpy.run_path(str(PROVIDER/"capacity.py"))["whole_roster"]()
    base = quote["base_169"]["native"]
    raw = base["raw"]
    native = base["independent_gap170"]
    need(quote["writer"] == active and quote["package"] == ref and raw["phase"] == "stopped"
         and raw["reserved_following_170_growth_bytes"] == 36*G
         and raw["failed_170"]["invocation_id"] == ORIG
         and base["independent_gap_funding"]["new_guard_cpu_micros"] == 1_000_000,
         "different lane or absent future capacity")
    if phase == "start":
        need(native is None and not (DEP/"SUCCESSOR_ACTOR.json").exists(), "independent gap already enrolled")
    else:
        need(native and native["actor"] == read(DEP/"SUCCESSOR_ACTOR.json")[1]
             and native["phase"] == "held" and not native["release"], "foreign held gap owner")
    growth = 36*G
    low, high = raw["terminal_tree_bounds"]
    floor = max(raw["guard_floor"], quote["guard_floor"], quote["required_home"]-growth,
                quote["available_home"]-quote["home_margin"]-growth)
    cap = min(low+growth, 384*G)
    required = floor+growth
    margin = min(quote["home_margin"],quote["available_home"]-required)
    return dict(phase=phase, observed=int(time.time()), fleet=quote["fleet"], writer=active,
                fits=quote["fits"] and margin>=0 and cap>=high and cap-low==growth,
                terminal_tree_bounds=[low, high], guard_cap=cap, guard_floor=floor,
                growth_bytes=growth, candidate_170_growth_bytes=growth, required_home=required,
                available_home=quote["available_home"], ram_margin=quote["ram_margin"], home_margin=margin,
                joint=raw["joint"], assembly168=raw["assembly168"], whole_roster=quote,
                resource_credit_bytes=0,archive_publication_authorized=False)
