"""Admit the private scratch retry with its predecessor guard transferred and both retries funded."""
import hashlib
import importlib.util
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time


spec = importlib.util.spec_from_file_location("original_gap_price", Path(__file__).with_name("gap170_price.py"))
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
RT, TREE, prior, need, cmd, state, inactive, read, bound = (
    original.RT, original.TREE, original.prior, original.need, original.cmd, original.state,
    original.inactive, original.read, original.bound,
)
G, M = 1 << 30, 1 << 20
DEP = ATTEMPT = RT / "epoch170-from-73760367-ram-20261128-v1"
OPERATOR = DEP / "operator-v1"
PROVIDER = RT / "epoch162-first-hourly-completion-20261127-v2/issued-price-v9"
PROVIDER_SHA = "d97547403106754db04ef006b72e5e4f60f6d92a90723a3fc312f7bb56bb0066"
UNIT = "horizon-qualify-170-from-73760367-ram-20261128-v1.service"
ALIAS, BRIDGE = original.ALIAS, original.BRIDGE
RETRY = FOLLOWING = False
INTERFACE_SHA = "cf7836a48efd71f886924a07657101691d27d24f6ccf05cbe7938b4be1daedaf"
STOP_SHA = "2eb844de0deb0717268b07b9cc0bdd746a92880075fbb14ca515638305f2721c"
OBSERVER_SHA = "e94b0211cfa973e0ca708259c3ec7e611b5cfd6b831d27c9530167d96b3c8bee"
PRODUCER_MEMORY = 56 * G
ENROLL_OPTION = "--enroll-ram-gap-170"
retained_guard = original.retained_guard


def package(directory, digest):
    seal, ref = read(directory / "deployment-seal-receipt.json", digest)
    need(seal["destination"] == str(directory), "incorrect sealed package")
    for item in seal["members"]:
        path = directory / item["name"]
        meta = path.lstat()
        need(path.parent == directory and path.resolve(strict=True) == path and stat.S_ISREG(meta.st_mode)
             and meta.st_uid == 0 and meta.st_nlink == 1 and not meta.st_mode & 0o222
             and meta.st_size == item["bytes"] and hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"],
             "changed sealed member " + str(path))
    return seal, ref


def scope():
    value, ref = read(DEP/"RAM_GAP170_WRITER_INTERFACE.json", INTERFACE_SHA)
    earlier, old_ref = original.scope()
    stop, stop_ref = read(DEP/"PREDECESSOR_FLOOR_STOP.json", STOP_SHA)
    proof = bound(value["source_preflight"])
    namespace = bound(value["namespace"])
    profile = value["profile"]
    need(value["expected_producer_unit"] == profile["host_unit"] == UNIT
         and value["prior_gap"] == old_ref and value["ram_retry_predecessor"] == stop_ref
         and stop["unit"] == original.UNIT and not stop["closed_segment"]
         and stop["invocation_id"] == "d8ea1fcfbd6646839b9593752f4afdef"
         and [value["first_new_slot"], value["last"]] == proof["scope"] == [73760368,73766969]
         and proof["route_accepted"] and not proof["worker_executed"] and proof["namespace"] == value["namespace"]
         and namespace["report"]["limits"]["memory.max"] == str(PRODUCER_MEMORY)
         and namespace["report"]["scratch"]["bytes"] == profile["scratch_noswap_tmpfs_bytes"] == 40*G
         and profile["producer_memory_bytes"] == PRODUCER_MEMORY and profile["new_home_total_bytes"] == 8*G
         and profile["new_control_bytes"] == 64*M and not value["publication_authorized"]
         and all(value[k] == earlier[k] for k in ("source_packet","old_actor","old_release","independent_checkpoint","handoff"))
         and all(profile[k] == earlier["profile"][k] for k in ("bootstrap","positions","worker","node","checkpoints")),
         "different private 170 retry scope or predecessor")
    return value, ref


def compare_predecessor():
    checkpoint = original.compare_predecessor()
    value, _ = scope()
    need(checkpoint == value["independent_checkpoint"], "incorrect bootstrap checkpoint")
    return checkpoint


def writer(require_registration=True):
    _, active_scope = scope()
    _, registered = package(PROVIDER, PROVIDER_SHA)
    binding, _ = read(OPERATOR/"binding.json")
    need(binding["provider"] == registered and binding["ram_gap170_interface"] == active_scope,
         "different 170 issuer, scope or whole-fleet provider")
    peer = runpy.run_path(str(PROVIDER/"following_peers.py"))
    original_ref = dict(path=str(peer["ISSUED"]/"deployment-seal-receipt.json"), sha256=peer["SEAL169"])
    active_ref = peer["current_writer"](prior, original_ref)
    active = bound(active_ref)
    ready = bound(active["ready"])
    program = Path(active["new"]["program"])
    if not require_registration and "ram_gap170_interface" not in ready:
        return active_ref, None
    enrolled = bound(ready["package"])
    receiver, _ = package(DEP/"observer-modules-v1", OBSERVER_SHA)
    images = {item["name"]: item["sha256"] for item in enrolled["members"]}
    need(ready.get("ram_gap170_interface") == active_scope and enrolled["destination"] == str(program.parent)
         and all(images.get(item["name"]) == item["sha256"] for item in receiver["members"])
         and ENROLL_OPTION in program.read_text(), "live cadence has not enrolled the RAM-backed 170 scope")
    return active_ref, program


def previous_guard():
    """The interrupted gap and its timer must belong to the exact prior grant."""
    value, _ = scope()
    stop = bound(value["ram_retry_predecessor"])
    grant = bound(stop["release"])
    done = bound(stop["stop_completion"])
    old = original.UNIT
    unit = old.replace("-qualify-","-guard-")
    timer = unit.replace(".service",".timer")
    producer = inactive(old)
    need(not producer["ControlGroup"] and done["terminal"]["active"] == "inactive"
         and grant["producer_invocation_id"] == done["producer_invocation_id"] == stop["invocation_id"]
         and grant["guard_plan"]["sha256"] == done["plan_sha256"]
         and bound(grant["guard_plan"])["unit"] == old, "previous gap still owns compute")
    current = state(timer, "Id,ActiveState,InvocationID,Job,Triggers")
    need(not current["Job"], "prior gap timer is transitioning")
    if current["ActiveState"] == "active":
        need(current["InvocationID"] == grant["guard_timer_invocation_id"] and current["Triggers"] == unit,
             "unrecognized old gap timer")
        child = state(unit,"Id,ExecStart,TriggeredBy,MemoryMax,CPUQuotaPerSecUSec")
        need(child["TriggeredBy"] == timer and child["MemoryMax"] == str(G) and child["CPUQuotaPerSecUSec"] == "1s"
             and all(token in child["ExecStart"] for token in
                     (str(original.DEP/"package/guard"), grant["guard_plan"]["path"], grant["guard_plan"]["sha256"])),
             "unrecognized old gap guard")
    else:
        need(current["ActiveState"] == "inactive" and not inactive(unit)["ControlGroup"], "old gap guard still executing")
    return current, unit, stop["release"]


def transfer_guard(save):
    before, unit, grant = previous_guard()
    if before["ActiveState"] == "active":
        intent = save("PREVIOUS_GUARD_DRAIN_INTENT.json", dict(timer=before, unit=unit, grant=grant))
        subprocess.run(["/usr/bin/systemctl","stop",before["Id"]],check=True)
        # A sampling invocation may already have entered the cgroup. Let its
        # ordinary observation finish before using its CPU and RAM allotment.
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            row = state(unit)
            if row["ActiveState"] in ("inactive","failed") and not row["Job"] and not row["ControlGroup"]:
                break
            time.sleep(.1)
    else:
        history = DEP / "PREVIOUS_GUARD_DRAIN_INTENT.json"
        if history.exists():
            prior_intent, intent = read(history)
            need(prior_intent["grant"] == grant and prior_intent["unit"] == unit, "previous timer drain differs")
        else:
            intent = save(history.name, dict(timer=before, unit=unit, grant=grant, observed_already_drained=True))
    after, _, final_grant = previous_guard()
    need(after["ActiveState"] == "inactive" and grant == final_grant, "previous gap guard did not drain")
    return save("PREVIOUS_GUARD_DRAIN.json",dict(intent=intent,unit=unit,timer=after["Id"],old_grant=grant,
                                                producer_and_guard_drained=True))


def geometry(quote, bounds, minimum_floor, other_floor):
    low, high = bounds
    growth = 8*G - 64*M
    # Keep control bytes outside the epoch tree charged through producer exit.
    floor = max(minimum_floor, other_floor, quote["guard_floor"], quote["required_home"]-growth,
                quote["available_home"]-quote["home_margin"]-growth)
    required = floor + growth
    cap = min(low + growth, 384*G)
    margin = min(quote["home_margin"], quote["available_home"]-required)
    return dict(guard_floor=floor,guard_cap=cap,growth_bytes=growth,candidate_170_growth_bytes=growth,
                required_home=required,home_margin=margin,terminal_tree_bounds=bounds,
                fits=quote["fits"] and margin>=0 and high<=cap and cap-low==growth)


def price(phase, *, preliminary=False):
    need(phase in ("start","held") and Path(__file__).resolve().parent == OPERATOR, "unexpected retry phase or location")
    need(not preliminary or phase == "start", "a held admission requires its registered cadence")
    before, _, predecessor = previous_guard()
    active, program = writer(require_registration=not preliminary)
    quote = runpy.run_path(str(PROVIDER/"capacity.py"))["whole_roster"]()
    n = quote["base_169"]["native"]
    p = n["planned_169_retry"]
    r = n["ram_retry_cost"]
    row = n["ram_gap170"]
    need(quote["writer"] == active and quote["package"]["sha256"] == PROVIDER_SHA
         and p["second_scope"]["sha256"] == "322698c6be8e7632654eea5b9074a395b61f27db648bb6ebb818f79b0ee1bd0e"
         and p["first_unreleased_closure"]["sha256"] == "24d2fc5ecf736827e0b06af6194f85ad1dae055f33065d6e9e20606eb17ee9dc"
         and p["additional_ram"] == r["extra_ram"] == 8*G and p["additional_home"] == 4*G + 64*M
         and r["home_growth"] == 8*G and r["producer_memory_max"] == PRODUCER_MEMORY and r["scratch_tmpfs"] == 40*G
         and r["original_guard_still_budgeted"] and r["previous_stop"]["release"] == predecessor
         and not quote["resource_credit_bytes"], "changed bilateral reservation or predecessor")
    if phase == "held":
        need(row and row["phase"] == "held" and row["actor"] == read(DEP/"SUCCESSOR_ACTOR.json")[1]
             and not row["release"] and before["ActiveState"] == "inactive", "incorrect held retry or guard turnover")
    else:
        need(not row and not os.path.lexists(DEP/"SUCCESSOR_ACTOR.json"), "retry already has an actor")
    peer = n["independent_retry169"]
    other_floor = (peer.get("floor") or 0) if peer else 0
    raw = n["raw"]
    result = geometry(quote,raw["terminal_tree_bounds"],raw["guard_floor"],other_floor)
    return dict(**result,phase=phase,observed=int(time.time()),fleet=quote["fleet"],writer=active,
                available_home=quote["available_home"],ram_margin=quote["ram_margin"],
                joint=raw["joint"],assembly168=raw["assembly168"],whole_roster=quote,prior_guard=before,
                writer_ready=program is not None,preliminary=preliminary,
                resource_credit_bytes=0,archive_publication_authorized=False)
