"""One-time reassignment of idle CPU following successful public playback of epoch 144."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from datetime import datetime, timezone

RT = Path("/var/lib/jetstreamer/horizon_runtime_data")
OUT = RT / "ready-region-cpu-transfer-20261122-v1"
READY = RT / "ready-range-audit-20261121-v1"
CADENCE = RT / "prefix140-status-cadence-20261122-v1/cadence-tools"
CG = Path("/sys/fs/cgroup/horizonaudit.slice")
POOL = "horizon-r2-ready-parallel-regions-20261121-v1.service"
PRIMARY = "horizon-r2-ready-ranges-101-300-20261121-v1.service"
RETIRED = "horizon-r2-fast-ranges-256-20261121-v1.service"
GUARD = "horizon-ready-top-metadata-guard-20261121-v1.service"
PREFIX = "horizon-epoch140-prefix-audit-runtime-20261122-v1.service"
BASELINE = "b05e3f518bc8def15aca673f698c9312acc577a489c05a211a1ef87213654b24"
START = "a39d96650795b7c06b4d53dd83b3e099891ee8b1203c0efb0d283aa0e88ea6f3"
OLD_LIMIT = 4
NEW_LIMIT = 7
LEGAL = (OLD_LIMIT, NEW_LIMIT)

def need(ok, why):
    if not ok:
        raise ValueError(why)

def amount(cores):
    need(cores in LEGAL, "unsupported pool CPU quota")
    return f"{cores * 100000} 100000"

def pin(path, digest):
    stat = path.lstat()
    need(path.resolve(strict=True) == path and stat.st_uid == 0 and stat.st_nlink == 1
         and not stat.st_mode & 0o022, "invalid root evidence " + str(path))
    data = path.read_bytes()
    need(hashlib.sha256(data).hexdigest() == digest, "changed " + str(path))
    return data

def set_pool(cores):
    amount(cores)
    unit = subprocess.check_output(["/usr/bin/systemctl", "show", POOL, "-p", "InvocationID,MainPID"], text=True, timeout=10)
    props = dict(line.split("=", 1) for line in unit.splitlines())
    need(props == {"MainPID": "61054", "InvocationID": "fda0b105c9d64738a7008d613b9c821e"},
         "refusing to change a different pool manager")
    need((CG / POOL / "cpu.max").read_text().strip() in {amount(limit) for limit in LEGAL},
         "refusing to replace a foreign quota")
    subprocess.run(["/usr/bin/systemctl", "set-property", "--runtime", POOL, f"CPUQuota={cores * 100}%"],
                   check=True, timeout=30)

def load():
    pin(CADENCE / "deployment-seal-receipt.json", "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e")
    sys.path.insert(0, str(CADENCE))
    import evidence
    from owners import show
    from retired_public_audit import observe_public
    from idle_audit_cpu import profile
    from public_witness import slice_envelope
    code = READY / "ready-controller.py"
    pin(code, "5a218dae2974b73e0b792ab33e992ba77d6249bd8b2168ca153f89ee0b676f4b")
    pin(READY / "parallel-regions.py", "7ca7068542deeb7adb704875190358e30ae8d033939edb85dd6c9685c33296a3")
    spec = importlib.util.spec_from_file_location("original_ready_controller", code)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    audit_preflight = OUT / "ready_audit_preflight.py"
    pin(audit_preflight, "39629b33437cb7a797d8b2bb6e8bb35a89895db51bf097af1f4ceee852f33419")
    population = runpy.run_path(str(audit_preflight))["main"]
    last = json.loads(pin(OUT / "CPU_BASELINE_END.json", BASELINE))
    first = json.loads(pin(OUT / "CPU_BASELINE_START.json", START))
    need(last["managers"] == first["managers"] and last["scope"] == first["scope"], "changed baseline roster")
    return evidence, show, observe_public, profile, slice_envelope, controller, population, last

def verify_leaf(snapshot, quota):
    exact = snapshot["manager"][POOL]
    need(exact["InvocationID"] == "fda0b105c9d64738a7008d613b9c821e" and exact["MainPID"] == "61054"
         and exact["NRestarts"] == "0" and exact["ActiveState"] == "active" and not exact["Job"]
         and exact["CPUQuotaPerSecUSec"] == f"{quota}s" and snapshot["limits"][POOL]["cpu.max"] == amount(quota),
         "pool manager, kernel quota or invocation changed")
    need(snapshot["parent"] == "idle-twelve" and snapshot["paid_cpu_micros"] == 4_000_000
         and snapshot["limits"][CG.name]["cpu.max"] == "1200000 100000"
         and snapshot["limits"][CG.name]["cpu.idle"] == "1", "idle-only parent entitlement changed")
    need(snapshot["limits"][PRIMARY]["cpu.max"] == "400000 100000"
         and snapshot["limits"][PREFIX]["cpu.max"] == "100000 100000", "other running entitlement changed")
    need(snapshot["retired"]["MainPID"] == snapshot["retired"]["ControlPID"] == "0"
         and snapshot["retired"]["ActiveState"] in ("failed", "inactive")
         and all(not snapshot["retired"][k] for k in ("Job", "ControlGroup", "Triggers", "TriggeredBy")),
         "epoch 144 owner is no longer drained")
    need(snapshot["output_guard"]["ActiveState"] == "active" and snapshot["output_guard"]["SubState"] == "running"
         and snapshot["output_guard"]["MainPID"] != "0" and not snapshot["output_guard"]["Job"],
         "existing output guard is inactive")

def inspect(api, fleet_ref, quota):
    ev, show, actual, profile, envelope, controller, population, baseline = api
    fleet = ev.checked(fleet_ref)
    need(fleet_ref["path"] == str(Path(fleet_ref["path"]).resolve()) and Path(fleet_ref["path"]).parent.parent == RT
         and fleet["owner"] == "/root" and fleet["complete_active_status_count"] == 20
         and fleet["canonical_producer_count"] == len(fleet["actual_executing_replays"]) == 5, "unexpected fleet")
    next_unit = fleet["sole_next_timer"]
    successor = RT / next_unit.removeprefix("horizon-observer-").removesuffix(".timer") / "ROOT_COMPLETE_OPERATIONAL_FLEET.json"
    need(not successor.exists(), "refresh the accepted fleet")
    guard = population(fleet_ref["path"], fleet_ref["sha256"])
    audit, storage, witness = actual(Path("/home/sol").stat().st_dev, fleet["continuing_audit_obligation"])
    jobs = {tuple(row["range"]): row for row in audit["active_ready_workers"]}
    accepted = ev.bound(READY / "accepted/144-144.json")
    need(accepted["sha256"] == "4565e2da06301ac2cc738eaa060af1decb1a50949c9738bbaba02d29c8bccac2"
         and ev.checked(accepted)["exit"]["success"] is True and guard["accepted_ranges"] == [accepted]
         and set(jobs) == {tuple(j["range"]) for j in baseline["jobs"].values()}
         and len(jobs) == len(guard["readers"]) == 11 and not (CG / RETIRED).exists(), "audit population changed")
    for row in baseline["jobs"].values():
        other = jobs[tuple(row["range"])]
        need(all(row[k] == other[k] for k in other), "audit worker replaced")
    limits, managers = {}, {}
    controls = ("cpu.max", "cpu.weight", "cpu.idle", "memory.high", "memory.max", "memory.swap.max", "pids.max")
    for name, original in baseline["managers"].items():
        cg = CG if name == CG.name else CG / name
        observed = show(name, tuple(original))
        expected = dict(original)
        if name == POOL:
            expected["CPUQuotaPerSecUSec"] = f"{quota}s"
        need(observed == expected, "changed unit: " + name)
        managers[name] = observed
        limits[name] = {k: (cg / k).read_text().strip() for k in controls}
        for k, v in limits[name].items():
            expected_value = amount(quota) if name == POOL and k == "cpu.max" else (
                "0" if k == "memory.swap.max" else baseline["groups"][name][k])
            need(v == expected_value, "changed cgroup: " + name + "/" + k)
    # Additional slice children (such as a qualified short build) retain their own existing
    # hierarchy and limits. The parent enforces twelve across all children at every instant.
    retired = show(RETIRED, ("Id", "InvocationID", "MainPID", "ControlPID", "ActiveState", "Job",
                             "TriggeredBy", "Triggers", "ControlGroup"))
    output_guard = show(GUARD, ("Id", "ActiveState", "SubState", "MainPID", "ControlPID", "NRestarts", "Job", "InvocationID"))
    source = controller.current_branch(controller.config())
    exe = controller.config()["elf"]
    need(source["binary"] == exe and all(v["reader"] == exe["path"] for v in jobs.values()), "foreign audit reader")
    producers = {}
    for r in fleet["actual_executing_replays"]:
        unit, timer = r["unit"], r["guard_timer"]
        keys = ("Id", "MainPID", "InvocationID", "ActiveState", "CPUQuotaPerSecUSec", "MemoryMax", "ControlGroup")
        current = show(unit["Id"], keys)
        need(all(current[k] == unit[k] for k in keys if k in unit) and current["ActiveState"] == "active"
             and current["ControlGroup"] == "/system.slice/" + unit["Id"], "producer changed")
        timer_keys = ("Id", "InvocationID", "ActiveState", "Triggers")
        current_timer = show(timer["Id"], timer_keys)
        need(all(current_timer[k] == timer[k] for k in timer_keys) and current_timer["ActiveState"] == "active",
             "producer guard changed")
        producers[str(r["epoch"])] = [current, current_timer]
    result = dict(fleet=fleet_ref, readers=guard["readers"], accepted144=accepted, source=source,
                  controller=witness["controller_file"], ready_output_budget=storage["output_budget"],
                  manager=managers, limits=limits, retired=retired, output_guard=output_guard,
                  paid_cpu_micros=fleet["active_ready_range_audit_obligation"]["additional_cpu_quota_micros"],
                  parent=profile(), parent_witness=envelope(), producers=producers)
    verify_leaf(result, quota)
    return result

def same_work(before, after):
    for key in ("fleet", "readers", "accepted144", "controller", "ready_output_budget", "output_guard",
                "retired", "parent", "parent_witness", "paid_cpu_micros", "producers"):
        need(before[key] == after[key], "work changed across limit update: " + key)
    need(before["source"]["binary"] == after["source"]["binary"], "different qualified reader")
    for group in before["manager"]:
        for what in ("manager", "limits"):
            original, updated = dict(before[what][group]), dict(after[what][group])
            if group == POOL:
                del original["CPUQuotaPerSecUSec" if what == "manager" else "cpu.max"]
                del updated["CPUQuotaPerSecUSec" if what == "manager" else "cpu.max"]
            need(original == updated, "an unrelated unit property changed")

def change_once(before, inspect_changed, change=set_pool):
    verify_leaf(before, OLD_LIMIT)
    try:
        change(NEW_LIMIT)
        after = inspect_changed(NEW_LIMIT)
        same_work(before, after)
    except BaseException:
        change(OLD_LIMIT)
        raise
    return after

def proposed(snapshot):
    copy_ = copy.deepcopy(snapshot)
    copy_["limits"][POOL]["cpu.max"] = amount(NEW_LIMIT)
    copy_["manager"][POOL]["CPUQuotaPerSecUSec"] = "7s"
    return copy_

def fixtures(actual):
    target = proposed(actual)
    calls = []
    def accepted(cores):
        verify_leaf(target, cores)
        return target
    change_once(actual, accepted, calls.append)
    need(calls == [7], "unexpected legal sequence")
    cases = (("foreign pool", ("manager", POOL, "InvocationID"), "wrong"),
             ("manager/kernel mismatch", ("limits", POOL, "cpu.max"), amount(OLD_LIMIT)),
             ("extra funded CPU", ("paid_cpu_micros",), 7_000_000),
             ("normal-priority expansion", ("limits", CG.name, "cpu.idle"), "0"),
             ("144 returned", ("retired", "MainPID"), "1"),
             ("stopped output guard", ("output_guard", "ActiveState"), "failed"),
             ("reader replaced", ("readers", 0, "pid"), 1),
             ("producer changed", ("producers", "166", 0, "MainPID"), "1"),
             ("unexpected memory", ("limits", PRIMARY, "memory.max"), "max"))
    for label, path, value in cases:
        changed = copy.deepcopy(target)
        at = changed
        for key in path[:-1]:
            at = at[key]
        at[path[-1]] = value
        def check(cores):
            verify_leaf(changed, cores)
            return changed
        calls.clear()
        try:
            change_once(actual, check, calls.append)
        except ValueError:
            need(calls == [7, 4], "missing rollback on " + label)
        else:
            raise ValueError("accepted " + label)
    calls.clear()
    def timeout(cores):
        calls.append(cores)
        if cores == 7:
            raise TimeoutError()
    try:
        change_once(actual, accepted, timeout)
    except TimeoutError:
        need(calls == [7, 4], "ambiguous D-Bus response did not restore the original cap")
    return [row[0] for row in cases] + ["ambiguous D-Bus response"]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("qualify", "apply", "rollback", "verify"))
    parser.add_argument("fleet", type=Path)
    parser.add_argument("sha256")
    args = parser.parse_args()
    need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__, "use root python3 -IB")
    api = load()
    ev = api[0]
    fleet = {"path": str(args.fleet), "sha256": args.sha256}
    ev.ensure_dir(OUT)
    fd = ev.lock(OUT / "quota.lock")
    try:
        changed_path = OUT / "TRANSFERRED.json"
        intent_path = OUT / "TRANSFER_INTENT.json"
        if args.operation == "rollback":
            # Restore even if workers, branch, or R2 have changed since qualification.
            intent = ev.checked(ev.bound(intent_path))
            need(intent["before"]["manager"][POOL]["Id"] == POOL, "foreign rollback")
            set_pool(OLD_LIMIT)
            need((CG / POOL / "cpu.max").read_text().strip() == amount(OLD_LIMIT), "rollback was not applied")
            print("Restored four-core child quota")
            return
        q = 7 if args.operation == "verify" else 4
        if args.operation == "apply" and intent_path.exists() and (CG / POOL / "cpu.max").read_text().strip() == amount(NEW_LIMIT):
            q = 7
        before = inspect(api, fleet, q)
        if args.operation == "qualify":
            cases = fixtures(before)
            record = dict(schema="horizon-ready-pool-cpu-qualified-v1", before=before, proposed=proposed(before),
                          tested_rejections=cases, kernel_properties_changed=False, operator=ev.bound(Path(__file__)))
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            p = OUT / f"QUALIFIED-{stamp}.json"
            ev.durable(p, record)
            print(json.dumps(ev.bound(p)))
        elif args.operation == "verify":
            need(changed_path.exists(), "transfer not committed")
            print(json.dumps({"quota": 7, "live_readers": len(before["readers"]), "source": before["source"]}))
        else:
            evidence = sorted(OUT.glob("QUALIFIED-*.json"), reverse=True)
            need(any(ev.checked(ev.bound(path))["operator"] == ev.bound(Path(__file__)) for path in evidence),
                 "no successful preflight for this operator")
            if not intent_path.exists():
                need(q == 4 and not changed_path.exists(), "unowned transfer")
                ev.durable(intent_path, dict(schema="horizon-ready-pool-cpu-intent-v1", before=before, operator=ev.bound(Path(__file__))))
            original = ev.checked(ev.bound(intent_path))
            need(original["operator"] == ev.bound(Path(__file__)), "different transfer owner")
            if q == 7:
                same_work(original["before"], before)
                after = before
            else:
                same_work(original["before"], before)
                after = change_once(before, lambda n: inspect(api, fleet, n))
            if not changed_path.exists():
                ev.durable(changed_path, dict(schema="horizon-ready-pool-cpu-transfer-v1", intent=ev.bound(intent_path),
                                              applied_utc=datetime.now(timezone.utc).isoformat(), after=after))
            print(json.dumps(ev.bound(changed_path)))
    finally:
        os.close(fd)

if __name__ == "__main__":
    main()
