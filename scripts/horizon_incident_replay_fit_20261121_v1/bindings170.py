"""Bind the epoch 170 hold, first guard, and release to one real invocation."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import time

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RUNTIME / "epoch170-metered-hourly-20261124-v1"
FIT = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-170-metered-hourly-v7"
FIT_SEAL = "8442e17a4055d37b0a039764bacc0cc1785e408c2be95b1570cf46fc4032d094"
OBSERVER = RUNTIME / "survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v2"
OBSERVER_SEAL = "2cd5d8ca7ff607ececb36101e06ca0985c5dd88a906fd4a9d8b09b7eeb9d4c1d"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def runtime():
    need(os.geteuid() == 0, "epoch 170 admission evidence requires root")
    for package, expected in ((FIT, FIT_SEAL), (OBSERVER, OBSERVER_SEAL)):
        receipt = package / "deployment-seal-receipt.json"
        raw = receipt.read_bytes()
        need(hashlib.sha256(raw).hexdigest() == expected, "different package seal")
        seal = json.loads(raw)
        need(seal["destination"] == str(package) and package.stat().st_uid == 0
             and not package.stat().st_mode & 0o222, "unsafe package path")
        for row in seal["members"]:
            path = package / row["name"]
            md = path.lstat()
            need(path.resolve(strict=True) == path and stat.S_ISREG(md.st_mode)
                 and md.st_uid == 0 and not md.st_mode & 0o222
                 and hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"],
                 f"changed sealed member {path}")
    provider = runpy.run_path(str(FIT / "post-stop-fit"), run_name="hourly170_bindings_provider")
    route = provider["hourly170"]
    contract = route["ready_contract"]()
    launcher = ROOT / "sealed/diagnostic170.py"
    diagnostic = runpy.run_path(str(launcher), run_name="hourly170_bindings_diagnostic")
    need(provider["HOURLY170_CADENCE"] and route["UNIT"] == diagnostic["UNIT"],
         "different metered epoch 170 route")
    return provider, route, contract, diagnostic


def staged_paths(route, contract):
    staged, ref = route["sealed"](ROOT / "PREPARED_BIND_PATHS.json")
    need(staged["schema"] == "horizon-epoch170-sealed-diagnostic-bind-paths-v1"
         and staged["inputs"] == contract["ready"] and staged["allow_absent"]
         and not staged["producer_launched"], "foreign epoch 170 staged mount receipt")
    for member in [*staged["targets"], staged["log"]]:
        path = Path(member["path"])
        md = path.lstat()
        need(path.resolve(strict=True) == path and
             (md.st_dev, md.st_ino, md.st_uid, md.st_gid, stat.S_IMODE(md.st_mode)) ==
             (member["device"], member["inode"], member["uid"], member["gid"], member["mode"]),
             f"changed epoch 170 staging inode {path}")
    need(not route["GRANT"].exists(), "epoch 170 barrier already released")
    return staged, ref


def positive_prestart(provider, route, contract):
    path = ROOT / "PRESTART.json"
    try:
        pre, ref = route["sealed"](path)
    except FileNotFoundError as exc:
        if exc.filename != str(path):
            raise
        raise ValueError(f"missing epoch 170 prestart quote: {path}") from None
    proposal = pre["hourly170_diagnostic"]
    need(pre["schema"] == "horizon-incident-replay-fit-v1"
         and pre["fits"] is True and pre["replay_launch_authorized"] is False
         and pre["resource_credit_bytes"] == 0 and pre["phase145"]["stage"] == "v5u-drained"
         and 0 <= time.time() - pre["recorded_unix_seconds"] <= 180
         and proposal["stage"] == "prestart"
         and proposal["inputs_ready"] == contract["ready"] and proposal["inputs"] == contract["inputs"]
         and proposal["resource_fit"] is True and proposal["launch_compatible"] is True
         and proposal["retained_booking_bytes"] == route["CAP"]
         and proposal["private_growth_bytes"] == route["GROWTH"]
         and all(proposal[k] == 0 for k in ("additive_charge_bytes", "additive_memory_bytes",
                                           "additive_cpu_quota_micros")),
         "no fresh, funded held epoch 170 prestart")
    fleet, _ = provider["fleet_head"](pre["fleet"])
    current = provider["registered_status"]()
    need(current == pre["status_registration"]
         and current["consumer_seal"] == dict(path=str(OBSERVER / "deployment-seal-receipt.json"),
                                              sha256=OBSERVER_SEAL),
         "epoch 170 needs the live diagnostic-aware fleet monitor")
    route["drained145"](provider["s"], provider["fit"])
    return pre, ref, proposal, fleet


def held_owner(provider, route, contract, diagnostic, staged):
    unit = route["UNIT"]
    fields = ("Id", "ActiveState", "SubState", "MainPID", "ControlPID", "Job", "NRestarts",
              "InvocationID", "ControlGroup", "FragmentPath", "CPUQuotaPerSecUSec",
              "MemoryMax", "MemoryHigh", "MemorySwapMax", "TasksMax", "User", "Group")
    manager = route["properties"](unit, *fields)
    iid = manager["InvocationID"]
    pid = int(manager["MainPID"])
    limits = route["ACTOR"]
    need(manager["Id"] == unit and manager["ActiveState"] == "active" and manager["SubState"] == "running"
         and manager["ControlGroup"] == route["CGROUP"] and not manager["Job"]
         and manager["ControlPID"] == manager["NRestarts"] == "0" and pid > 1 and route["digest"](iid, 32)
         and manager["CPUQuotaPerSecUSec"] == "3s" and int(manager["MemoryMax"]) == limits["memory_max"]
         and int(manager["MemoryHigh"]) == limits["memory_high"] and manager["MemorySwapMax"] == "0"
         and int(manager["TasksMax"]) == limits["tasks_max"]
         and (manager["User"], manager["Group"]) == ("sol", "horizon"),
         "different held epoch 170 limits or systemd owner")
    route["sealed"](Path(manager["FragmentPath"]), contract["service"]["sha256"], read=False)
    proc = Path(f"/proc/{pid}")
    expected = ["/usr/bin/python3", "-IB", str(route["ALIAS"] / "diagnostic170.py"),
                "run", contract["inputs"]["sha256"]]
    _, ticks, group = provider["s"].process(pid)
    need(provider["fit"].members(unit) == (pid,) and group == "0::" + route["CGROUP"]
         and os.path.samefile(proc / "exe", "/usr/bin/python3") and route["process_argv"](pid) == expected,
         "epoch 170 is outside its one-process hold")
    log = Path(staged["log"]["path"])
    with log.open("rb") as stream:
        md = os.fstat(stream.fileno())
        line = stream.readline(4097)
        need(0 < len(line) <= 4096 and line.endswith(b"\n"), "missing held epoch 170 log binding")
    event = json.loads(line)
    need(event == dict(phase="await-first-guard-and-post-fit", invocation_id=iid, pid=pid, start_ticks=ticks)
         and (md.st_dev, md.st_ino) == (staged["log"]["device"], staged["log"]["inode"])
         and os.path.samestat(md, log.stat())
         and all(os.path.samefile(proc / "fd" / key, log) for key in ("1", "2")),
         "held epoch 170 append log differs")
    need(diagnostic["UNIT"] == unit and not route["GRANT"].exists()
         and route["properties"](unit, *fields) == manager,
         "epoch 170 owner changed during observation")
    return dict(invocation_id=iid, pid=pid, start_ticks=ticks, log_device_inode=[md.st_dev, md.st_ino])


def plan_and_owner(provider, route, contract, diagnostic, proposal):
    staged, _ = staged_paths(route, contract)
    held = held_owner(provider, route, contract, diagnostic, staged)
    plan = diagnostic["guard_plan"](held["invocation_id"], proposal["protected_raw_floor_bytes"],
                                    proposal["baseline_physical_bytes"])
    return plan, held


def first_intent(provider, route, contract, diagnostic, pre, ref, proposal, sample_path):
    plan, held = plan_and_owner(provider, route, contract, diagnostic, proposal)
    current, plan_ref = route["sealed"](route["PLAN"])
    need(current == plan, "different sealed epoch 170 guard plan")
    guard, sample_ref = route["sealed"](sample_path)
    need(sample_path == ROOT / "guard-receipts" / f"sample-{guard['guard_invocation_id']}.json",
         "different native epoch 170 timer receipt")
    diagnostic["validate_guard"](plan, plan_ref["sha256"], guard, held["pid"])
    timer = route["properties"](route["TIMER"], "Id", "ActiveState", "InvocationID", "Triggers", "Job",
                                "Requisite", "After", "StopPropagatedFrom")
    need(timer["Id"] == route["TIMER"] and timer["ActiveState"] == "active" and not timer["Job"]
         and route["digest"](timer["InvocationID"], 32) and timer["Triggers"] == route["GUARD_SERVICE"]
         and all(route["UNIT"] in timer[k].split() for k in ("Requisite", "After", "StopPropagatedFrom")),
         "different epoch 170 protective timer")
    proposal_actor = dict(first=sample_ref, iid=held["invocation_id"], native_plan=plan,
                          plan=plan_ref, baseline=proposal["baseline_physical_bytes"],
                          processes=[[held["pid"], held["start_ticks"]]])
    proof = route["sample"](contract, proposal_actor, "post-guard")
    need(proof["receipt"] == sample_ref, "different first native epoch 170 guard")
    return dict(schema="horizon-epoch170-hourly-held-intent-v1", unit=route["UNIT"], **held,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                fleet=pre["fleet"], prestart=ref, inputs_ready=contract["ready"], inputs=contract["inputs"],
                service=contract["service"], guard_plan=plan_ref, first_guard=sample_ref,
                timer_iid=timer["InvocationID"], diagnostic_only=True, reservation_ending_bytes=0)


def grant(provider, route, contract, diagnostic, pre, fleet):
    intent, intent_ref = route["sealed"](route["INTENT"])
    post, post_ref = route["sealed"](route["POST"])
    context = post["hourly170_diagnostic"]
    now = int(time.time())
    need(post["fits"] is True and post["replay_launch_authorized"] is False
         and post["fleet"] == pre["fleet"] and post["status_registration"] == pre["status_registration"]
         and context["stage"] == "post-guard" and context["launch_compatible"] is True
         and context["resource_fit"] is True
         and context["inputs"] == contract["inputs"] and context["intent"] == intent_ref
         and context["receipt"] == intent["first_guard"] and 0 <= now - post["recorded_unix_seconds"] <= 90,
         "no fresh positive quote for the held epoch 170 invocation")
    actor = route["owner"](provider["s"], provider["fit"], contract, fleet, pre["fleet"], None, "post-guard")
    current_guard = route["sample"](contract, actor, "post-guard")
    need(actor["intent"] == intent_ref and current_guard["receipt"] == context["receipt"],
         "epoch 170 actor or guard changed after pricing")
    result = dict(schema="horizon-epoch170-metered-hourly-postguard-release-v1", unit=route["UNIT"],
                  invocation_id=intent["invocation_id"], pid=intent["pid"], start_ticks=intent["start_ticks"],
                  boot_id=intent["boot_id"], issued_unix_seconds=now, inputs_sha256=contract["inputs"]["sha256"],
                  native_post_guard_fit_sha256=post_ref["sha256"], guard_plan_sha256=intent["guard_plan"]["sha256"],
                  first_guard_sha256=intent["first_guard"]["sha256"], log_device_inode=intent["log_device_inode"],
                  retained_booking_bytes=route["CAP"], private_growth_bytes=route["GROWTH"],
                  archive_publication_authorized=False, resource_credit_bytes=0)
    diagnostic["validate_grant"](result, contract["inputs"]["sha256"], intent["invocation_id"],
                                 intent["pid"], intent["start_ticks"], intent["boot_id"], time.time())
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("check", "guard-plan", "guard-argv", "grant"):
        sub.add_parser(action)
    sub.add_parser("first").add_argument("sample", type=Path)
    args = parser.parse_args()
    provider, route, contract, diagnostic = runtime()
    if args.action == "check":
        _, staged = staged_paths(route, contract)
        result = dict(inputs=contract["ready"], staged=staged, release_issued=False)
    else:
        pre, ref, proposal, fleet = positive_prestart(provider, route, contract)
        if args.action == "first":
            result = first_intent(provider, route, contract, diagnostic, pre, ref, proposal, args.sample)
        elif args.action == "grant":
            result = grant(provider, route, contract, diagnostic, pre, fleet)
        else:
            plan, _ = plan_and_owner(provider, route, contract, diagnostic, proposal)
            result = plan
            if args.action == "guard-argv":
                saved, plan_ref = route["sealed"](route["PLAN"])
                need(saved == plan, "different sealed epoch 170 guard plan")
                result = diagnostic["guard_command"](route["PLAN"], plan_ref["sha256"])
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
