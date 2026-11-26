"""Prepare epoch 170 guard records from the sealed review and PID 1 evidence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
ROOT = RUNTIME / "epoch170-full-metered-rebook-20261124-v1"
EVIDENCE = RUNTIME / "prefix140-status-cadence-20261122-v1/cadence-tools"
RECEIVER = RUNTIME / "survivor172-cadence-20261122-v1/tools-cold168-retry4-failed166-v7-entry146"
CADENCE = RECEIVER.parent
V13 = CADENCE / "tools-cold168-retry5-failed166-v13-entry146"
V12_OWNER_SHA = "b42e7b3c5327438cd355357f73f2574c05ffbd67fd9597aa7d05c17f8324cc54"
V13_RECEIVER_SHA = "4ec9ca4476a6e8ed21090e9dfeb58582916b00610f5145a9181a8cadc0dbb695"
V13_WRITER_SHA = "3d2401bb1bfe9a65f68503c2feca30c0630ea876ad04fa01d1a6a5eda374e8ab"
POST_BUILD = RUNTIME / "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5z-build-v1"
PREDECESSOR = RUNTIME / "epoch170-retry10-recovery-20261121-v1/guard-receipts/stop-completion.json"
PREDECESSOR_SHA = "d670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a"
PLAN = ROOT / "ACTUAL_GUARD_PLAN.json"
OWNER_FIELDS = ("Id", "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState", "Job",
                "NRestarts", "MemoryMax", "CPUQuotaPerSecUSec", "MemorySwapMax")
TIMER_FIELDS = ("Id", "InvocationID", "ActiveState", "SubState", "Triggers", "Job",
                "Requisite", "After", "StopPropagatedFrom")
V13_DRAINED_PHASES = (
    "v9-semantic-complete-drained",
    "v10-semantic-complete-drained",
    "independent-semantic-complete-v10-drained",
)

sys.path.insert(0, str(EVIDENCE))
from evidence import bound, checked, need


def reference(path, digest):
    return {"path": str(path), "sha256": digest}


def sealed_module(package, seal_digest, name):
    seal = checked(reference(package / "deployment-seal-receipt.json", seal_digest))
    row, = (member for member in seal["members"] if member["name"] == name and member["mode"] == "0444")
    path = package / name
    need(seal["destination"] == str(package) and bound(path)["sha256"] == row["sha256"], "foreign guard module")
    return runpy.run_path(str(path))


def v13_writer(price, enrollment):
    from owners import show, ticks

    status = price["status_registration"]
    incumbent = enrollment["incumbent"]
    active_ref = enrollment["incumbent_registration"]
    need(active_ref["path"] == str(CADENCE / "FAILED166_CADENCE_V13_ACTIVE.json")
         and status["consumer_seal"]["path"] == str(V13 / "deployment-seal-receipt.json"),
         "current cadence cannot adopt the held full epoch 170 worker")
    active = checked(active_ref)
    ready = checked(active["ready"])
    seal = checked(status["consumer_seal"])
    actor = active["new"]
    previous_ref = reference(CADENCE / "FAILED166_CADENCE_V12_ACTIVE.json", V12_OWNER_SHA)
    previous = checked(previous_ref)["new"]
    receiver = reference(V13 / "full170_status.py", V13_RECEIVER_SHA)
    program = reference(V13 / "status_cycle.py", V13_WRITER_SHA)
    member, = (row for row in seal["members"] if row["name"] == "full170_status.py")
    need(active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1"
         and active["producer_mutations"] is False
         and active["ready"]["path"] == str(CADENCE / "FAILED166_CADENCE_V13_READY.json")
         and ready["package"] == status["consumer_seal"]
         and ready["old_owner"] == previous_ref and active["old"] == previous
         and actor["invocation_id"] != previous["invocation_id"] and actor["start_ticks"] > previous["start_ticks"]
         and all(actor["lock"][key] == previous["lock"][key] for key in ("path", "device", "inode"))
         and ready["full170_receiver"] == bound(V13 / "full170_status.py") == receiver
         and seal["destination"] == str(V13)
         and member["mode"] == "0444" and member["sha256"] == V13_RECEIVER_SHA
         and incumbent["program"] == bound(V13 / "status_cycle.py") == program
         and actor["program"] == program["path"]
         and all(status[key] == incumbent[key] == actor[key] for key in ("invocation_id", "pid", "start_ticks")),
         "different V13 receiver or enrolled writer")
    unit = "horizon-archive-status-cadence-after172-20261120-v1.service"
    manager = show(unit, ("Id", "InvocationID", "MainPID", "ActiveState", "NRestarts", "Job"))
    need(actor["unit"] == unit and manager == dict(
        Id=unit, InvocationID=actor["invocation_id"], MainPID=str(actor["pid"]),
        ActiveState="active", NRestarts="0", Job="") and ticks(actor["pid"]) == actor["start_ticks"],
         "V13 writer changed before the epoch 170 transition")


def protected_retry5(price, now):
    owner = price.get("full170_retry5_owner")
    if owner is None:
        return
    from owners import show, ticks

    peer = price["replacements"]["168"]
    sample_path = Path(peer["guard"]["path"])
    sample = checked(peer["guard"])
    unit = "horizon-qualify-168-full-metered-cold-v5-20261125.service"
    timer = "horizon-guard-168-full-metered-cold-v5-20261125.timer"
    producer, worker = owner["processes"]
    manager = show(unit, ("Id", "InvocationID", "MainPID", "ActiveState", "NRestarts", "Job"))
    current = show(timer, ("Id", "InvocationID", "ActiveState", "Job"))
    need(owner["producer_unit"] == unit and owner["timer"] == timer
         and manager == dict(Id=unit, InvocationID=owner["producer_invocation_id"],
                             MainPID=str(producer[0]), ActiveState="active", NRestarts="0", Job="")
         and current == dict(Id=timer, InvocationID=owner["timer_invocation_id"], ActiveState="active", Job="")
         and all(ticks(process[0]) == process[1] for process in (producer, worker))
         and sample["producer_invocation_id"] == owner["producer_invocation_id"]
         and sample["plan_sha256"] == owner["plan"]["sha256"]
         and sample["minimum_free_bytes"] == owner["floor"]
         and sample["producer_stop_enabled"] and sample["trip_reason"] is None
         and [row[0] for row in sample["workers"]] == [worker[0]]
         and 0 <= now - sample["recorded_unix_seconds"] <= 90
         and not any(sample_path.parent.glob("stop-*.json")),
         "retry5 producer or protective guard changed before the epoch 170 transition")


def start_intent(route, review_ref):
    review = checked(review_ref)
    profile = review["profile"]
    enrollment = checked(review["observer"])
    price = checked(review["price"])
    fleet_ref = profile["observer"]["active_fleet"]["fleet"]
    fleet = checked(fleet_ref)
    anchor, _, _ = route["generation"]()
    need(review["schema"] == "horizon-epoch170-metered-preflight-review-v1"
         and review["replay_launch_authorized"] is review["archive_publication_authorized"] is False
         and price["epoch"] == 170 and price["fits"] is True and price["resource_credit_bytes"] == 0
         and price["fleet"] == fleet_ref == enrollment["fleet"]
         and price["epoch170_metered_full"]["stage"] == "prestart"
         and price["epoch170_metered_full"]["observer_enrollment"] == review["observer"]
         and review["guard"]["root"] == anchor
         and review["observer"]["path"] == str(ROOT / f"OBSERVER_ENROLLMENT-{fleet_ref['sha256']}.json")
         and profile["actor"]["unit"] == route["UNIT"]
         and not os.path.lexists(route["PERMIT"]), "epoch 170 start basis differs")
    if price.get("phase145", {}).get("stage") in V13_DRAINED_PHASES:
        v13_writer(price, enrollment)
    protected_retry5(price, time.time())
    predecessor = bound(PREDECESSOR)
    need(predecessor["sha256"] == PREDECESSOR_SHA, "original epoch 170 stop proof changed")
    return dict(schema="horizon-170-full-metered-start-intent-v1", epoch=170, fleet=fleet_ref,
                prepared=review_ref, prestart=review["price"], stable_root=anchor,
                producer_unit=route["UNIT"], timer_unit=route["TIMER"], predecessor_stop=predecessor,
                armed_floor=price["protected_raw_floor_bytes"], authenticated_inventory=fleet["authenticated_inventory"],
                recorded_unix_seconds=int(time.time()), resource_credit_bytes=0)


def held_owner(route):
    current = route["native"](OWNER_FIELDS)
    need(current is not None, "no native epoch 170 hold")
    _, actor = current
    need(route["held"]({"actor": actor}) and not os.path.lexists(route["PERMIT"]),
         "native epoch 170 producer has left its hold")
    return actor


def guard_plan(route, actor, intent, qualification):
    return dict(schema="jetstreamer-horizon-standalone-guard-plan-v1", unit=route["UNIT"],
                invocation_id=actor["producer_invocation_id"], filesystem="/home/sol",
                minimum_free_bytes=intent["armed_floor"], worker_root=str(route["LANE"]),
                receipt_directory=str(ROOT / "guard-receipts"), maximum_root_physical_bytes=route["CAP"],
                maximum_worker_vmas=3_500_000, data_fulfillment=qualification["contract"])


def guard_argv(route, plan_ref, qualification):
    producer = route["UNIT"]
    service = route["TIMER"].removesuffix(".timer") + ".service"
    image = qualification["guard"]
    argv = [image["path"], plan_ref["path"], "--plan-sha256", plan_ref["sha256"],
            "--self-sha256", image["sha256"]]
    return [
        "/usr/bin/systemd-run", "--unit=" + service,
        "--on-active=1s", "--on-unit-inactive=5s", "--timer-property=AccuracySec=1s",
        "--timer-property=RemainAfterElapse=no", "--timer-property=Requisite=" + producer,
        "--timer-property=After=" + producer, "--timer-property=StopPropagatedFrom=" + producer,
        "--property=User=root", "--property=Group=root", "--property=UMask=0077", "--property=Restart=no",
        "--property=MemoryMax=1073741824", "--property=MemorySwapMax=0", "--property=CPUQuota=25%",
        "--property=TasksMax=256", "--property=TimeoutStartSec=2min", "--property=TimeoutStopSec=15s",
        "--property=PrivateNetwork=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes", "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_KILL CAP_SYS_PTRACE",
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_KILL CAP_SYS_PTRACE",
        f"--property=ReadWritePaths={ROOT / 'guard-receipts'}",
        f"--property=StandardOutput=append:{ROOT / 'guard.stdout'}",
        f"--property=StandardError=append:{ROOT / 'guard.stderr'}", "--property=Type=oneshot", *argv,
    ]


def guard_proof(route, native, actor, plan_ref, sample_path):
    sample_ref = bound(sample_path)
    sample = checked(sample_ref)
    iid = sample["guard_invocation_id"]
    need(re.fullmatch(r"[0-9a-f]{32}", iid)
         and sample_path == ROOT / "guard-receipts" / f"sample-{iid}.json",
         "foreign epoch 170 guard sample path")
    timer = native["properties"](route["TIMER"], *TIMER_FIELDS)
    service = route["TIMER"].removesuffix(".timer") + ".service"
    need(timer["Id"] == route["TIMER"] and timer["ActiveState"] == "active"
         and timer["SubState"] == "waiting" and not timer["Job"]
         and re.fullmatch(r"[0-9a-f]{32}", timer["InvocationID"]) and timer["Triggers"] == service
         and all(route["UNIT"] in timer[key].split() for key in ("Requisite", "After", "StopPropagatedFrom")),
         "epoch 170 guard timer is outside its producer scope")
    proof = dict(guard_invocation=iid, receipt=sample_ref, timer=timer)
    validated = route["actual_guard"](actor, proof, plan_ref)
    need(0 <= time.time() - validated["recorded_unix_seconds"] <= 120, "epoch 170 guard sample is stale")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    events = native["pid1"](service, iid, boot, (native["SUCCESS"], native["FAILURE"], native["EXIT"]))
    need(len(events) == 1 and events[0]["MESSAGE_ID"] == native["SUCCESS"]
         and int(events[0]["__REALTIME_TIMESTAMP"]) // 1_000_000 >= validated["recorded_unix_seconds"],
         "epoch 170 guard lacks exact PID 1 success")
    need(native["properties"](route["TIMER"], *TIMER_FIELDS) == timer, "epoch 170 guard timer changed")
    return proof, validated


def first_proof(route, native, actor, plan_ref, sample_path):
    proof, sample = guard_proof(route, native, actor, plan_ref, sample_path)
    need(not sample["workers"] and held_owner(route) == actor, "first epoch 170 guard is outside the hold")
    return proof


def release_record(route, actor, intent, plan_ref, first_ref, post_ref, boot, now):
    post = checked(post_ref)
    pre = checked(intent["prestart"])
    stage = post["epoch170_metered_full"]
    book = post["bookings"]["170"]
    candidate = post["candidate"]
    intent_ref = bound(ROOT / "START_INTENT.json")
    guard = stage["first_guard"]
    floor = intent["armed_floor"]
    need(post["schema"] == "horizon-incident-replay-fit-v1"
         and post["epoch"] == 170 and post["fits"] is True and post["replay_launch_authorized"] is False
         and post["resource_credit_bytes"] == stage["resource_credit_bytes"] == 0
         and post["fleet"] == intent["fleet"] and pre["phase145"] == post["phase145"]
         and 0 <= now - post["recorded_unix_seconds"] <= 120
         and stage["stage"] == "post-guard" and stage["boot_id"] == boot
         and stage["start_intent"] == intent_ref and stage["prestart"] == intent["prestart"]
         and stage["worker_sha256"] == route["WORKER_SHA"]
         and all(candidate[key] == stage[key] == value for key, value in actor.items())
         and guard["first_guard"] == first_ref and guard["actual_guard_plan"] == plan_ref
         and book["root"] == str(route["LANE"]) and book["run"] == str(route["RUN"])
         and 0 < book["remaining_bytes"] == route["CAP"] - book["physical_bytes"]
         and book["cap_bytes"] == route["CAP"]
         and stage["candidate_repriced_floor_bytes"] <= post["protected_raw_floor_bytes"] == floor
         and post["available_HOME_bytes"] >= post["complete_required_HOME_bytes"] == floor + book["remaining_bytes"]
         and post["available_memory_bytes"] >= post["required_available_memory_bytes"],
         "epoch 170 release lacks a fresh positive post-guard quote for this hold")
    if pre["phase145"].get("stage") in V13_DRAINED_PHASES:
        enrollment_ref = pre["epoch170_metered_full"]["observer_enrollment"]
        need(post["status_registration"] == pre["status_registration"]
             and stage["observer_enrollment"] == enrollment_ref,
             "epoch 170 post-guard quote changed the enrolled V13 writer")
        v13_writer(post, checked(enrollment_ref))
    need(post.get("full170_retry5_owner") == pre.get("full170_retry5_owner"),
         "retry5 ownership differs between epoch 170 prestart and post-guard prices")
    protected_retry5(post, now)
    return dict(actor, intent=intent_ref, actual_guard_plan=plan_ref, first_guard=first_ref,
                post_guard_capacity=post_ref, transaction_replay_claimed=False)


def released_owner(route):
    state = route["native"](OWNER_FIELDS)
    need(state is not None and not route["held"]({"actor": state[1]}), "epoch 170 has no released producer")
    return state


def admission_record(route, native, actor):
    intent, _, _ = route["intent"]()
    authorization = checked(bound(ROOT / "AUTHORIZED_GATED_PAYLOAD.json"))
    first = checked(authorization["first_guard"])
    timer = native["properties"](route["TIMER"], "Id", "ActiveState", "InvocationID", "Triggers", "Job")
    need(all(authorization[key] == value for key, value in actor.items())
         and timer["Id"] == route["TIMER"] and timer["ActiveState"] == "active" and not timer["Job"]
         and timer["InvocationID"] == first["timer"]["InvocationID"]
         and timer["Triggers"] == route["TIMER"].removesuffix(".timer") + ".service",
         "epoch 170 admission lost the authorized producer or guard timer")
    return dict(authorization, schema="horizon-170-full-metered-admission-v1", epoch=170,
                stage="node", bootstrap_only=True, fleet=intent["fleet"], stable_root=intent["stable_root"],
                predecessor_stop=intent["predecessor_stop"], source=intent["prepared"],
                timer_unit=route["TIMER"], timer_invocation_id=first["timer"]["InvocationID"], resource_credit_bytes=0)


def worker_record(route, native, state, sample_path):
    _, actor = state
    admission = bound(ROOT / "ACTUAL_ADMISSION_AND_PROTECTION.json")
    expected = admission_record(route, native, actor)
    need(checked(admission) == expected, "different epoch 170 admission")
    proof, sample = guard_proof(route, native, actor, expected["actual_guard_plan"], sample_path)
    need(len(sample["workers"]) == 1 and proof["timer"]["InvocationID"] == expected["timer_invocation_id"],
         "guard has no single protected epoch 170 worker under the admitted timer")
    pid, _ = sample["workers"][0]
    proc = Path("/proc") / str(pid)
    ticks = proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()
    ancestry = proc.joinpath("cgroup").read_text().strip()
    handle = proc / "exe"
    worker = handle.readlink()
    scratch, = (parent.parent for parent in worker.parents if parent.name == ".historical-runtime")
    need(ancestry == "0::" + route["GROUP"] and int(ticks[1]) == actor["producer_pid"]
         and int(ticks[19]) > actor["start_ticks"] and worker.name == "historical-worker"
         and scratch.name == "scratch" and scratch.is_relative_to(route["RUN"] / "private"),
         "epoch 170 worker is outside the admitted replay tree")
    with handle.open("rb") as image:
        identity = os.fstat(image.fileno())
        digest = hashlib.file_digest(image, "sha256").hexdigest()
    need(digest == route["WORKER_SHA"] and os.path.samestat(identity, handle.stat())
         and handle.samefile(worker) and proc.joinpath("stat").read_text().rsplit(")", 1)[1].split()[19] == ticks[19]
         and released_owner(route) == state, "protected epoch 170 worker changed")
    _, _, candidate = route["intent"]()
    row = dict(range="170", controller_unit=route["UNIT"], producer_unit=route["UNIT"],
               expected_controller_invocation_id=actor["producer_invocation_id"],
               expected_producer_invocation_id=actor["producer_invocation_id"], scratch_path=str(scratch),
               append_log=route["append_identity"](candidate, Path("/proc") / str(actor["producer_pid"])),
               worker_executable_basename=worker.name)
    return dict(actor, schema="horizon-170-full-metered-first-protected-worker-v1", epoch=170, stage="worker",
                admission=admission, worker_guard=proof, worker_pid=pid, worker_start_ticks=int(ticks[19]),
                worker_exe_device=identity.st_dev, worker_exe_inode=identity.st_ino,
                worker_sha256=digest, observer_row=row, measured_transaction_replay=False)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="operation", required=True)
    start = sub.add_parser("start-intent")
    start.add_argument("review", type=Path)
    start.add_argument("review_sha256")
    sub.add_parser("plan")
    sub.add_parser("arm-argv")
    first = sub.add_parser("first-guard")
    first.add_argument("sample", type=Path)
    sub.add_parser("release-record")
    sub.add_parser("permit")
    sub.add_parser("admission")
    worker = sub.add_parser("worker")
    worker.add_argument("sample", type=Path)
    args = cli.parse_args()
    try:
        need(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, "run as root with python3 -IB")
        route = sealed_module(RECEIVER, "c1b777be3164beca0db8afc9777a02bbbd8f7babc09acf063acb00297cd51504", "full170_status.py")
        if args.operation == "start-intent":
            result = start_intent(route, reference(args.review, args.review_sha256))
        elif args.operation in ("admission", "worker"):
            native = sealed_module(POST_BUILD, "8e48c19a738a9ff4586c10fd4c7581b5c2a01133b5de5edbae8b7e26e241d4ea",
                                   "hourly170_actor.py")
            state = released_owner(route)
            if args.operation == "admission":
                result = admission_record(route, native, state[1])
            else:
                result = worker_record(route, native, state, args.sample)
        else:
            actor = held_owner(route)
            intent, _, _ = route["intent"]()
            _, _, qualification = route["generation"]()
            result = guard_plan(route, actor, intent, qualification)
            if args.operation != "plan":
                plan_ref = bound(PLAN)
                need(checked(plan_ref) == result, "epoch 170 guard plan differs from its current hold")
                if args.operation == "arm-argv":
                    result = guard_argv(route, plan_ref, qualification)
                    guard_args = result[result.index(qualification["guard"]["path"]):]
                    subprocess.run([*guard_args, "--validate-plan-only"], check=True, capture_output=True, timeout=30)
                else:
                    native = sealed_module(POST_BUILD, "8e48c19a738a9ff4586c10fd4c7581b5c2a01133b5de5edbae8b7e26e241d4ea",
                                           "hourly170_actor.py")
                    if args.operation == "first-guard":
                        result = first_proof(route, native, actor, plan_ref, args.sample)
                    else:
                        first_ref = bound(ROOT / "FIRST_GUARD.json")
                        first = checked(first_ref)
                        need(first == first_proof(route, native, actor, plan_ref, Path(first["receipt"]["path"])),
                             "epoch 170 first guard changed before release")
                        post_ref = bound(ROOT / "POST_GUARD_CAPACITY.json")
                        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                        result = release_record(route, actor, intent, plan_ref, first_ref, post_ref, boot, time.time())
                        if args.operation == "permit":
                            need(result == checked(bound(ROOT / "AUTHORIZED_GATED_PAYLOAD.json")),
                                 "epoch 170 permit lacks the sealed release record")
                            need(held_owner(route) == actor, "epoch 170 hold changed before the permit")
                            sys.stdout.write(actor["producer_invocation_id"])
                            return
        print(json.dumps(result, sort_keys=True))
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
        cli.exit(1, f"{exc}\n")


if __name__ == "__main__":
    main()
