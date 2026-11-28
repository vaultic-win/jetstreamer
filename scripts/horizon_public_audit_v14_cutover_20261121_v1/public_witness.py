"""Read-only public audit observation. The original audit's final receipt stays historical."""
import os
from owners import show
import time
from pathlib import Path
import audit_handoff as native
from evidence import BASE, bound, checked, content, need

ROOT = BASE / "public-stream-observer-handoff-20261120-v1"
PUBLIC = BASE / "r2-audit-storage-20261119-v1/state/public-stream-v1"
STOP = ROOT / "OLD_AUDIT_STOPPED.json"

SUCCESSOR = BASE / "public-stream-observer-continuity-20261120-v1"
PREVIOUS_DIGEST = "8f2a5f9edfa0132a2f95a0ef1c73b1905443a0182ae9715c3dba142812844099"
SUCCESSOR_SEAL = "2bbc2bc89b6dcc12cad8442f0632b9910babe08ad1206ab64ad1a2f37f30b67b"
SLICE = "horizonaudit.slice"
NEXT_CGROUP = "/" + SLICE + "/" + native.UNIT

V14 = BASE / "public-audit73-observer-20261121-v1"
V13_OWNER_SHA = "1990f8fe2c1c215586ad7c54980d2278ff937ce658588b5f6d321cd63ba04851"
V14_PACKAGE = PUBLIC.parent.parent / "runtime-v14-public"
V14_SEAL_SHA = "9acff056bbafe73b528832fa4e1fd468d2e2cb6bbfab49e4b17d49ba2ace17ff"
V14_COMMIT = "2db5b99d5d213e921ebcbb08d5b25e00b754a0d4"
ATTEMPT = PUBLIC / "attempts" / "range-70-135-1795211361251901223"
INVENTORY_SHA = "c4dbc4bc2413377f6c77922730be26e77640a182bf5ac53038aa4856e72983f7"


REVIEW = {"path":str(V14/"ORIGINAL_73_CLOSED_REPORT_REVIEW.json"),
          "sha256":"a39e2af5dacf83186fc72ccc52b51ad112f4614992980becf37297c70d7c9834"}

def recovery_boundary(boundary, previous, report):
    need(boundary["schema"]=="horizon-public-audit-natural-successor-v2" and boundary["original_73_review"]==REVIEW,
         "unknown original 73 review")
    review=checked(REVIEW)
    need(review["native_report"]==boundary["native_report"] and review["branch_event"]==boundary["event"]
         and review["full_epoch_verified"] and review["report"]==report["report"],"incorrect closed 73 playback")
    inventory=checked(boundary["inventory"])["objects"]
    accepted=boundary["accepted_epochs"]
    manifest=boundary["accepted_result_sha256"]
    need(len(accepted)>=73 and accepted==[entry["epoch"] for entry in inventory[:len(accepted)]]
         and set(manifest)=={str(n) for n in accepted},"incomplete preserved inventory prefix")
    for epoch in accepted:
        need(bound(PUBLIC/"results"/f"epoch-{epoch}.json")["sha256"]==manifest[str(epoch)],"accepted result changed")
    trigger=checked(boundary["quiescent_reader"])
    native_reader=checked(trigger["reader_proof"])
    need(trigger["schema"]=="horizon-previous-public-reader-v2" and trigger["parent"]==previous
         and trigger["pid"]==boundary["previous_child_pid"] and trigger["start_ticks"]>0
         and trigger["argv"][0]==native_reader["artifact"] and trigger["reader_sha256"]==native_reader["artifact_sha256"]
         and trigger["range_start"]<=trigger["range_end"] and trigger["range_start"]>=73,
         "foreign naturally closed reader")
    need(boundary["fresh_quiescence_unix_seconds"]>=trigger["observed_at"] and
         boundary["at"]>=boundary["fresh_quiescence_unix_seconds"] and boundary["sole_quiescent_parent"] is True
         and boundary["recovery_activated_live_reader"] is False,"invalid successor boundary evidence")


def v14_chain(previous, launch, closure, boundary, branch, report, reference_report):
    """Accept a new invocation only after the incumbent's natural report boundary."""
    need(previous == {"path": str(SUCCESSOR / "PUBLIC_OWNER.json"), "sha256": V13_OWNER_SHA},
         "v13 launch receipt differs")
    old = checked(previous)
    seal = {"path": str(V14_PACKAGE / "deployment-seal-receipt.json"), "sha256": V14_SEAL_SHA}
    if "rollback" in launch:
        need(launch["rollback"]["path"] == str(V14 / "ROLLBACK.json"), "foreign rollback path")
        rollback = checked(launch["rollback"])
        need(rollback["stopped"] == launch["previous_stopped"] and rollback["attempted_seal"] == seal
             and rollback["v14_cgroup_empty"] is True and rollback["accepted_results_unchanged"] is True
             and launch["seal"] == old["seal"] and launch["source_commit"] == old["source_commit"]
             and closure["at"] <= rollback["at"] <= launch["at"], "unproved v13 rollback")
    else:
        need(launch["seal"] == seal and launch["source_commit"] == V14_COMMIT,
             "v14 controller seal or commit differs")
    need(launch["previous_owner"] == previous and launch["stopped"] == old["stopped"]
         and len(launch["InvocationID"]) == 32 and launch["InvocationID"] != old["InvocationID"]
         and launch["pid"] > 1 and launch["start_ticks"] > old["start_ticks"],
         "v14 launch or seal differs")
    n = closure["native"]
    need(launch["previous_stopped"]["path"] == str(V14 / "STOPPED.json")
         and closure["previous_owner"] == previous and closure["old_cgroup_empty"] is True
         and closure["old_pid_absent_or_reused"] is True
         and n["Id"] == native.UNIT and n["ActiveState"] == "inactive"
         and n["MainPID"] == "0" and n["Job"] == ""
         and closure["boundary"]["path"] == str(V14 / "BOUNDARY.json"),
         "v13 controller still owns audit work")
    result = boundary["native_report"]
    need(boundary["previous_owner"] == previous and boundary["epoch"] == 73
         and (boundary.get("schema")=="horizon-public-audit-natural-successor-v2" or boundary["previous_child_pid"]==3376515)
         and boundary["previous_child_drained"] is True
         and boundary["new_playback_started"] is False
         and boundary["inventory"] == {"path": str(PUBLIC/"inventory.json"), "sha256": INVENTORY_SHA}
         and boundary["event"]["path"] == str(ATTEMPT / "branch-change.json")
         and result["path"] == str(ATTEMPT/"reports"/"epoch-73.json")
         and (boundary.get("schema")=="horizon-public-audit-natural-successor-v2" or boundary["accepted_epochs"]==list(range(73)))
         and type(branch["completed"]) is int and branch["completed"] == 3
         and branch["reader_commit"] == "5bb2637754782ad3f03f5b780a5024fa89602adc"
         and report["full_epoch_verified"] is True and report["report"]["epoch"] == 73,
         "wrong natural epoch-73 boundary")
    if "schema" in boundary:
        recovery_boundary(boundary,previous,report)
    decoded = report["report"]
    need(report["schema"] == reference_report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
         and report["source"] == reference_report["source"] == "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"
         and report["invocation"] == reference_report["invocation"]
         and report["expected_first_slot"] == decoded["first_slot"] == 31536000
         and report["expected_last_slot"] == decoded["last_slot"] == 31967999
         and decoded["slots"] == 432000 and decoded["worker_count"] == 4,
         "wrong completed native epoch or range invocation")
    need(branch["at"] <= boundary["at"] <= closure["at"] <= launch["at"],
         "audit handoff times are out of order")


def successor_v14(previous, witness):
    root = V14 / "PUBLIC_OWNER.json"
    if not root.exists():
        if (V14 / "STOPPED.json").exists():
            raise native.TransitionPending("v13 stopped and successor launch is pending")
        return None
    launch = checked(bound(root))
    need(launch["previous_stopped"]["path"] == str(V14 / "STOPPED.json"), "foreign closure path")
    closure = checked(launch["previous_stopped"])
    need(closure["boundary"]["path"] == str(V14 / "BOUNDARY.json"), "foreign boundary path")
    boundary = checked(closure["boundary"])
    need(boundary["event"]["path"] == str(ATTEMPT / "branch-change.json")
         and boundary["native_report"]["path"] == str(ATTEMPT/"reports"/"epoch-73.json"),
         "foreign native range evidence")
    event = checked(boundary["event"])
    report = checked(boundary["native_report"])
    reference = checked({"path": str(ATTEMPT / "reports" / "epoch-72.json"),
                         "sha256": "e61aa491cde4d5396aa78d9d1bc76bc5c6815afe9845f7fcaa309982830590b8"})
    v14_chain(previous, launch, closure, boundary, event, report, reference)
    witness.update(previous_owner=previous, previous_stopped=launch["previous_stopped"],
                   natural_epoch73_boundary=closure["boundary"])
    return root


def slice_envelope():
    row = show(SLICE, ("Id", "ActiveState", "ControlGroup", "CPUQuotaPerSecUSec", "MemoryHigh", "MemoryMax", "MemorySwapMax", "TasksMax"))
    limits = {"Id": SLICE, "ActiveState": "active", "ControlGroup": "/" + SLICE, "MemoryHigh": str(20<<30), "MemoryMax": str(24<<30), "MemorySwapMax": "0", "TasksMax": "512"}
    need(all(row.get(key) == value for key, value in limits.items()), "shared audit memory/task envelope changed")
    if row["CPUQuotaPerSecUSec"] != "4s":
        assignment = checked(bound(SUCCESSOR / "SHARED_CPU_ASSIGNMENT.json"))
        need(assignment["slice"] == SLICE and assignment["previous_cpu_quota"] == "4s" and assignment["cpu_quota"] == row["CPUQuotaPerSecUSec"] and 4 < int(assignment["cpu_quota"].removesuffix("s")) <= 16 and assignment["additional_memory_bytes"] == 0, "shared audit CPU reservation differs")
    return row

def observe_public(dev, obligation):
    stop = bound(STOP)
    need(stop["sha256"] == "8721fbd0fcd41f8062a7ef7100027946723d915511e455f3b6598b7605a01abd", "retired audit receipt changed")
    stopped = checked(stop)
    need(stopped["native"]["MainPID"] == "0" and stopped["native"]["ActiveState"] == "inactive", "incomplete download-audit stop")
    need(STOP.stat().st_dev == dev and PUBLIC.parent.stat().st_dev == dev, "audit filesystem changed")
    row = native.native()
    witness = dict(native=row, predecessor_stop=stop)
    observed = int(time.time())
    progress = dict(phase="public_method_qualification", pid=None, epoch=None, remote_mutations=False)
    summary = dict(scope="public playback", passed=0, failed=0, archives=None, pending=None, complete=False)
    inventory = None
    child = None
    accepted = ROOT / "PUBLIC_OWNER.json"
    previous = bound(accepted)
    need(previous["sha256"] == PREVIOUS_DIGEST, "first public launch changed")
    successor = SUCCESSOR / "PUBLIC_OWNER.json"
    successor_active = successor.exists()
    cgroup = native.CG
    if successor_active:
        accepted = successor
        launch = checked(bound(accepted))
        need(launch["previous_owner"] == previous and launch["seal"]["sha256"] == SUCCESSOR_SEAL, "successor authority or seal differs")
        closure = checked(launch["previous_stopped"])
        need(closure["previous_owner"] == previous and closure["native"]["MainPID"] == "0" and closure["native"]["ActiveState"] == "inactive" and closure["old_cgroup_empty"], "first public owner not fenced")
        checked(closure["boundary"])
        witness.update(previous_owner=previous, previous_stopped=launch["previous_stopped"])
        cgroup = NEXT_CGROUP
        latest = successor_v14(bound(accepted), witness)
        if latest is not None:
            accepted = latest
            need(slice_envelope()["CPUQuotaPerSecUSec"] == "4s", "v14 shared CPU envelope changed")
    if accepted.exists():
        authority = content(accepted)
        need(authority["stopped"] == stop, "wrong predecessor")
        seal = checked(authority["seal"])
        package = Path(authority["seal"]["path"]).parent
        need(seal["destination"] == str(package) and seal["sealer_sha256"] == native.SEALER, "foreign public package")
        entries = {m["name"]:m for m in seal["members"]}
        _, image = native.read(package/"audit", entries["audit"]["sha256"], 0o555, "binary")
        _, config = native.read(package/"config.json", entries["config.json"]["sha256"], 0o444)
        witness.update(image=image,config=config,seal=authority["seal"],launch=bound(accepted))
        if row["ActiveState"]=="active":
            if successor_active:
                need(row["ControlGroup"] == cgroup and row["MemoryHigh"] == str(20<<30), "successor cgroup or high limit changed")
                native.validate_limits(dict(row, ControlGroup=native.CG))
                witness["shared_slice"] = slice_envelope()
            else:
                native.validate_limits(row)
            pid = int(row["MainPID"])
            proc = Path("/proc") / str(pid)
            need(row["InvocationID"]==authority["InvocationID"] and pid==authority["pid"] and native.ticks(pid)==authority["start_ticks"],"different public owner")
            need((proc/"exe").samefile(package/"audit") and (proc/"cgroup").read_text().strip()=="0::"+cgroup and
                 (proc/"cmdline").read_bytes()==b"\0".join([os.fsencode(package/"audit"),b"run-public",os.fsencode(package/"config.json"),b""]), "foreign executable or command")
        else:
            need(row["MainPID"]=="0" and row["ActiveState"] in ("inactive","failed"),"unknown public unit state")
        if (PUBLIC/"inventory.json").exists():
            inventory=bound(PUBLIC/"inventory.json")
            entries=checked(inventory)["objects"]
            epochs={entry["epoch"] for entry in entries}
            need(len(epochs)==len(entries) and all(e["key"]==f"epoch-{e['epoch']}.jet" for e in entries),"invalid frozen inventory")
        if (PUBLIC/"progress.json").exists():
            p=content(PUBLIC/"progress.json")
            if successor_active and p["pid"] != authority["pid"] and row["ActiveState"]=="active":
                raise native.TransitionPending("new public owner has not published progress yet")
            need(p["schema"]=="horizon-r2-public-audit-progress-v1" and p["pid"]==authority["pid"] and p["archive_scratch_bytes"]==0 and p["remote_mutations"] is False,"wrong streaming progress")
            total,passed,failed=p["archives"],p["passed"],p["failed"]
            need(0<=passed+failed<=total and (total==0 or inventory and total==len(epochs)),"invalid public audit counts")
            summary=dict(scope="public playback",archives=total,passed=passed,failed=failed,pending=total-passed-failed,complete=p["phase"]=="complete")
            progress=p
        if row["ActiveState"]!="active" and not summary["complete"]:
            progress=dict(progress,phase="public_audit_interrupted",last_reported_phase=progress["phase"])
        if row["ActiveState"]=="active" and (PUBLIC.parent/"child.json").exists():
            candidate=content(PUBLIC.parent/"child.json")
            cpid=candidate.get("pid")
            if isinstance(cpid,int) and cpid>1:
                try:
                    if (Path("/proc")/str(cpid)/"cgroup").read_text().strip()=="0::"+cgroup:child=candidate
                except FileNotFoundError:pass
    elif row["ActiveState"]=="active":
        progress["phase"]="awaiting_public_launch_receipt"

    # Keep the existing metadata/build commitments conservative while the changed
    # method qualifies. Public playback has no local archive growth.
    work=obligation["working_allocation_cap_bytes"]
    cargo=obligation["cargo_growth_allowance_bytes"]
    storage=dict(epoch=progress["epoch"], archive_bytes=None, resident_archive_bytes=0,
        remaining_archive_growth_bytes=0, remaining_working_growth_bytes=work,
        remaining_cargo_growth_allowance_bytes=cargo, remaining_DATA_growth_bytes=work+cargo,
        largest_archive_booked=False, promise_ending_bytes=0,resource_credit_bytes=0)
    return dict(observed_at=observed,progress=progress,summary=summary,child=child,
        inventory=inventory,predecessor_stop=stop),storage,witness
