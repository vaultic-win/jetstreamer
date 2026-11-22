"""Authenticate the epoch 145 semantic, selector and post-phase used by V7."""
from pathlib import Path
import re

RUNTIME = Path("/var/lib/jetstreamer/horizon_runtime_data")
FAMILY = RUNTIME / "epoch145-semantic-continuity-20261121-v1"
STATE = RUNTIME / "epoch145-guarded-export-20261121-v1/state"
DISPATCH = RUNTIME / "epoch145-fixture-phase-dispatch-20261122-v1"
V7 = RUNTIME / "epoch136-joint-writer-20261122-v7b"
V13 = FAMILY / "tools-v13b"
V21 = RUNTIME / "incident-replay-fit-20261121-v1/tools-v21b"
OLD = "a99ed8b51e8a482b805b8a36a11b2700"
FAILURE = dict(path=str(STATE / OLD / "failed.json"),
               sha256="da29d82a4349444ccc15e0be020aa12918ae5bbb4634f9b62e13cc83a93c5f43")
UNIT = "horizon-holding-export145-20261121-v1.service"
SEALER = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3"
ORIGINAL_LOCK = dict(path="/run/horizon-epoch171-to136-g1.operation.lock", device=26, inode=3453440)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def bound(row, path):
    need(set(row) == {"path", "sha256"} and row["path"] == str(path)
         and re.fullmatch("[0-9a-f]{64}", row["sha256"]), "unexpected binding for " + str(path))
    return row


def semantic(plan, read, read_start):
    ref = bound(plan["holding145_semantic_worker"], FAMILY / "V5F_ACTUAL_ADVANCING_WORKER.json")
    worker = read(ref)
    iid = worker["invocation_id"]
    need(re.fullmatch("[0-9a-f]{32}", iid) and iid not in (OLD, "0"*32),
         "wrong fixture semantic invocation")
    start = read_start(bound(worker["start"], STATE / iid / "recovery-started.json"))
    manager = read(bound(worker["manager"], FAMILY / "V5F_ACTUAL_MANAGER.json"))
    samples = worker["observations"]
    need(start["iid"] == manager["new"]["InvocationID"] == iid and manager["new"]["Id"] == UNIT
         and start["r2_mutations"] is False and
         start["prior_frozen_recovery"]["failed_qualification_census"]["current_boot_failure"]["failure"] == FAILURE
         and len(samples) == 2 and worker["resource_credit_bytes"] == 0, "different terminal or worker")
    first, last = samples
    keys = ("parent_pid", "parent_ticks", "child_pid", "child_ticks", "source_inode", "cgroup")
    need(all(first[key] == last[key] for key in keys)
         and first["parent_pid"] == manager["parent_pid"] and first["parent_ticks"] == manager["parent_start_ticks"]
         and first["cgroup"] == "/sys/fs/cgroup/system.slice/" + UNIT
         and last["source_offset"] > first["source_offset"] and last["worker_cpu_ticks"] > first["worker_cpu_ticks"],
         "fixture semantic worker did not advance")
    return iid


def sealed(package, seal_ref, members, read, pin):
    seal = read(bound(seal_ref, package / "deployment-seal-receipt.json"))
    need(seal["destination"] == str(package) and seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
         and seal["sealer_sha256"] == SEALER and seal["remote_mutations"] is False, "wrong deployment")
    for name, binding, mode in members:
        bound(binding, package / name)
        rows = [item for item in seal["members"] if item["name"] == name]
        need(len(rows) == 1 and rows[0]["sha256"] == binding["sha256"] and rows[0]["mode"] == mode,
             "wrong deployed member " + name)
        pin(package / name, binding["sha256"])


def completion_tools(plan, read, pin, runpy):
    completion = plan["holding145_completion"]
    sealed(V13, completion["seal"], [("build-proof.json", completion["build"], "0444"),
                                    ("incident-post-phase.py", completion["adapter"], "0444")], read, pin)
    build = read(completion["build"])
    need(build["prior_phase"] == plan["holding145_semantic_worker"], "V13 selects an older semantic worker")
    return build, runpy.run_path(str(V13 / "incident-post-phase.py"))


def ordinary_phase(plan, phase, read, pin, runpy, observer):
    iid = semantic(plan, read, read)
    if "stage" in phase:
        need(phase["stage"] == "leased-worker" and phase["invocation_id"] == iid,
             "ordinary price uses another semantic worker")
        return
    need(phase.get("ActiveState") == "inactive" and phase.get("SubState") == "dead" and phase.get("MainPID") == "0",
         "ordinary price uses a failed or changing semantic worker")
    build, verifier = completion_tools(plan, read, pin, runpy)
    done, extraction = verifier["completion"](observer, build)
    bound(done, STATE / iid / "complete.json")
    need(extraction["epoch"] == 145, "unexpected semantic completion")


def prepare(planref, plan, readyref, ready, read, read_start, pin, fixture_provider, runpy):
    bound(planref, V7 / "registered-production-plan.json")
    bound(readyref, DISPATCH / "READY.json")
    iid = semantic(plan, read, read_start)
    need(ready["schema"] == "horizon-145-136-prestart-selector-ready-v1" and
         ready["original_semantic_invocation"] == iid and ready["operation_lock"] == ORIGINAL_LOCK,
         "different original lock or selector generation")
    inspector = ready["boundary_inspector"]
    package = DISPATCH / "tools"
    sealed(package, ready["deployment"], [("boundary-inspector", inspector, "0555")], read, pin)
    provider = fixture_provider(ready["registered_provider"], V21)
    build, verifier = completion_tools(plan, read, pin, runpy)
    return iid, runpy.run_path(str(provider)), build, verifier
