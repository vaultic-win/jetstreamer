"""Observe the released epoch 170 diagnostic in the incumbent fleet cycle."""

import json
from pathlib import Path
import runpy
import subprocess
import sys

if __name__ == "__main__":
    sys.path.insert(0, "/var/lib/jetstreamer/horizon_runtime_data/prefix140-status-cadence-20261122-v1/cadence-tools")

from evidence import BASE, bound, checked, durable, need

ROOT = BASE / "epoch170-metered-hourly-20261124-v1"
PROVIDER = BASE / "incident-replay-fit-20261121-v1/tools-homefloor-170-metered-hourly-v3"
PROVIDER_SEAL = "4dc458d027ef29a669002b28a203b5cee4cfc19b79110a6dd0348bf73f1cb0a2"
FIELD = "epoch170_hourly_start_intent"
RELEASE = ROOT / "barrier/allow.json"
SCHEMA = "horizon-170-private-cycle-observation-v1"
FIRST_SLOT, LAST_SLOT = 73_706_461, 73_713_261


def previous_row(fleet):
    rows = [row for row in fleet["actual_active_private_diagnostics"] if row["epoch"] == 170]
    need(len(rows) <= 1 and not any(row["epoch"] == 170 for row in
         fleet["actual_executing_replays"] + fleet["actual_active_bootstraps"]),
         "epoch 170 diagnostic overlaps an ordinary producer")
    return rows[0] if rows else None


def projection(fleet_ref):
    """Use the existing sealed actor and guard checks in a separate process."""
    seal_ref = bound(PROVIDER / "deployment-seal-receipt.json")
    need(seal_ref["sha256"] == PROVIDER_SEAL, "different epoch 170 capacity package")
    seal = checked(seal_ref)
    need(seal["destination"] == str(PROVIDER), "different epoch 170 capacity directory")
    image = PROVIDER / "post-stop-fit"
    member, = (item for item in seal["members"] if item["name"] == image.name)
    need(bound(image)["sha256"] == member["sha256"], "changed epoch 170 capacity driver")
    provider = runpy.run_path(str(image), run_name="hourly170_cadence_provider")
    route, s, fit = (provider[key] for key in ("hourly170", "s", "fit"))
    fleet, _ = provider["fleet_head"](fleet_ref)
    prior = previous_row(fleet)
    iid = route["properties"](route["UNIT"], "InvocationID", "MainPID", "ControlPID",
                              "ControlGroup", "ActiveState", "Job")
    if not RELEASE.exists():
        need(prior is None, "epoch 170 released diagnostic lost its grant")
        return None
    contract = route["ready_contract"]()
    if iid["ActiveState"] == "active":
        route["drained145"](s, fit)
        actor = route["owner"](s, fit, contract, fleet, fleet_ref, prior, "active")
        guard = route["sample"](contract, actor, "active")
        worker = None
        if len(actor["processes"]) == 2:
            pid, ticks, device, inode = actor["processes"][1]
            image = Path(f"/proc/{pid}/exe")
            executable = image.readlink()
            st = image.stat()
            need(s.process(pid)[1] == ticks and (st.st_dev, st.st_ino) == (device, inode),
                 "epoch 170 diagnostic worker changed during observation")
            worker = dict(pid=pid, executable=str(executable))
        return {
            "row": dict(actor["registration"], guard_protection=guard["receipt"]),
            "worker": worker,
        }
    return {"terminal": terminal(route, fit, contract, prior, iid)}


def terminal(route, fit, contract, prior, manager):
    intent, intent_ref = route["sealed"](route["INTENT"])
    grant, grant_ref = route["sealed"](RELEASE)
    iid = intent["invocation_id"]
    need(intent["unit"] == grant["unit"] == route["UNIT"]
         and intent["schema"] == "horizon-epoch170-hourly-held-intent-v1"
         and grant["schema"] == "horizon-epoch170-metered-hourly-postguard-release-v1"
         and grant["invocation_id"] == iid
         and grant["pid"] == intent["pid"] and grant["start_ticks"] == intent["start_ticks"]
         and grant["boot_id"] == intent["boot_id"]
         and intent["inputs"] == contract["inputs"]
         and grant["inputs_sha256"] == contract["inputs"]["sha256"]
         and grant["guard_plan_sha256"] == intent["guard_plan"]["sha256"]
         and grant["first_guard_sha256"] == intent["first_guard"]["sha256"]
         and grant["archive_publication_authorized"] is False
         and (prior is None or prior[FIELD] == intent_ref),
         "different released epoch 170 diagnostic")
    post = route["binding"](dict(path=str(route["POST"]), sha256=grant["native_post_guard_fit_sha256"]),
                            route["POST"])
    context = post["hourly170_diagnostic"]
    need(post["fits"] is True and post["fleet"] == intent["fleet"]
         and context["stage"] == "post-guard" and context["intent"] == intent_ref
         and context["receipt"] == intent["first_guard"],
         "epoch 170 terminal has no matching release quote")
    need(manager["InvocationID"] in ("", iid) and manager["MainPID"] == manager["ControlPID"] == "0"
         and not manager["ControlGroup"] and not manager["Job"]
         and manager["ActiveState"] in ("inactive", "failed") and not fit.members(route["UNIT"]),
         "epoch 170 diagnostic has not drained")
    exits = route["pid1"](route["UNIT"], iid, grant["boot_id"],
                           (route["SUCCESS"], route["FAILURE"]))
    event, = exits
    need(event["UNIT"] == route["UNIT"] and event["INVOCATION_ID"] == iid
         and event["_BOOT_ID"] == grant["boot_id"].replace("-", "")
         and event["_PID"] == "1", "foreign epoch 170 terminal event")
    return dict(intent=intent_ref, grant=grant_ref, manager=manager,
                pid1_cursor=event["__CURSOR"], successful_exit=event["MESSAGE_ID"] == route["SUCCESS"],
                archive_publication_authorized=False, reservation_ending_bytes=0)


def observe(c):
    path = c.paths["out"] / "PRIVATE170_OBSERVATION.json"
    if not path.exists():
        if not RELEASE.exists() and previous_row(c.fleet) is None:
            return None
        args = ["/usr/bin/python3", "-IB", str(Path(__file__).resolve()),
                c.fleet_ref["path"], c.fleet_ref["sha256"]]
        observed = json.loads(subprocess.check_output(args, timeout=75))
        if observed is None:
            return None
        durable(path, dict(schema=SCHEMA, fleet=c.fleet_ref, sample=c.sample_ref, observed=observed))
    receipt = bound(path)
    value = checked(receipt)
    need(value["schema"] == SCHEMA and value["fleet"] == c.fleet_ref
         and value["sample"] == c.sample_ref, "different epoch 170 observation")
    return dict(value["observed"], receipt=receipt)


def interpret(c, observed, lane_progress):
    selected = observed.get("row") if observed else None
    c.next_cfg["diagnostic_replays"] = [row for row in c.next_cfg["diagnostic_replays"]
                                         if row["range"] != "170"]
    if not selected:
        return
    observed_config = selected["observer_config"]
    prior = [row for row in c.cfg["diagnostic_replays"] if row["range"] == "170"]
    samples = [row for row in c.sample["diagnostic_replays"] if row["range"] == "170"]
    need(len(prior) == len(samples) <= 1, "different epoch 170 scheduled diagnostic sample")
    if prior:
        sample = samples[0]
        need(prior[0] == observed_config and all(sample[key] == observed_config[key] for key in
             ("producer_unit", "expected_producer_invocation_id", "scratch_path"))
             and sample["ordinary_replay_claim"] is False and sample["publication_authorized"] is False
             and sample["r2_mutations"] is False, "foreign epoch 170 scheduled sample")
        worker = observed["worker"]
        if sample["status"] == "observed" and worker is not None:
            result = sample["observation"]
            unit = selected["unit"]
            advances = lane_progress(result, observed_config, unit["InvocationID"],
                                     int(unit["MainPID"]), private_journal=True)
            work = result["useful_work"]
            matched = all(
                observed_worker.get("pid") == worker["pid"]
                and observed_worker.get("executable") == worker["executable"]
                and observed_worker.get("matching_workers") == 1
                and observed_worker.get("executable_beneath_bound_scratch") is True
                for observed_worker in (result.get("worker_before") or {}, result.get("worker_after") or {})
            )
            within = all(FIRST_SLOT <= (work.get(key) or {}).get("slot", 0) <= LAST_SLOT
                         for key in ("first", "last"))
            selected.update(coordinated_sample_observed_this_invocation=True,
                            transaction_replay_claimed=bool(advances and matched and within),
                            observed_progress=work)
    c.next_cfg["diagnostic_replays"].append(observed_config)


def install(fleet, observed):
    if observed is None:
        return
    need(previous_row(fleet) is None, "epoch 170 already joined the successor fleet")
    row = observed.get("row")
    entry = next(item for item in fleet["epochs"] if item["epoch"] == 170)
    need(entry["state"] == "verification" and entry["repair_open"]
         and entry["current_repair_owner"] == "/root", "epoch 170 diagnostic changed repair status")
    entry.pop("current_private_diagnostic", None)
    entry["private170_observation"] = observed["receipt"]
    if row:
        fleet["actual_active_private_diagnostics"].append(row)
        fleet["active_private_diagnostic_count"] += 1
        fleet["active_producer_count"] += 1
        entry.update(current_private_diagnostic=row, no_live_producer_claimed=False)


if __name__ == "__main__":
    path, digest = sys.argv[1:]
    print(json.dumps(projection(dict(path=path, sha256=digest)), sort_keys=True))
