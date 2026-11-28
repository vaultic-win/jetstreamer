"""Bind epoch 167's new writable leaf and keep its prior terminal evidence."""
from importlib import util
from pathlib import Path

from evidence import bound, checked, need
import bounded167_admission as historical

ROOT = historical.RT/"epoch167-checkpoint-bounded-20261127-v2"
PACKAGE = ROOT/"package"
UNIT = "horizon-qualify-167-checkpoint-bounded-20261127-v2.service"
TIMER = "horizon-guard-167-checkpoint-bounded-20261127-v2.timer"
GUARD_SERVICE = TIMER.replace(".timer", ".service")
RUN = historical.RUN.with_name("bounded-72509256-72515090-v2")
OPERATOR_SEAL = ROOT/"operator-v1/deployment-seal-receipt.json"
PRODUCER_SEAL = PACKAGE/"deployment-seal-receipt.json"
INTENT = ROOT/"START_INTENT.json"
READY = historical.RT/"survivor172-cadence-20261122-v1/FAILED166_CADENCE_V34_READY.json"
HISTORY_FIELD = "current_bounded167_checkpoint"
V1_FLEET = {
    "path": str(historical.RT/"root044808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
    "sha256": "07c35a9f23bc8b43101cf935078bf6b11d4005a46780b10e74dee27b8b966394",
}
V1_TERMINAL = {
    "path": str(historical.ROOT/"BOOTSTRAP_GUARD_TERMINAL.json"),
    "sha256": "c3e3aa57fb2b71bf2c9432d4378e09a3babcae7a5faa5b06292f2b457ee9d26c",
}
V1_INVOCATION = "0dc747e9e3c04e8ba45123c7948a583f"
MEMORY = 42 << 30
MEMORY_HIGH = 40 << 30
RUN_GROWTH = 48 << 30
RUN_BASELINE_MAX = 1 << 20


def image(seal, path):
    need(seal["path"] == str(path) and seal == bound(path),
         "foreign bounded 167 retry deployment")
    member = historical.present_member(seal, "replay167.py", executable=True)
    need(member["path"] == str(path.with_name("replay167.py")),
         "bounded 167 retry executable left its sealed directory")
    return member


def load(seal):
    operator = image(seal, OPERATOR_SEAL)
    spec = util.spec_from_file_location("admitted_bounded167_v2_operator", operator["path"])
    reader = util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    need(reader.ROOT == ROOT and reader.PACKAGE == PACKAGE and reader.UNIT == UNIT
         and reader.TIMER == TIMER and reader.GUARD_SERVICE == GUARD_SERVICE
         and reader.RUN == RUN and reader.OUTPUT.parent == RUN
         and reader.GUARD == ROOT/"guard-tools/guard"
         and reader.CGROUP == "/system.slice/"+UNIT
         and reader.CAP == historical.CAP and reader.START == historical.START and reader.END == historical.END
         and reader.TERMINAL == historical.TERMINAL and reader.WORKER_SHA == historical.WORKER_SHA
         and reader.PRIOR_STOP == V1_TERMINAL
         and reader.MEMORY == MEMORY and reader.MEMORY_HIGH == MEMORY_HIGH and reader.CPU == historical.CPU,
         "sealed operator changed the bounded retry scope")
    return reader


def deployments():
    operator, producer = bound(OPERATOR_SEAL), bound(PRODUCER_SEAL)
    operator_image = image(operator, OPERATOR_SEAL)
    gate = image(producer, PRODUCER_SEAL)
    need(operator_image["sha256"] == gate["sha256"] and operator_image["path"] != gate["path"],
         "bounded 167 retry operator and separate producer package differ")
    return dict(bounded167_operator=operator, bounded167_operator_image=operator_image,
                bounded167_gate=producer, bounded167_gate_image=gate)


def historical_terminal(fleet, cfg):
    original = checked(V1_FLEET)[HISTORY_FIELD]
    terminal = checked(V1_TERMINAL)
    need(dict(fleet[HISTORY_FIELD], observer=original["observer"]) == original and original["phase"] == "terminal"
         and original["unit"]["Id"] == historical.UNIT
         and original["native_terminal"]["INVOCATION_ID"] == terminal["producer_invocation_id"] == V1_INVOCATION
         and original["release"] == terminal["release"] and terminal["resource_credit_bytes"] == 0
         and terminal["archive_created"] is False and terminal["publication_authorized"] is False
         and not any(historical.UNIT in (row.get("producer_unit"),row.get("controller_unit"))
                     for row in cfg["diagnostic_replays"])
         and not any(row["unit"]["Id"] == historical.UNIT
                     for row in fleet["actual_active_private_diagnostics"]),
         "epoch 167 retry crossed the preserved first bounded attempt")
    for unit in (historical.UNIT, historical.GUARD_SERVICE):
        historical.idle(unit)
    timer=historical.props(historical.TIMER, ("Id","ActiveState","SubState","Job","Triggers"))
    need(timer["ActiveState"] == "inactive" and timer["SubState"] == "dead" and not timer["Job"]
         and timer["Triggers"] in ("",historical.GUARD_SERVICE), "first bounded 167 guard timer has not drained")
    return V1_TERMINAL


def admitted_caps(doc):
    outside = doc["retained_outside_run_bytes"]
    baseline = doc["run_baseline_physical_bytes"]
    run_cap = doc["run_guard_cap_bytes"]
    whole_cap = doc["bounded_cap_bytes"]
    need(0 < baseline <= RUN_BASELINE_MAX and outside > 0 and run_cap == baseline+RUN_GROWTH
         and whole_cap == outside+run_cap and whole_cap <= historical.CAP,
         "bounded 167 retry scan cap does not reconcile to the whole-tree booking")
    return outside, baseline, run_cap, whole_cap


def launched_intent(reference):
    doc = checked(reference)
    need(reference["path"] == str(INTENT) and doc["epoch"] == 167
         and doc["schema"] == "horizon-epoch167-bounded-start-intent-v1"
         and doc["terminal"] == historical.TERMINAL and doc["producer_unit"] == UNIT
         and doc["previous_bounded_stop"] == V1_TERMINAL
         and doc["resource_credit_bytes"] == 0
         and doc["archive_publication_authorized"] is doc["replay_launch_authorized"] is False
         and doc["producer_memory_bytes"] == MEMORY and doc["guard_memory_bytes"] == historical.GUARD_MEMORY
         and historical.ORIGINAL_FLOOR <= doc["armed_floor"],
         "different admitted bounded 167 retry resources or historical terminal")
    admitted_caps(doc)
    request = checked(doc["request"])
    ready = checked(bound(READY))
    operator = doc.get("operator_deployment")
    seal = doc["deployment"]
    need(operator == request.get("operator_deployment") == ready["bounded167_operator"]
         and seal == ready["bounded167_gate"], "bounded 167 retry crossed its operator or producer seal")
    gate = image(seal, PRODUCER_SEAL)
    preparation = checked(doc["prepared"])
    need(gate == ready["bounded167_gate_image"] and gate["sha256"] == preparation["gate_source_sha256"]
         and image(operator, OPERATOR_SEAL) == ready["bounded167_operator_image"],
         "bounded 167 retry crossed its immutable gate source")
    reader = load(operator)
    recovered, payload, projected_gate, projected_payload, _ = reader.intent_data(reference, live=True)
    need(recovered == doc and projected_gate == gate and projected_payload == doc["payload"],
         "bounded 167 retry projection crossed the admitted intent")
    return doc,payload,reader
