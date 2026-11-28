"""Bind the reader to the corrected observer operator and immutable producer."""
from importlib import util
from pathlib import Path

from evidence import bound, checked, need
import bounded167_admission as route

ROOT = route.ROOT
UNIT = route.UNIT
INTENT = ROOT/"START_INTENT.json"
OPERATOR_SEAL = ROOT/"operator-terminal-v3/deployment-seal-receipt.json"
READY = route.RT/"survivor172-cadence-20261122-v1/FAILED166_CADENCE_V33_READY.json"
MEMORY = 42 << 30
MEMORY_HIGH = 40 << 30


def operator_image(seal):
    need(seal["path"] == str(OPERATOR_SEAL) and seal == bound(OPERATOR_SEAL),
         "foreign bounded 167 operator deployment")
    image = route.present_member(seal, "replay167.py", executable=True)
    need(image["path"] == str(OPERATOR_SEAL.with_name("replay167.py")),
         "bounded 167 operator executable left its sealed directory")
    return image


def launched_intent(reference):
    doc = checked(reference)
    need(reference["path"] == str(INTENT) and doc["epoch"] == 167
         and doc["schema"] == "horizon-epoch167-bounded-start-intent-v1"
         and doc["terminal"] == route.TERMINAL and doc["producer_unit"] == UNIT
         and doc["resource_credit_bytes"] == 0
         and doc["archive_publication_authorized"] is doc["replay_launch_authorized"] is False
         and doc["producer_memory_bytes"] == MEMORY and doc["guard_memory_bytes"] == route.GUARD_MEMORY
         and route.ORIGINAL_FLOOR <= doc["armed_floor"] and 0 < doc["bounded_cap_bytes"] <= route.CAP,
         "different admitted bounded 167 resources or historical terminal")
    seal = doc["deployment"]
    need(Path(seal["path"]).parent == route.PACKAGE, "foreign bounded producer deployment")
    gate = route.present_member(seal, "replay167.py", executable=True)
    prepared = checked(doc["prepared"])
    need(gate["sha256"] == prepared["gate_source_sha256"], "candidate launcher crossed the intent")
    request = checked(doc["request"])
    operator = doc.get("operator_deployment")
    ready = checked(bound(READY))
    need(operator == request.get("operator_deployment") == ready["bounded167_operator"],
         "bounded 167 request crossed its operator deployment")
    image = operator_image(operator)
    need(image == ready["bounded167_operator_image"], "bounded 167 operator crossed the writer handoff")
    spec = util.spec_from_file_location("bounded167_operator", image["path"])
    reader = util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    need(reader.ROOT == ROOT and reader.UNIT == UNIT and reader.TIMER == route.TIMER
         and reader.PACKAGE == route.PACKAGE and reader.CGROUP == route.CGROUP
         and reader.CAP == route.CAP and reader.START == route.START and reader.END == route.END
         and reader.WORKER_SHA == route.WORKER_SHA and reader.GUARD_SHA == route.GUARD_SHA
         and reader.MEMORY == MEMORY and reader.MEMORY_HIGH == MEMORY_HIGH and reader.CPU == route.CPU,
         "sealed candidate operator changed the bounded scope")
    recovered, payload, projected_gate, projected_payload, _ = reader.intent_data(reference, live=True)
    need(recovered == doc and projected_gate == gate and projected_payload == doc["payload"],
         "bounded 167 intent or immutable producer projection changed during inspection")
    return doc,payload,reader
