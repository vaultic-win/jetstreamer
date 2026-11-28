"""Recognize the fourth private 169 in the complete 162/169/170 roster."""
import hashlib
import json
from pathlib import Path
import runpy
import sys


BASE = Path("/var/lib/jetstreamer/horizon_runtime_data")
PARENT = BASE / "epoch162-first-hourly-completion-20261127-v2/issued-price-v12/retry169_peer.py"
PARENT_SHA = "66f24b837f2168ff4474ab07def6d50470527334dd91e7570502c424b9da0283"
ROOT = BASE / "epoch169-hourly-retry-20261128-v4"
OP = ROOT / "operator-v1"
SCOPE = "f74d0b1dd33abe2b03705f3c69af3a74b27784bb293f69aff1f913fecf24ddb5"
OPERATOR = "c87a140777cc4e94cd3db1b60ac2ee5f022d2a4d24bfa5ffd2110c4a7b3c2148"
CLOSURE = "438f68aca277600ec8ecbf9eea5c651a02f8962b4d0b5cde94db00743f358b4b"
THIRD = BASE / "epoch169-hourly-retry-20261128-v3"


def predecessor():
    if hashlib.sha256(PARENT.read_bytes()).hexdigest() != PARENT_SHA:
        raise ValueError("unrecognized third 169 peer")
    return runpy.run_path(str(PARENT))


def load():
    third = predecessor()
    previous = third["previous"]()
    need, body = previous["require"], previous["body"]
    seal = json.loads(body(OP / "deployment-seal-receipt.json", OPERATOR))
    scope = json.loads(body(ROOT / "SCOPE.json", SCOPE))
    old = json.loads(body(THIRD / "SCOPE.json", third["SCOPE"]))
    conserved = ("quota", "inputs", "worker", "node", "predecessor", "first_gate_closure", "second_guard_stop",
                 "first", "last", "terminal_hash", "guard_projection_qualification", "guard_readonly_target")
    need(seal["destination"] == str(OP)
         and scope["operator"] == dict(path=str(OP / "deployment-seal-receipt.json"), sha256=OPERATOR)
         and scope["parent_scope"] == dict(path=str(THIRD / "SCOPE.json"), sha256=third["SCOPE"])
         and scope["third_unreleased"] == dict(path=str(THIRD / "UNRELEASED_OUTPUT_MARGIN.json"), sha256=CLOSURE)
         and all(scope[k] == old[k] for k in conserved) and not scope["canonical_publication_authorized"]
         and scope["producer_unit"] == "horizon-qualify-169-hourly-retry-20261128-v4.service"
         and scope["guard_readonly_source"] == "/home/sol/.jetstreamer-private/epoch169-hourly-retry-20261128-v4",
         "fourth 169 changed predecessor, resource envelope or private interval")
    for item in seal["members"]:
        path = OP / item["name"]
        need(path.parent == OP and len(body(path, item["sha256"])) == item["bytes"], "fourth 169 operator changed")
    names = ("contract", "namespace", "quote")
    for name in names:
        candidate = sys.modules.get(name)
        need(candidate is None or Path(candidate.__file__) == OP / (name + ".py"), "foreign 169 import " + name)
    saved = list(sys.path)
    try:
        observer = runpy.run_path(str(OP / "observe.py"))
    finally:
        sys.path[:] = saved
    need(all(Path(sys.modules[n].__file__) == OP / (n + ".py") for n in names), "unbound fourth 169 observer")
    return observer


def bind(core, native):
    third = predecessor()
    third["bind"](core, native)
    scope, ref = core.read(ROOT / "SCOPE.json", SCOPE)
    closure, closed = core.read(THIRD / "UNRELEASED_OUTPUT_MARGIN.json", CLOSURE)
    end = core.bound(closure["terminal"])
    intent = core.bound(closure["intent"])
    post = core.bound(closure["postguard"])
    paid = native["planned_169_retry"]
    core.need(scope["third_unreleased"] == closed and scope["parent_scope"] == closure["scope"] == paid["third_scope"]
              and scope["second_guard_stop"] == paid["second_guard_stop"] and scope["first_gate_closure"] == paid["first_unreleased_closure"]
              and end == dict(disposition="private-payload-never-released", canonical_publication_authorized=False)
              and intent["held"] == closure["held"] and intent["guard_plan"] == closure["guard"]
              and intent["producer_invocation_id"] == closure["invocation_id"] == "5d0455bad43742be89ee9711b460d1c0"
              and intent["scope"] == post["scope"] == closure["scope"] and post["fits"]
              and [k for k, v in post["postguard_checks"].items() if not v] == ["funded_output"]
              and not closure["first_replay_slot_observed"] and not closure["resource_credit_bytes"]
              and paid["additional_home"] == scope["quota"]["home_output"] + scope["quota"]["home_control"]
              and paid["additional_ram"] + native["stopped_169_compute_handoff"]["retained_159_ram"] == scope["quota"]["producer_ram"],
              "third 169 closure or paid fourth 169 reservation changed")
    # load().current() independently checks the three older producers, their guards
    # and the fourth gate on each side of the shared price.
    paid.update(fourth_scope=ref, third_unreleased=closed)
