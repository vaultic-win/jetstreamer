"""Recover the unreleased third gate even when no cadence tick observed it."""
from pathlib import Path


ROOT = Path("/var/lib/jetstreamer/horizon_runtime_data/epoch169-hourly-retry-20261128-v3")
CLOSURE = "438f68aca277600ec8ecbf9eea5c651a02f8962b4d0b5cde94db00743f358b4b"
SCOPE = "7668d6747cfe67bfbfbc5d0db14331d8db57a73b1fb4d3d6a12820dc08a56daf"
INVOCATION = "5d0455bad43742be89ee9711b460d1c0"
FIELD = "current_private169_retry3"


def terminal(contract, state, fleet):
    closure, ref = contract.read(ROOT / "UNRELEASED_OUTPUT_MARGIN.json", CLOSURE)
    previous, scope = contract.read(ROOT / "SCOPE.json", SCOPE)
    end, terminal_ref = contract.read(ROOT / "results/TERMINAL.json", closure["terminal"]["sha256"])
    held, held_ref = contract.read(ROOT / "HELD_GATE.json", closure["held"]["sha256"])
    contract.need(closure["scope"] == scope and closure["held"] == held_ref and closure["terminal"] == terminal_ref
                  and held["invocation_id"] == closure["invocation_id"] == INVOCATION
                  and end == dict(disposition="private-payload-never-released", canonical_publication_authorized=False)
                  and not closure["first_replay_slot_observed"] and not closure["resource_credit_bytes"]
                  and closure["armed_home_margin"] < 0, "unrecognized third 169 terminal")
    unit = previous["producer_unit"]
    for name, saved in closure["states"].items():
        live = state(name)
        allowed = ("failed", "inactive") if name == unit else ("inactive",)
        contract.need(live["Id"] == name and live["ActiveState"] in allowed and not live["Job"]
                      and live.get("MainPID", "0") == live.get("ControlPID", "0") == "0"
                      and not live.get("ControlGroup") and live["InvocationID"] in ("", saved["InvocationID"])
                      and not (Path("/sys/fs/cgroup/system.slice") / name / "cgroup.procs").exists(),
                      "third 169 owner reacquired " + name)
    row = fleet.get(FIELD)
    if row is not None:
        contract.need(row["invocation_id"] == INVOCATION and row["unit"]["Id"] == unit,
                      "different third 169 in the fleet")
        if row["phase"] == "terminal":
            contract.need(row["terminal"] == terminal_ref and row["held"] == held_ref,
                          "different third 169 fleet terminal")
            return row, ref
        contract.need(row["phase"] == "held" and row["intent"] == closure["intent"]
                      and row["guard_plan"] == closure["guard"] and not row["release"],
                      "fleet records a different or released third 169")
    return dict(epoch=169, phase="terminal", unit=closure["states"][unit], invocation_id=INVOCATION,
                held=held_ref, terminal=terminal_ref, canonical_replay_claimed=False,
                archive_publication_authorized=False, resource_credit_bytes=0), ref
