"""Enroll measured epoch 167 assembly in the sole writer while preserving the V72 fleet."""
from pathlib import Path

import adjacent169_route as adjacent
import assembly_cadence as assembly
import assembly_forecast as model
from evidence import BASE, bound, checked, need
from transition import clock
from transition_v71 import native_assignments


V72_SHA = "16100229f345b290452df1d071d6b1986b6e32a6d03b6b1e12c8e0b3cf51c174"
V72_SEAL = "1ce0186cb6b339ee8189f24d9ee8620eb85047fb64c5b6293a1522bbe82c2146"
V72_READY = "f7407afdc837661a412b012ae9e0c837983c71f56a90b70df68b129d1308a7d6"


def ready(api, head, seal):
    root = api["ROOT"]
    old_dir = root / api["failed166_package"](72)
    owner = dict(path=str(root / "FAILED166_CADENCE_V72_ACTIVE.json"), sha256=V72_SHA)
    old = checked(owner)
    prior = checked(old["ready"])
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p:p.stat().st_mtime_ns)
    need(old["ready"]["sha256"] == V72_READY and head == bound(latest)
         and old["new"]["program"] == str(old_dir / "status_cycle.py")
         and prior["package"] == dict(path=str(old_dir / "deployment-seal-receipt.json"),sha256=V72_SEAL)
         and all(prior[k] == v for k,v in adjacent.ready_fields(old_dir).items()),
         "V73 predecessor writer, adjacent 169 route or fleet changed")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api, fleet, api["sealed"](config), timer, config)
    current = api["CURRENT"].parent
    copies = {k:bound(current / Path(v["path"]).name) for k,v in prior.items()
              if k != "package" and isinstance(v, dict) and "path" in v and Path(v["path"]).parent == old_dir}
    proof = checked(assembly.QUALIFIED)
    module = bound(current / "assembly_forecast.py")
    need(proof["module"]["sha256"] == module["sha256"] and proof["deployment"] == assembly.DEPLOYMENT
         and proof["provenance"]["assembly_observation"]["booking"] == model.BOOKING
         and proof["after_status"]["epoch"] == 167 and proof["external_writes"] == 0,
         "unqualified 167 forecast source")
    return prior | copies | adjacent.ready_fields(current) | dict(package=seal, old_owner=owner, fleet=head,
            config=config, timer=timer, completed_sample=completed, protected_private_assignments=active,
            terminal_private_invocations=closed, epoch167_assembly_forecast=module,
            epoch167_assembly_route=bound(current/"assembly_cadence.py"), epoch167_assembly_qualification=assembly.QUALIFIED,
            epoch167_assembly_owner=assembly.owner_binding())


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed), "V73 observer or protected assignment changed")
