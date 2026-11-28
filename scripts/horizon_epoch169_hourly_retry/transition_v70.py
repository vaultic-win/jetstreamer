"""Register epoch 169's next interval with the current writer and its armed observer."""

from pathlib import Path

import adjacent169_route as route
from evidence import BASE, bound, checked, need
from transition import clock
import transition_v69


V69_SHA = "eabc10a834d15a0e9558872fb79c94074f53b76c13a52ca99c4533a17106805f"
V69_SEAL = "5e340efd8997049cc8000a06feaf666c00605ad81ad384387b375981aaeb3f58"


def native_assignments(fleet):
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    head = bound(latest)
    need(checked(head) == fleet, "different fleet while enrolling the adjacent epoch 169 owner")
    active, closed = transition_v69.native_assignments(route.legacy_fleet(fleet), head)
    prior = route.previous(fleet)
    need(closed.get(prior["unit"]["Id"]) == route.OLD_IID, "missing prior epoch 169 terminal")
    row = route.live.current(fleet)
    if row:
        name, iid = row["unit"]["Id"], row["producer_invocation_id"]
        need(name == route.UNIT and name not in active and name not in closed
             and iid != route.OLD_IID and checked(row["held_owner"]) == row["actor"],
             "different epoch 169 owner")
        if row["phase"] == "terminal":
            need(row["terminal"] == route.live.native_end(route.live.api(), row["actor"]),
                 "different adjacent epoch 169 terminal")
            closed[name] = iid
        else:
            need(row["phase"] in ("bootstrap", "worker") and row["release"] and row["guard"]
                 and row["unit"]["InvocationID"] == iid, "epoch 169 is crossing its guarded release")
            active[name] = dict(unit=name, iid=iid, pid=row["unit"]["MainPID"], intent=row["held_owner"])
    return active, closed


def ready(api, head, seal):
    root = api["ROOT"]
    old_dir = root / api["failed166_package"](69)
    owner = dict(path=str(root / "FAILED166_CADENCE_V69_ACTIVE.json"), sha256=V69_SHA)
    old = checked(owner)
    prior = checked(old["ready"])
    latest = max(BASE.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"), key=lambda p: p.stat().st_mtime_ns)
    need(head == bound(latest) and old["new"]["program"] == str(old_dir / "status_cycle.py")
         and prior["package"] == dict(path=str(old_dir / "deployment-seal-receipt.json"), sha256=V69_SEAL),
         "different incumbent writer or fleet")
    fleet = checked(head)
    active, closed = native_assignments(fleet)
    need(route.UNIT not in active and route.UNIT not in closed, "epoch 169 already has a successor owner")
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    completed = clock(api, fleet, api["sealed"](config), timer, config)
    current = api["CURRENT"].parent
    copies = {k: bound(current / Path(v["path"]).name) for k, v in prior.items()
              if k != "package" and isinstance(v, dict) and "path" in v and Path(v["path"]).parent == old_dir}
    return prior | copies | route.ready_fields(current) | dict(
        package=seal, old_owner=owner, fleet=head, config=config, timer=timer, completed_sample=completed,
        protected_private_assignments=active, terminal_private_invocations=closed)


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or proposed["completed_sample"] is None and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed, "epoch 169 handoff lost the observer or its owners")
