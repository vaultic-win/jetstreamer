"""Bind the successor reader to the incumbent writer and observer."""

from pathlib import Path

from evidence import bound, checked, need
from successor170_status import INTERFACE
from transition import clock

V41_SHA = "cd4f29ecbf483235e594e4e6e67eddcc58d063583e6b43e57ed9485ba6c9f407"
V41_SEAL = "245dda3f40bc976ff0a293b3256291a351aecc1473528694b00126bf9b1573aa"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root / "FAILED166_CADENCE_V41_ACTIVE.json"), sha256=V41_SHA)
    old = checked(old_ref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V41_SEAL
         and old["new"]["program"] == str(root / api["failed166_package"](41) / "status_cycle.py"),
         "unexpected V41 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns),
         "V42 must adopt the current accepted fleet")
    reference = fleet["sole_next_observer"]
    config = api["sealed"](reference)
    timer = fleet["sole_next_timer"]
    complete = clock(api, fleet, config, timer, reference)
    api["tail167_status"].retained_population(fleet, config)
    api["bridge170_status"].retained_population(fleet, config)
    api["successor170_status"].retained_population(fleet, config)
    api["successor170_status"].interface()
    unchanged = {
        "lane_k_receiver": "holding185_lanek.py",
        "phase162_receiver": "prefix162_status.py",
        "recording140_receiver": "recording140_status.py",
    }
    for key, name in unchanged.items():
        need(bound(current.with_name(name))["sha256"] == earlier[key]["sha256"],
             f"V42 changed the existing {name} reader")
    bindings = {
        "full170_receiver": "full170_status.py", "focused168_receiver": "focused168_status.py",
        "joint168_receiver": "joint168_status.py", "joint168_native_reader": "joint168_capacity.py",
        "bridge170_status": "bridge170_status.py", "successor170_receiver": "successor170_status.py",
    }
    receivers = {key: bound(current.with_name(name)) for key, name in bindings.items()}
    return dict(earlier, package=seal, old_owner=old_ref, fleet=head, config=reference, timer=timer,
                completed_sample=complete, successor170_interface=INTERFACE, **receivers)


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (
        proposed["completed_sample"] is None and actual["completed_sample"] is not None
        and dict(actual, completed_sample=None) == proposed
    ), "V42 lost the prior clock")
