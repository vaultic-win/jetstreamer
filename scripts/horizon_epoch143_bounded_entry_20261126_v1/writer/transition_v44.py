"""Bind the independently qualified epoch 170 retry to the same clock."""

from pathlib import Path

from evidence import bound, checked, need
from successor170_status import INTERFACE
from transition import clock

V43_SHA = "55ab9c6a0beeca94ff5792280ece90b0edc480e090f614a14bb21bf2dca0b0a9"
V43_SEAL = "5191b1fde1164f4da59fc09906c52b62be90668ec6564f0d0d260dcd73b91cd7"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root / "FAILED166_CADENCE_V43_ACTIVE.json"), sha256=V43_SHA)
    old = checked(old_ref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V43_SEAL
         and old["new"]["program"] == str(root / api["failed166_package"](43) / "status_cycle.py"),
         "unexpected V43 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns),
         "V44 must adopt the current accepted fleet")
    reference, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    config = api["sealed"](reference)
    complete = clock(api, fleet, config, timer, reference)
    api["tail167_status"].retained_population(fleet, config)
    api["bridge170_status"].retained_population(fleet, config)
    api["successor170_status"].retained_population(fleet, config)
    api["successor170_status"].interface()
    bindings = {
        "full170_receiver": "full170_status.py", "focused168_receiver": "focused168_status.py",
        "joint168_receiver": "joint168_status.py", "joint168_native_reader": "joint168_capacity.py",
        "bridge170_status": "bridge170_status.py", "successor170_receiver": "successor170_status.py",
        "retry5_generation": "retry5-168-generation.json", "hourly_reader": "first_hourly143.py",
        "hourly_population": "hourly_population.py",
    }
    receivers = {key: bound(current.with_name(name)) for key, name in bindings.items()}
    return dict(earlier, package=seal, old_owner=old_ref, fleet=head, config=reference, timer=timer,
                completed_sample=complete, successor170_interface=INTERFACE, **receivers)


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (
        proposed["completed_sample"] is None and actual["completed_sample"] is not None
        and dict(actual, completed_sample=None) == proposed
    ), "V44 lost the prior clock")
