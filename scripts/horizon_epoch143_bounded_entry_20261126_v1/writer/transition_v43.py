"""Carry the active 170 continuation and original observer into V43."""

from pathlib import Path

from evidence import bound, checked, need
from successor170_status import INTERFACE
from transition import clock

V42_SHA = "a456c3198331db26760ac3f70acd0b14bfde5157ff64fe82352d6d82d0eb3979"
V42_SEAL = "7400a14e6af29e19f9880afdc9976da4528cd607d1d77da54cd48be76b47e0db"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root / "FAILED166_CADENCE_V42_ACTIVE.json"), sha256=V42_SHA)
    old = checked(old_ref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V42_SEAL
         and old["new"]["program"] == str(root / api["failed166_package"](42) / "status_cycle.py"),
         "unexpected V42 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns),
         "V43 must adopt the current accepted fleet")
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
    ), "V43 lost the prior clock")
