"""Bind the epoch 140 receiver to the accepted V40 clock."""
from pathlib import Path

from evidence import bound, checked, need
from transition import clock

V40_SHA = "04df4d1f281f565415ede59ed457dab17957ee0322c23e55c378cd2b1306e340"
V40_SEAL = "eb9c4380a8aad5d44a21b91c0feca8d9475d31c1fea4a201cb3bac75b143ccb7"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root / "FAILED166_CADENCE_V40_ACTIVE.json"), sha256=V40_SHA)
    old = checked(old_ref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V40_SEAL
         and old["new"]["program"] == str(root / api["failed166_package"](40) / "status_cycle.py"),
         "unexpected V40 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns),
         "V41 must adopt the current accepted fleet")
    reference = fleet["sole_next_observer"]
    config = api["sealed"](reference)
    timer = fleet["sole_next_timer"]
    complete = clock(api, fleet, config, timer, reference)
    api["tail167_status"].retained_population(fleet, config)
    api["bridge170_status"].retained_population(fleet, config)
    unchanged = {
        "lane_k_receiver": "holding185_lanek.py",
        "phase162_receiver": "prefix162_status.py",
    }
    for key, name in unchanged.items():
        need(bound(current.with_name(name))["sha256"] == earlier[key]["sha256"],
             f"V41 changed the existing {name} reader")
    bindings = {
        "full170_receiver": "full170_status.py", "focused168_receiver": "focused168_status.py",
        "joint168_receiver": "joint168_status.py", "joint168_native_reader": "joint168_capacity.py",
        "retry5_generation": "retry5-168-generation.json",
        "phase162_receiver": "prefix162_status.py", "recording140_receiver": "recording140_status.py",
    }
    receivers = {key: bound(current.with_name(name)) for key, name in bindings.items()}
    return dict(earlier, package=seal, old_owner=old_ref, fleet=head, config=reference,
                timer=timer, completed_sample=complete, **receivers)


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or (
        proposed["completed_sample"] is None and actual["completed_sample"] is not None
        and dict(actual, completed_sample=None) == proposed
    ), "V41 lost the prior clock")
