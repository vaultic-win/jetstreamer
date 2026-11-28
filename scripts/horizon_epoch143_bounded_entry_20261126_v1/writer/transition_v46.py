"""Adopt the V45 clock for the existing 143 and replacement 170 receivers."""

from pathlib import Path

from evidence import bound, checked, need
from transition import clock
import rolling170_retry_status as rolling

V45_SHA = "a95b8ea8c0fc8692b5b534bb1afe33800476e48156a362c8f59dff75d12ae202"
V45_SEAL = "237ff74a47d9d3fce22399ea81ff268aa50b6ed09daa3a03bf102a228f09e0bb"


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    oldref = dict(path=str(root / "FAILED166_CADENCE_V45_ACTIVE.json"), sha256=V45_SHA)
    old = checked(oldref)
    earlier = checked(old["ready"])
    need(earlier["package"]["sha256"] == V45_SEAL
         and earlier["successor170_interface"] == rolling.history.INTERFACE
         and old["new"]["program"] == str(root / api["failed166_package"](45) / "status_cycle.py"),
         "different V45 writer")
    fleet = checked(head)
    need(Path(head["path"]) == max(base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                                   key=lambda path: path.stat().st_mtime_ns),
         "V46 needs the latest fleet")
    config, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    cfg = api["sealed"](config)
    complete = clock(api, fleet, cfg, timer, config)
    api["tail167_status"].retained_population(fleet, cfg)
    api["bridge170_status"].retained_population(fleet, cfg)
    rolling.contract.require_failed_owner(rolling.retained_population(fleet, cfg))
    need(not rolling.retry.ACTOR.exists() and not rolling.retry.RELEASE.exists()
         and not rolling.retry.ENROLLMENT.exists(), "retry 170 dispatched before the writer handoff")
    rolling.interface()
    bindings = {
        "full170_receiver": "full170_status.py",
        "focused168_receiver": "focused168_status.py",
        "joint168_receiver": "joint168_status.py",
        "joint168_native_reader": "joint168_capacity.py",
        "bridge170_status": "bridge170_status.py",
        "successor170_receiver": "rolling170_retry_status.py",
        "prior_successor170_receiver": "rolling170_status.py",
        "next_successor170_receiver": "continuation170_retry_native.py",
        "continuation170_contract": "continuation170_retry_contract.py",
        "retry5_generation": "retry5-168-generation.json",
        "hourly_reader": "first_hourly143.py",
        "hourly_population": "hourly_population.py",
    }
    return dict(earlier, package=seal, old_owner=oldref, fleet=head, config=config, timer=timer,
                completed_sample=complete, successor170_interface=rolling.INTERFACE,
                prior_successor170_interface=rolling.history.INTERFACE,
                unreleased_170_terminal=rolling.contract.FAILED,
                **{key: bound(current.with_name(name)) for key, name in bindings.items()})


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(actual == proposed or proposed["completed_sample"] is None
         and actual["completed_sample"] is not None and dict(actual, completed_sample=None) == proposed,
         "V46 lost the original observer")
