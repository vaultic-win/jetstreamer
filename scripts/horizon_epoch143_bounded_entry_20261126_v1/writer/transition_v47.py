"""Preserve V46's existing clock, every receiver and the 143 re-entry authority."""

from pathlib import Path

from evidence import BASE, bound, checked, need
from transition import clock
import rolling170_fourth_status as rolling

V46_SHA = "657c9965f71dbff5478308c1c6a703bb4732855c6ac3d4b6daaa4dfa67907f4f"
V46_SEAL = "4bb23953781c66d9d221d36525f0daae6243d8d667b41bc4388b36be17bc9ea4"
LISTENER = dict(
    path=str(BASE / "epoch143-first-hourly-20261127-v1/REENTRY_WATCH_ARMED.json"),
    sha256="accd593c5de9fbe4ad9dd061393678e36e51bff7ae96c4a1f825d3bcabffae64",
)


def ready(api, head, seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    oldref = dict(path=str(root / "FAILED166_CADENCE_V46_ACTIVE.json"), sha256=V46_SHA)
    old = checked(oldref)
    earlier = checked(old["ready"])
    listener = checked(LISTENER)
    need(
        earlier["package"]["sha256"] == V46_SEAL
        and old["new"]["program"]
        == str(root / api["failed166_package"](46) / "status_cycle.py")
        and earlier["successor170_interface"] == rolling.history.INTERFACE
        and checked(listener["phase"])["writer"] == oldref,
        "V46 writer or 143 phase differs",
    )
    fleet = checked(head)
    need(
        Path(head["path"])
        == max(
            base.glob("root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
            key=lambda path: path.stat().st_mtime_ns,
        ),
        "V47 needs the latest committed fleet",
    )
    ref, timer = fleet["sole_next_observer"], fleet["sole_next_timer"]
    cfg = api["sealed"](ref)
    complete = clock(api, fleet, cfg, timer, ref)
    api["tail167_status"].retained_population(fleet, cfg)
    api["bridge170_status"].retained_population(fleet, cfg)
    prior = rolling.history.retained_population(fleet, cfg)
    scope = rolling.interface()
    rolling.contract.previous_owner(prior, scope)
    need(
        not any(
            path.exists()
            for path in (
                rolling.following.ACTOR,
                rolling.following.RELEASE,
                rolling.following.ENROLLMENT,
                Path(scope["barrier"]),
            )
        ),
        "fourth window already dispatched",
    )
    bindings = {
        "full170_receiver": "full170_status.py",
        "focused168_receiver": "focused168_status.py",
        "joint168_receiver": "joint168_status.py",
        "joint168_native_reader": "joint168_capacity.py",
        "bridge170_status": "bridge170_status.py",
        "successor170_receiver": "rolling170_fourth_status.py",
        "prior_successor170_receiver": "rolling170_retry_status.py",
        "next_successor170_receiver": "fourth170_native.py",
        "continuation170_contract": "fourth170_contract.py",
        "retry5_generation": "retry5-168-generation.json",
        "hourly_reader": "first_hourly143.py",
        "hourly_population": "hourly_population.py",
    }
    return dict(
        earlier,
        package=seal,
        old_owner=oldref,
        fleet=head,
        config=ref,
        timer=timer,
        completed_sample=complete,
        successor170_interface=rolling.INTERFACE,
        prior_successor170_interface=rolling.history.INTERFACE,
        retained_143_listener=LISTENER,
        retained_143_phase=listener["phase"],
        **{key: bound(current.with_name(name)) for key, name in bindings.items()},
    )


def validate(api, proposed, seal):
    actual = ready(api, proposed["fleet"], seal)
    need(
        actual == proposed
        or proposed["completed_sample"] is None
        and actual["completed_sample"] is not None
        and dict(actual, completed_sample=None) == proposed,
        "V47 lost the original owner or observer",
    )
