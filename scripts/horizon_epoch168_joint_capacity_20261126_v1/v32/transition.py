"""Validate an in-place V31 to V32 writer handoff and its unchanged native clock."""
from pathlib import Path

from evidence import bound, checked, need, utc

V31_SHA = "e1656e850ee59398d8d5489b39d81a023744dc1d37132f632592feb52c54f2f5"
V31_SEAL_SHA = "fce9080d3190e16d9353a594113d9ebb785d7f0be6f22c9e5c56f31e40f3240e"
HEAD_SHA = "cce5bc5600c7eee4ce400f0cfeef7d24b1a1814a067a212325b3db4cfcf3f9e1"
HISTORY = (
    "cold167_execution_failure", "cold170_full_metered_guard_stop",
)


def accepted_head(base, head):
    initial = dict(path=str(base/"root031808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                   sha256=HEAD_SHA)
    authority = checked(initial)
    current = checked(head)
    cursor = head
    for _ in range(96):
        row = checked(cursor)
        need(all(row[key] == authority[key] for key in HISTORY), "V32 lost an original retained terminal")
        if cursor == initial:
            return current
        next_ref = row["previous_Root_operational_review"]
        need(Path(next_ref["path"]).parent.parent == base and cursor != next_ref
             and utc(checked(next_ref)["sampled_at_utc"]) < utc(row["sampled_at_utc"]),
             "V32 fleet lineage left the accepted V31 sequence")
        cursor = next_ref
    raise ValueError("V32 fleet does not descend from the accepted 03:18 fleet")


def clock(api, fleet, config, timer, receipt):
    """Prove the exact existing timer, or the successful sample it already ran."""
    need(timer == fleet["sole_next_timer"]
         and receipt == fleet["sole_next_observer"]
         and config["previous_sample"] == fleet["observer"]["path"], "wrong inherited observer")
    clock_names = api["names"](config["not_before_utc"])
    need(clock_names["timer"] == timer and str(clock_names["sample"]) == config["output"],
         "wrong unchanged timer or sample path")
    waiting = api["timer_names"]()
    owner = api["owners"]
    if waiting:
        need(waiting == [timer], "V32 may only inherit one observer timer")
        native = owner.show(timer, ("Id","InvocationID","ActiveState","SubState","Job","Triggers","TimersCalendar"))
        service = owner.show(timer.replace(".timer",".service"), ("ExecStart",))
        need(native["Id"] == timer and native["InvocationID"] and native["ActiveState"] == "active"
             and native["SubState"] == "waiting" and not native["Job"]
             and native["Triggers"] == timer.replace(".timer",".service")
             and str(api["race166"].NATIVE)+" "+receipt["path"]+" " in service["ExecStart"]
             and utc(config["not_before_utc"]).strftime("%F %T UTC") in native["TimersCalendar"],
             "existing timer lost the V31 native config")
        return None
    sample = Path(config["output"])
    need(sample.is_file(), "original sole timer has no completed sample")
    native = owner.show(timer.replace(".timer",".service"), ("ActiveState","Result","Job"))
    need(native["ActiveState"] == "inactive" and native["Result"] == "success" and not native["Job"],
         "native observer did not finish the original clock")
    reference = bound(sample)
    api["check_sample"](fleet, checked(reference), config)
    return reference


def ready(api, head, new_seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root/"FAILED166_CADENCE_V31_ACTIVE.json"), sha256=V31_SHA)
    old = checked(old_ref)
    previous = checked(old["ready"])
    fleet = accepted_head(base, head)
    need(previous["package"]["sha256"] == V31_SEAL_SHA
         and old["new"]["program"] == str(root/api["failed166_package"](31)/"status_cycle.py"),
         "foreign V31 authority")
    ref = fleet["sole_next_observer"]
    cfg = api["sealed"](ref)
    timer = fleet["sole_next_timer"]
    completed = clock(api,fleet,cfg,timer,ref)
    return dict(schema="horizon-epoch166-cadence-rejoin-ready-v1", package=new_seal, old_owner=old_ref,
                fleet=head, config=ref, timer=timer, completed_sample=completed,
                full170_receiver=bound(current.with_name("full170_status.py")),
                full170_terminal=previous["full170_terminal"],
                focused168_receiver=bound(current.with_name("focused168_status.py")),
                retry5_generation=bound(current.with_name("retry5-168-generation.json")),
                retained_retry4_stop=previous["retained_retry4_stop"], retry5_scan_stop=previous["retry5_scan_stop"],
                full146_receiver=previous["full146_receiver"],
                joint168_receiver=bound(current.with_name("joint168_status.py")),
                joint168_native_reader=bound(current.with_name("joint168_capacity.py")),
                bounded167_receiver=bound(current.with_name("bounded167_status.py")),
                bounded167_admission=bound(current.with_name("bounded167_admission.py")))


def validate(api, proposed, new_seal):
    actual = ready(api, proposed["fleet"], new_seal)
    need(actual == proposed or proposed["completed_sample"] is None
         and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed,
         "V32 READY changed the accepted population, seal or observer clock")
    return actual["completed_sample"]
