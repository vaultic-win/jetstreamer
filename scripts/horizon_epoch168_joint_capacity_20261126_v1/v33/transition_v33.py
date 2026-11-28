"""Validate an in-place V32 to V33 writer handoff and its unchanged native clock."""
from pathlib import Path

from evidence import bound, checked, need, utc
from transition import clock

V32_SHA = "2d6ef7e3fa1263f05240b893bd545af2b98371340b4b6d3f1cc86466d0d7d6d2"
V32_SEAL_SHA = "a6399f6c67ae2c5e70e98ebfeea9c79955b0e91bdc134db2795f8eb0c99035f0"
HEAD_SHA = "95752c652e120bd15324abcfe564d6786eef6bd151053ad19bb67bc077d420a0"
HISTORY = (
    "cold167_execution_failure", "cold170_full_metered_guard_stop",
)


def accepted_head(base, head):
    initial = dict(path=str(base/"root041808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                   sha256=HEAD_SHA)
    authority = checked(initial)
    current = checked(head)
    cursor = head
    for _ in range(96):
        row = checked(cursor)
        need(all(row[key] == authority[key] for key in HISTORY), "V33 lost an original retained terminal")
        if cursor == initial:
            return current
        next_ref = row["previous_Root_operational_review"]
        need(Path(next_ref["path"]).parent.parent == base and cursor != next_ref
             and utc(checked(next_ref)["sampled_at_utc"]) < utc(row["sampled_at_utc"]),
             "V33 fleet lineage left the accepted V32 sequence")
        cursor = next_ref
    raise ValueError("V33 fleet does not descend from the accepted 04:18 fleet")


def ready(api, head, new_seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root/"FAILED166_CADENCE_V32_ACTIVE.json"), sha256=V32_SHA)
    old = checked(old_ref)
    previous = checked(old["ready"])
    fleet = accepted_head(base, head)
    need(previous["package"]["sha256"] == V32_SEAL_SHA
         and old["new"]["program"] == str(root/api["failed166_package"](32)/"status_cycle.py"),
         "foreign V32 authority")
    ref = fleet["sole_next_observer"]
    cfg = api["sealed"](ref)
    timer = fleet["sole_next_timer"]
    completed = clock(api,fleet,cfg,timer,ref)
    bounded = api["bounded167_status"]
    operator = bound(bounded.OPERATOR_SEAL)
    operator_image = bounded.operator_image(operator)
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
                bounded167_admission=bound(current.with_name("bounded167_admission.py")),
                bounded167_operator=operator, bounded167_operator_image=operator_image)


def validate(api, proposed, new_seal):
    actual = ready(api, proposed["fleet"], new_seal)
    need(actual == proposed or proposed["completed_sample"] is None
         and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed,
         "V33 READY changed the accepted population, seal or observer clock")
    return actual["completed_sample"]
