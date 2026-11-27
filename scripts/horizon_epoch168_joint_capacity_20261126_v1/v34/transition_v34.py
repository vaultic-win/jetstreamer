"""Validate an in-place V33 to V34 writer handoff and its unchanged native clock."""
from pathlib import Path

from evidence import bound, checked, need, utc
from transition import clock
import bounded167_v2_operator as retry
import bridge170_status as bridge

V33_SHA = "05379c4acf4a480309d4cdbf5457f55c68b56e21ed57d19ebe2a6b074f3c02ec"
V33_SEAL_SHA = "7bd9c52b4b4aaa213be55937b5855ccff3057b873c1ecb245e46ea135643dee7"
HEAD_SHA = "07c35a9f23bc8b43101cf935078bf6b11d4005a46780b10e74dee27b8b966394"
HISTORY = (
    "cold167_execution_failure", "cold170_full_metered_guard_stop",
)


def accepted_head(base, head):
    initial = dict(path=str(base/"root044808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
                   sha256=HEAD_SHA)
    authority = checked(initial)
    current = checked(head)
    cursor = head
    for _ in range(96):
        row = checked(cursor)
        need(all(row[key] == authority[key] for key in HISTORY), "V34 lost an original retained terminal")
        if cursor == initial:
            return current
        next_ref = row["previous_Root_operational_review"]
        need(Path(next_ref["path"]).parent.parent == base and cursor != next_ref
             and utc(checked(next_ref)["sampled_at_utc"]) < utc(row["sampled_at_utc"]),
             "V34 fleet lineage left the accepted V33 sequence")
        cursor = next_ref
    raise ValueError("V34 fleet does not descend from the accepted 04:48 fleet")


def ready(api, head, new_seal):
    root, base, current = api["ROOT"], api["BASE"], api["CURRENT"]
    old_ref = dict(path=str(root/"FAILED166_CADENCE_V33_ACTIVE.json"), sha256=V33_SHA)
    old = checked(old_ref)
    previous = checked(old["ready"])
    fleet = accepted_head(base, head)
    need(previous["package"]["sha256"] == V33_SEAL_SHA
         and old["new"]["program"] == str(root/api["failed166_package"](33)/"status_cycle.py"),
         "foreign V33 authority")
    ref = fleet["sole_next_observer"]
    cfg = api["sealed"](ref)
    timer = fleet["sole_next_timer"]
    completed = clock(api,fleet,cfg,timer,ref)
    old_terminal = retry.historical_terminal(fleet, cfg)
    bridge.interface()
    bridge.retained_population(fleet, cfg)
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
                bounded167_receiver=bound(current.with_name("bounded167_status_v2.py")),
                bounded167_admission=bound(current.with_name("bounded167_v2_operator.py")),
                bounded167_v1_terminal=old_terminal, bridge170_interface=bridge.INTERFACE,
                bridge170_status=bound(current.with_name("bridge170_status.py")), **retry.deployments())


def validate(api, proposed, new_seal):
    actual = ready(api, proposed["fleet"], new_seal)
    need(actual == proposed or proposed["completed_sample"] is None
         and actual["completed_sample"] is not None
         and dict(actual, completed_sample=None) == proposed,
         "V34 READY changed the accepted population, seal or observer clock")
    return actual["completed_sample"]
